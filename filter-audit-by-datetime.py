#!/usr/bin/env python3
"""Filter audit logs by datetime range with multi-core processing.

Tar archives are streamed: each member is extracted, processed, and
discarded before reading the next.  Only one member's data lives on
disk at any given moment.

The ``-j / --workers`` flag limits the multiprocessing Pool to at most
``--workers`` concurrent file-processing jobs (default = CPU count).
"""

import argparse
import gzip
import os
import re
import shutil
import sys
import tarfile
import tempfile
from datetime import datetime
from multiprocessing import Pool
from pathlib import Path

# ── datetime patterns ──────────────────────────────────────────────
PATTERNS = [
    re.compile(r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+'),
    re.compile(r'msg=audit\((\d+\.?\d*):'),
    re.compile(r'^-{3,}\s+(\w+\s+\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+([+\-]?\d{2})\s+\d{4}\s+-{3,}'),
    re.compile(r'(?:Start|End)-Date:\s+(\d{4}-\d{2}-\d{2}\s{2,3}\d{2}:\d{2}:\d{2})'),
    re.compile(r'Log started:\s+(\d{4}-\d{2}-\d{2}\s{2,3}\d{2}:\d{2}:\d{2})'),
    re.compile(r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'),
    re.compile(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?)([+-]\d{2}:\d{2})\s+'),
]
DATE_FMTS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S%z",
             "%Y-%m-%d  %H:%M:%S")


def parse_ts(line):
    for idx, pat in enumerate(PATTERNS):
        m = pat.search(line)
        if not m:
            continue
        try:
            if idx == 1:
                return datetime.fromtimestamp(float(m.group(1).strip()))
            if idx == 2:
                ts, tz = m.group(1).strip(), m.group(2).strip()
                if len(tz) == 3 or (len(tz) == 4 and tz[0] in '+-'):
                    tz = tz[:3] + tz[3:].ljust(2, '0')
                return datetime.strptime(f"{ts} {tz}",
                    "%a %b %d %H:%M:%S %z %Y").replace(tzinfo=None)
            if idx == 5:
                return datetime.strptime(m.group(1).strip(),
                    "%b %d %H:%M:%S").replace(year=datetime.now().year)
            if idx == 6:
                tp, tz = m.group(1).strip(), m.group(2).strip()
                f = "%Y-%m-%dT%H:%M:%S.%f%z" if "." in tp else "%Y-%m-%dT%H:%M:%S%z"
                return datetime.strptime(tp + tz, f).replace(tzinfo=None)
            for fmt in (DATE_FMTS[0], DATE_FMTS[2]):
                try:
                    return datetime.strptime(m.group(1).strip(), fmt)
                except ValueError:
                    continue
        except (ValueError, OSError):
            continue
    return None


def filter_text(text, start, end):
    kept = []
    for line in text.splitlines(keepends=True):
        try:
            ts = parse_ts(line)
            if ts and start <= ts <= end:
                kept.append(line)
        except Exception:
            pass
    return "".join(kept)


def process_text(path, start, end):
    os.chmod(path, 0o644)
    with open(path) as f:
        content = f.read()
    with open(path, "w") as f:
        f.write(filter_text(content, start, end))


def process_gz(path, start, end):
    os.chmod(path, 0o644)
    with gzip.open(path, "rt") as f:
        content = f.read()
    with gzip.open(path, "wt") as f:
        f.write(filter_text(content, start, end))


def is_tar(path):
    s = path.lower()
    return any(s.endswith(e) for e in
               (".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar"))


def tar_comp(path):
    s = path.lower()
    if s.endswith(".tar.gz") or s.endswith(".tgz"):
        return "gz"
    if s.endswith(".tar.bz2") or s.endswith(".tbz2"):
        return "bz2"
    return ""


# ── helpers ────────────────────────────────────────────────────────
def copy_merge(src, dst):
    """Recursively merge contents of *src* into *dst*."""
    if not os.path.isdir(src):
        return
    for item in os.listdir(src):
        sp = os.path.join(src, item)
        dp = os.path.join(dst, item)
        if os.path.isdir(sp):
            os.makedirs(dp, exist_ok=True)
            copy_merge(sp, dp)
        else:
            os.makedirs(os.path.dirname(dp), exist_ok=True)
            shutil.copy2(sp, dp)


def find_extracted_file(member, tmpdir):
    """Find the file tar.extract(member, path=tmpdir) put on disk."""
    for root, _, files in os.walk(tmpdir):
        if files:
            return os.path.join(root, files[0])
    return None


def save_member_to_path(member_path, extracted_file, workdir):
    """Extracted file -> workdir, preserving the archive's path."""
    parts = member_path.strip("/").split("/")
    dst = workdir
    for part in parts:
        if part:
            dst = os.path.join(dst, part)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copy2(extracted_file, dst)


def repack_tar(src_dir, out_path, comp, arcroot=""):
    """Pack all files in src_dir into a tar archive at out_path."""
    if comp not in ("gz", "bz2"):
        comp = ""
    wm = "w:" + comp
    with tarfile.open(out_path, wm) as tar:
        for root, _, files in os.walk(src_dir):
            for f in files:
                fp = os.path.join(root, f)
                rel = os.path.relpath(fp, src_dir)
                an = os.path.join(arcroot, rel) if arcroot else rel
                tar.add(fp, arcname=an)


# ── streaming tar: extract & process members one-by-one ───────────
def stream_extract_process(tar_obj, workdir, start, end):
    """Stream-extract each member, process it, save to workdir.

    Only one member lives on disk at a time. Nested tars are delegated
    to handle_tar_file which repacks them in-place.
    """
    for member in tar_obj:
        if member.isdir():
            dir_path = os.path.join(workdir, member.name.lstrip("/"))
            os.makedirs(dir_path, exist_ok=True)
            continue

        tmp = tempfile.mkdtemp()
        try:
            tar_obj.extract(member, path=tmp)
            extracted = find_extracted_file(member, tmp)

            if extracted and os.path.isfile(extracted) and is_tar(member.name):
                # Nested tar: process & repack in-place, then copy to workdir
                try:
                    handle_tar_file(extracted, start, end)
                    dst = os.path.join(workdir, member.name)
                    os.makedirs(os.path.dirname(dst), exist_ok=True)
                    shutil.copy2(extracted, dst)
                except Exception as e:
                    sys.stderr.write(f"WARNING {member.name}: {e}\n")
            elif extracted and os.path.isfile(extracted):
                # ── Regular file: dispatch by extension ──
                basename = member.name.lower()
                try:
                    if basename.endswith(".gz"):
                        process_gz(extracted, start, end)
                    else:
                        process_text(extracted, start, end)
                    save_member_to_path(member.name, extracted, workdir)
                except Exception as e:
                    # Binary/unrecognizable file: skip silently, keep original
                    pass
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


# ── process one file ─────────────────────────────────────────────
def process_one_file(path, start, end):
    if is_tar(path):
        handle_tar_file(path, start, end)
    elif path.lower().endswith(".gz"):
        process_gz(path, start, end)
    else:
        process_text(path, start, end)


def handle_tar_file(tar_path, start, end):
    """Handle ONE tar: stream-extract, accumulate results, re-pack.

    The tar is modified in-place (re-packed) after all members are
    processed.  Arcnames inside the tar match the original archive
    (no extra arcroot prefix).
    """
    comp = tar_comp(tar_path)
    # Use parentheses to make the ternary unambiguous
    rm = ("r:" + comp) if comp else "r:"
    workdir = tempfile.mkdtemp()
    try:
        with tarfile.open(tar_path, rm) as tar:
            stream_extract_process(tar, workdir, start, end)
        out = tar_path + ".tmp"
        # No arcroot so archive members sit at the archive root
        repack_tar(workdir, out, comp, arcroot="")
        shutil.move(out, tar_path)
    except Exception as e:
        sys.stderr.write(f"ERROR {tar_path}: {e}\n")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# ── Pool worker ──────────────────────────────────────────────────
def _process_batch(args):
    """Pool worker: receives (items, start, end) as one tuple."""
    items, start, end = args
    c = 0
    for (path,) in items:
        try:
            process_one_file(path, start, end)
            c += 1
        except Exception as e:
            sys.stderr.write(f"WARNING {path}: {e}\n")
    return c


def collect_files(base):
    result = []
    for r, _, fs in os.walk(base):
        for f in fs:
            result.append(os.path.join(r, f))
    return result


# ── CLI ────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="Filter audit logs by datetime range")
    ap.add_argument("input", help="Input .tar.gz or folder")
    ap.add_argument("output", help="Output .tar.gz or folder")
    ap.add_argument("--start", required=True,
                    help="Start datetime (e.g. '2026-02-01' or '2026-02-01 08:00:00')")
    ap.add_argument("--end", required=True,
                    help="End datetime (e.g. '2026-05-15' or '2026-05-15 23:59:59')")
    ap.add_argument("-j", "--workers", type=int, default=os.cpu_count() or 1)
    args = ap.parse_args()

    def pdate(val):
        val = val.strip()
        if re.match(r'^\d{4}-\d{2}-\d{2}$', val):
            return datetime.strptime(val, "%Y-%m-%d")
        for fmt in (DATE_FMTS[0], DATE_FMTS[2]):
            try:
                return datetime.strptime(val, fmt)
            except ValueError:
                pass
        try:
            return datetime.strptime(val,
                "%a %b %d %H:%M:%S %z %Y").replace(tzinfo=None)
        except ValueError:
            pass
        raise ValueError(f"Cannot parse date: {val}")

    s_val = pdate(args.start)
    e_val = pdate(args.end)

    inp = os.path.abspath(args.input)
    out = os.path.abspath(args.output)

    in_is_tar = is_tar(inp)
    in_is_file = os.path.isfile(inp)
    out_is_tar = is_tar(out)
    workers = min(args.workers or 1, 64)

    work = tempfile.mkdtemp()
    try:
        # ── Case 1: single non-tar file ──
        if in_is_file and not in_is_tar:
            src = os.path.join(work, os.path.basename(inp))
            shutil.copy2(inp, src)
            process_text(src, s_val, e_val)
            if out_is_tar:
                with tarfile.open(out, "w:gz") as tar:
                    tar.add(src, arcname=os.path.basename(src))
            else:
                shutil.copy2(src, out)

        # ── Case 2: tar archive (streaming) ──
        elif in_is_tar:
            comp = tar_comp(inp)
            rm = ("r:" + comp) if comp else "r:"
            src_dir = os.path.join(work, "extracted")
            with tarfile.open(inp, rm) as tar:
                stream_extract_process(tar, src_dir, s_val, e_val)
            repack_tar(src_dir, os.path.join(work, "result.tar.gz"),
                       comp, arcroot="")
            shutil.copy2(
                os.path.join(work, "result.tar.gz"), out)

        # ── Case 3: folder (Pool + multi-core) ──
        elif os.path.isdir(inp):
            workdir = os.path.join(work, "input")
            shutil.copytree(inp, workdir)
            for r, _, fs in os.walk(workdir):
                for f in fs:
                    os.chmod(os.path.join(r, f), 0o644)

            files = collect_files(workdir)
            total = len(files)
            if total:
                nw = min(workers, total)
                batches = [[] for _ in range(nw)]
                for i, f in enumerate(files):
                    batches[i % nw].append((f,))
                done = 0
                with Pool(nw) as pool:
                    for n in pool.imap_unordered(
                        _process_batch,
                        [(batch, s_val, e_val)
                         for batch in batches]
                    ):
                        done += n
                        sys.stdout.write(f"\rProgress: {done}/{total}")
                        sys.stdout.flush()
                sys.stdout.write("\n")

            if out_is_tar:
                repack_tar(workdir, out, "gz", arcroot="")
            else:
                if os.path.exists(out):
                    shutil.rmtree(out)
                shutil.copytree(workdir, out)
        else:
            print(f"Error: input does not exist: {inp}")

    finally:
        shutil.rmtree(work, ignore_errors=True)

    print(f"Done. Output: {out}")


if __name__ == "__main__":
    main()
