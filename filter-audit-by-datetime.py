#!/usr/bin/env python3
"""Filter audit logs by datetime range with multi-core processing.

Tar archives are streamed: each member is extracted, processed immediately,
and discarded before reading the next.  Only one member's data lives on disk
at any given moment.

Multi-core processing via multiprocessing.Pool is used for overall file
processing, bounded by --workers (default: os.cpu_count()).
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
                ts = m.group(1).strip()
                tz = m.group(2).strip()
                if len(tz) == 3 or (len(tz) == 4 and tz[0] in '+-'):
                    tz = tz[:3] + tz[3:].ljust(2, '0') if len(tz) == 3 else tz
                full = f"{ts} {tz}"
                dt = datetime.strptime(full, "%a %b %d %H:%M:%S %z %Y")
                return dt.replace(tzinfo=None) if dt.tzinfo else dt
            if idx == 5:
                current_year = datetime.now().year
                return datetime.strptime(m.group(1).strip(), "%b %d %H:%M:%S").replace(year=current_year)
            if idx == 6:
                ts_part = m.group(1).strip()
                tz_part = m.group(2).strip()
                fmt = "%Y-%m-%dT%H:%M:%S.%f%z" if "." in ts_part else "%Y-%m-%dT%H:%M:%S%z"
                dt = datetime.strptime(ts_part + tz_part, fmt)
                return dt.replace(tzinfo=None) if dt.tzinfo else dt
            ts = m.group(1).strip()
            for fmt in (DATE_FMTS[0], DATE_FMTS[2]):
                try:
                    return datetime.strptime(ts, fmt)
                except ValueError:
                    continue
        except (ValueError, OSError):
            continue
    return None


def filter_text(text, start, end):
    lines = text.splitlines(keepends=True) if text else []
    result = []
    for line in lines:
        try:
            ts = parse_ts(line)
            if ts and start <= ts <= end:
                result.append(line)
        except Exception:
            pass
    return "".join(result)


def process_text(path, start, end):
    os.chmod(path, 0o644)
    with open(path, "r", errors="replace") as f:
        content = f.read()
    with open(path, "w") as f:
        f.write(filter_text(content, start, end))


def process_gz(path, start, end):
    os.chmod(path, 0o644)
    with gzip.open(path, "rt", errors="replace") as f:
        content = f.read()
    with gzip.open(path, "wt") as f:
        f.write(filter_text(content, start, end))


def is_tar(path):
    s = path.lower()
    return (s.endswith(".tar.gz") or s.endswith(".tgz") or
            s.endswith(".tar.bz2") or s.endswith(".tbz2") or s.endswith(".tar"))


def tar_comp(path):
    s = path.lower()
    if s.endswith(".tar.gz") or s.endswith(".tgz"):
        return "gz"
    if s.endswith(".tar.bz2") or s.endswith(".tbz2"):
        return "bz2"
    return ""


def handle_process_file(item_path, start, end):
    name = item_path.name.lower()
    try:
        if name.endswith(".gz"):
            process_gz(str(item_path), start, end)
        else:
            process_text(str(item_path), start, end)
    except Exception as e:
        sys.stderr.write(f"WARNING {name}: {e}\n")


def handle_tar(tar_path, start, end, workers=1):
    """Process ONE tar archive.

    Streaming approach: each member is extracted to its own unique temp dir,
    processed, and the temp dir is discarded before moving to the next member.
    Only one member lives in memory/disk at a time.

    Nested tar archives are handle_tar()'d recursively (also streaming).
    """
    comp = tar_comp(tar_path)
    mode_map = {"gz": "r:gz", "bz2": "r:bz2", "": "r:"}
    write_map = {"gz": "w:gz", "bz2": "w:bz2", "": "w:"}
    tmpdir = tempfile.mkdtemp()
    root = os.path.basename(os.path.splitext(tar_path)[0])
    errors = []

    try:
        with tarfile.open(tar_path, mode_map[comp]) as tar:
            for member in tar:
                if member.isdir():
                    continue

                try:
                    if is_tar(member.name):
                        # Nested tar: extract to temp, recurse in-place, clean up
                        nested_tmp = tempfile.mkdtemp(dir=tmpdir)
                        tar.extract(member, path=nested_tmp)
                        entries = os.listdir(nested_tmp)
                        if entries:
                            nested_path = os.path.join(
                                nested_tmp,
                                _find_nested_file(entries, member.name)
                            )
                            handle_tar(nested_path, start, end, workers)
                        else:
                            sys.stderr.write(f"WARNING {member.name}: empty nested tar\n")
                        shutil.rmtree(nested_tmp, ignore_errors=True)
                        continue

                    # Single-file member: unique temp dir -> process -> discard
                    member_dir = tempfile.mkdtemp(dir=tmpdir)
                    tar.extract(member, path=member_dir)
                    fpath = _resolve_file([(member_dir, f) for f in os.listdir(member_dir)])
                    if fpath and os.path.isfile(fpath):
                        handle_process_file(Path(fpath), start, end)
                    shutil.rmtree(member_dir, ignore_errors=True)

                except Exception as e:
                    errors.append(f"WARNING {member.name}: {e}\n")

        # Repack all processed contents
        out = tar_path + ".tmp"
        with tarfile.open(out, write_map[comp]) as tar:
            tar.add(tmpdir, arcname=root)
        shutil.move(out, tar_path)

        for e in errors:
            sys.stderr.write(e)

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _find_nested_file(entries, member_name):
    base = os.path.basename(member_name)
    for e in entries:
        if e.lower() == base.lower():
            return e
    return entries[0]


def _resolve_file(entries):
    if len(entries) == 1:
        return os.path.join(entries[0][0], entries[0][1])
    return None


def _process_one(path, start, end):
    if is_tar(path):
        handle_tar(path, start, end)
    elif path.lower().endswith(".gz"):
        process_gz(path, start, end)
    else:
        process_text(path, start, end)


def worker_batch(items):
    c = 0
    for path, start, end in items:
        try:
            _process_one(path, start, end)
            c += 1
        except Exception as e:
            sys.stderr.write(f"WARNING {path}: {e}\n")
    return c


def repack_dir(source_dir, tar_path, comp="gz"):
    mode_map = {"gz": "w:gz", "bz2": "w:bz2", "": "w:"}
    with tarfile.open(tar_path, mode_map[comp]) as tar:
        for root, _, files in os.walk(source_dir):
            for f in files:
                fp = os.path.join(root, f)
                arcname = os.path.relpath(fp, source_dir)
                tar.add(fp, arcname=arcname)


def _collect_writable(base):
    files = []
    for root, _, fs in os.walk(base):
        for f in fs:
            fp = os.path.join(root, f)
            os.chmod(fp, 0o644)
            files.append(fp)
    return files


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
            return datetime.strptime(val, "%a %b %d %H:%M:%S %z %Y").replace(tzinfo=None)
        except ValueError:
            pass
        raise ValueError(f"Cannot parse date: {val}")

    _start = pdate(args.start)
    _end = pdate(args.end)

    inp = os.path.abspath(args.input)
    out = os.path.abspath(args.output)

    in_is_tar = is_tar(inp)
    in_is_file = os.path.isfile(inp)
    out_is_tar = is_tar(out)
    workers = min(args.workers or 1, 64)

    work = tempfile.mkdtemp()
    try:
        # === Case 1: single non-tar file ===
        if in_is_file and not in_is_tar:
            src = os.path.join(work, os.path.basename(inp))
            shutil.copy2(inp, src)
            process_text(src, _start, _end)
            if out_is_tar:
                with tarfile.open(out, "w:gz") as tar:
                    tar.add(src, arcname=os.path.basename(src))
            else:
                shutil.copy2(src, out)

        # === Case 2: tar archive ===
        # STREAMING: iterate tar members one-by-one, process each, discard.
        # Nested tars recurse via handle_tar() which is also streaming.
        elif in_is_tar:
            comp = tar_comp(inp)
            src_dir = os.path.join(work, "extracted")
            os.makedirs(src_dir)

            collected = []

            with tarfile.open(inp) as tar:
                for member in tar:
                    if member.isdir():
                        os.makedirs(os.path.join(src_dir, member.name), exist_ok=True)
                        continue

                    try:
                        if is_tar(member.name):
                            # Nested tar: extract to temp, recurse, then extract
                            # the repacked result into src_dir.
                            nested_tmp = tempfile.mkdtemp(dir=src_dir)
                            tar.extract(member, path=nested_tmp)
                            entries = os.listdir(nested_tmp)
                            if entries:
                                nested_path = os.path.join(
                                    nested_tmp,
                                    _find_nested_file(entries, member.name)
                                )
                                # Recurse: handle_tar processes + repacks in place
                                handle_tar(nested_path, _start, _end, workers)
                                # Now nested_path is the PROCESSED tar.
                                # Extract its contents into src_dir.
                                extract_nested_to(nested_path, nested_tmp, src_dir)
                            else:
                                sys.stderr.write(f"WARNING {member.name}: empty nested tar\n")
                            shutil.rmtree(nested_tmp, ignore_errors=True)
                            continue

                        # Single file: unique temp dir -> copy to src_dir -> collect
                        uniq_tmp = tempfile.mkdtemp(dir=src_dir)
                        tar.extract(member, path=uniq_tmp)
                        entry = _resolve_file([(uniq_tmp, f) for f in os.listdir(uniq_tmp)])
                        if entry and os.path.isfile(entry):
                            target = os.path.join(
                                src_dir,
                                _safe_name(member.name)
                            )
                            os.chmod(entry, 0o644)
                            shutil.copy2(entry, target)
                            collected.append((target, _start, _end))
                        shutil.rmtree(uniq_tmp, ignore_errors=True)

                    except Exception as e:
                        sys.stderr.write(f"WARNING {member.name}: {e}\n")

            # Process collected files with bounded Pool
            total = len(collected)
            if total:
                batches = [[item] for item in collected]
                done = 0
                with Pool(workers) as pool:
                    for n in pool.imap_unordered(worker_batch, batches):
                        done += n
                        sys.stdout.write(f"\rProgress: {done}/{total}")
                        sys.stdout.flush()
                sys.stdout.write("\n")

            if out_is_tar:
                repack_dir(src_dir, out, comp)
            else:
                if os.path.exists(out):
                    shutil.rmtree(out)
                shutil.copytree(src_dir, out)

        # === Case 3: folder input ===
        elif os.path.isdir(inp):
            workdir = os.path.join(work, "input")
            shutil.copytree(inp, workdir)
            files = _collect_writable(workdir)
            total = len(files)

            if total:
                nw = min(workers, total)
                batches = [[] for _ in range(nw)]
                for i, f in enumerate(files):
                    batches[i % nw].append((f, _start, _end))
                done = 0
                with Pool(nw) as pool:
                    for n in pool.imap_unordered(worker_batch, batches):
                        done += n
                        sys.stdout.write(f"\rProgress: {done}/{total}")
                        sys.stdout.flush()
                sys.stdout.write("\n")

            if out_is_tar:
                repack_dir(workdir, out)
            else:
                if os.path.exists(out):
                    shutil.rmtree(out)
                shutil.copytree(workdir, out)
        else:
            print(f"Error: input does not exist: {inp}")

    finally:
        shutil.rmtree(work, ignore_errors=True)

    print(f"Done. Output: {out}")


def _safe_name(path):
    """Convert a path with slashes into a safe filename."""
    return "_" + path.lstrip("/").replace("/", "_").replace(" ", "_")


def extract_nested_to(nested_path, nested_tmp, src_dir):
    """Extract a processed nested tar (now repacked) into src_dir."""
    if not nested_path or not os.path.isfile(nested_path):
        return
    if not is_tar(nested_path):
        return
    extract_dir = tempfile.mkdtemp(dir=src_dir)
    try:
        with tarfile.open(nested_path) as tar:
            tar.extractall(path=extract_dir)
        # Move extracted files into src_dir with proper relative paths
        for root, _, files in os.walk(extract_dir):
            for f in files:
                fp = os.path.join(root, f)
                rel = os.path.relpath(fp, extract_dir)
                target = os.path.join(src_dir, rel)
                os.makedirs(os.path.dirname(target), exist_ok=True)
                shutil.copy2(fp, target)
    finally:
        shutil.rmtree(extract_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
