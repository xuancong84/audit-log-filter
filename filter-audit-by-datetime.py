#!/usr/bin/env python3
"""Filter audit logs by datetime range with multi-core processing."""

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
    return s.endswith(".tar.gz") or s.endswith(".tgz") or s.endswith(".tar.bz2") or s.endswith(".tbz2") or s.endswith(".tar")


def tar_comp(path):
    s = path.lower()
    if s.endswith(".tar.gz") or s.endswith(".tgz"):
        return "gz"
    if s.endswith(".tar.bz2") or s.endswith(".tbz2"):
        return "bz2"
    return ""


def handle_tar(tar_path, start, end):
    """Extract tar, process all members recursively, repack to same path."""
    comp = tar_comp(tar_path)
    mode_map = {"gz": "r:gz", "bz2": "r:bz2", "": "r:"}
    write_map = {"gz": "w:gz", "bz2": "w:bz2", "": "w:"}
    tmpdir = tempfile.mkdtemp()
    root = os.path.basename(os.path.splitext(tar_path)[0])
    try:
        with tarfile.open(tar_path, mode_map[comp]) as tar:
            tar.extractall(path=tmpdir)

        for item in Path(tmpdir).rglob("*"):
            if not item.is_file():
                continue
            ip = str(item)
            name = item.name.lower()
            try:
                if is_tar(name):
                    handle_tar(ip, start, end)
                elif name.endswith(".gz"):
                    process_gz(ip, start, end)
                else:
                    process_text(ip, start, end)
            except Exception as e:
                sys.stderr.write(f"WARNING {name}: {e}\n")

        out = tar_path + ".tmp"
        with tarfile.open(out, write_map[comp]) as tar:
            tar.add(tmpdir, arcname=root)
        shutil.move(out, tar_path)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def process_file(path, start, end):
    name = path.lower()
    if is_tar(name):
        handle_tar(path, start, end)
    elif name.endswith(".gz"):
        process_gz(path, start, end)
    else:
        os.chmod(path, 0o644)
        process_text(path, start, end)


def worker_batch(items):
    c = 0
    for path, start, end in items:
        try:
            process_file(path, start, end)
            c += 1
        except Exception as e:
            sys.stderr.write(f"WARNING {path}: {e}\n")
    return c


def repack_dir(source_dir, tar_path, comp="gz"):
    """Repack source_dir into tar_path."""
    mode_map = {"gz": "w:gz", "bz2": "w:bz2", "": "w:"}
    with tarfile.open(tar_path, mode_map[comp]) as tar:
        for root, _, files in os.walk(source_dir):
            for f in files:
                fp = os.path.join(root, f)
                arcname = os.path.relpath(fp, source_dir)
                tar.add(fp, arcname=arcname)


def main():
    ap = argparse.ArgumentParser(description="Filter audit logs by datetime range")
    ap.add_argument("input", help="Input .tar.gz or folder")
    ap.add_argument("output", help="Output .tar.gz or folder")
    ap.add_argument("--start", required=True, help="Start datetime (e.g. '2026-02-01' or '2026-02-01 08:00:00')")
    ap.add_argument("--end", required=True, help="End datetime (e.g. '2026-05-15' or '2026-05-15 23:59:59')")
    ap.add_argument("-j", "--workers", type=int, default=os.cpu_count() or 1)
    args = ap.parse_args()

    def pdate(val):
        val = val.strip()
        # bare date: 2026-02-01
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

    work = tempfile.mkdtemp()
    try:
        if in_is_file and not in_is_tar:
            src = os.path.join(work, os.path.basename(inp))
            shutil.copy2(inp, src)
            process_text(src, _start, _end)
            if out_is_tar:
                with tarfile.open(out, "w:gz") as tar:
                    tar.add(src, arcname=os.path.basename(src))
            else:
                shutil.copy2(src, out)

        elif in_is_tar:
            extracted = os.path.join(work, "extracted")
            os.makedirs(extracted)
            comp = tar_comp(inp)
            mode_map = {"gz": "r:gz", "bz2": "r:bz2", "": "r:"}
            with tarfile.open(inp, mode_map[comp]) as tar:
                tar.extractall(path=extracted)
            # Make all files writable
            for r, d, fs in os.walk(extracted):
                for f in fs:
                    os.chmod(os.path.join(r, f), 0o644)

            nw = min(args.workers, 64)
            files = []
            for r, _, fs in os.walk(extracted):
                files.extend(os.path.join(r, f) for f in fs)
            total = len(files)

            if total:
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
                repack_dir(extracted, out, comp)
            else:
                if os.path.exists(out):
                    shutil.rmtree(out)
                shutil.copytree(extracted, out)

        elif os.path.isdir(inp):
            workdir = os.path.join(work, "input")
            shutil.copytree(inp, workdir)
            # Make all files writable (preserve original read-only sources)
            for r, d, fs in os.walk(workdir):
                for f in fs:
                    os.chmod(os.path.join(r, f), 0o644)

            nw = min(args.workers, 64)
            files = []
            for r, _, fs in os.walk(workdir):
                files.extend(os.path.join(r, f) for f in fs)
            total = len(files)

            if total:
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


if __name__ == "__main__":
    main()
