#!/usr/bin/env python3
"""
Audit‑log filter supporting a wide range of log formats.

Features
--------
* Input: a directory tree **or** a .tar.gz archive (any nesting depth)
* Output: same type as input (directory or .tar.gz)
* Recursively walks archives, compressed text files and regular files
* Multi‑core line filtering (ProcessPoolExecutor)
* Accepts start / end datetimes in ISO‑8601 (date only is accepted – time defaults to 00:00:00)
* If a line cannot be parsed, it is copied unchanged.
"""

import argparse
import datetime
import gzip
import io
import os
import re
import shutil
import sys
import tarfile
import tempfile
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Optional, Tuple

# ----------------------------------------------------------------------
# 1. Argument handling
# ----------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Filter audit logs by datetime range (multi‑core)."
    )
    p.add_argument(
        "input_path",
        type=Path,
        help="Path to a directory or .tar.gz archive to filter.",
    )
    p.add_argument(
        "output_path",
        type=Path,
        help="Path where filtered result will be written (same type as input).",
    )
    p.add_argument(
        "--start",
        required=True,
        help="Start datetime (ISO‑8601 or YYYY‑MM‑DD). Time defaults to 00:00:00.",
    )
    p.add_argument(
        "--end",
        required=True,
        help="End datetime (ISO‑8601 or YYYY‑MM‑DD). Time defaults to 00:00:00.",
    )
    p.add_argument(
        "--workers",
        type=int,
        default=os.cpu_count() or 1,
        help="Number of worker processes (default: number of CPUs).",
    )
    return p.parse_args()


def iso_to_dt(s: str) -> datetime.datetime:
    """Parse ISO‑8601 or YYYY‑MM‑DD (adds midnight if time missing)."""
    try:
        dt = datetime.datetime.fromisoformat(s)
        if dt.time() == datetime.time():
            dt = dt.replace(hour=0, minute=0, second=0, microsecond=0)
        return dt
    except ValueError as e:
        raise argparse.ArgumentTypeError(f"Invalid datetime: {s}") from e

# ----------------------------------------------------------------------
# 2. Regexes for the supported log formats
# ----------------------------------------------------------------------
# Named group `dt` holds a string that can be parsed with strptime.
# For the auditd format we capture the epoch seconds in group `ts`.
# Added generic syslog datetime pattern
PATTERNS = [
    # ISO‑8601 timestamps (e.g., 2026-05-18T16:12:12.053957+08:00)
    re.compile(r"(?P<dt>\d{4}-\d{2}-\d{2}T[^\s]+)"),
    # Generic syslog style: "Jan  1 12:34:56"
    re.compile(r"(?P<dt>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"),
    # 1. dpkg log: "2026-05-12 18:47:39 ..."
    re.compile(r"(?P<dt>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"),
    # 2. auditd log: "... audit(1779039207.533:33367473): ..."
    re.compile(r"audit\((?P<ts>\d+\.\d+):"),
    # 3. boot log: "------------ Tue May 12 18:45:08 +08 2026 ------------"
    re.compile(
        r"(?P<dt>\w{3} \w{3} \d{1,2} \d{2}:\d{2}:\d{2} [\+\-]\d{4} \d{4})"
    ),
    # 4. apt history Start‑Date: "Start-Date: 2026-05-12  18:50:47"
    re.compile(r"Start-Date:\s*(?P<dt>\d{4}-\d{2}-\d{2}\s{2}\d{2}:\d{2}:\d{2})"),
    # 5. apt term log: "Log started: 2026-05-12  18:47:39"
    re.compile(r"Log started:\s*(?P<dt>\d{4}-\d{2}-\d{2}\s{2}\d{2}:\d{2}:\d{2})"),
]

# ----------------------------------------------------------------------
# 3. Helper – extract datetime from a line (returns None if not found)
# ----------------------------------------------------------------------
# Global default year for month‑day timestamps
DEFAULT_YEAR = None

def extract_dt(line: str) -> Optional[datetime.datetime]:
    for pat in PATTERNS:
        m = pat.search(line)
        if not m:
            continue
        if "ts" in m.groupdict():
            try:
                ts = float(m.group("ts"))
                return datetime.datetime.fromtimestamp(ts)
            except Exception:
                return None
        dt_str = m.group("dt")
        # ISO‑8601 timestamps (e.g., 2026-05-18T16:12:12.053957+08:00)
        if "T" in dt_str:
            try:
                dt = datetime.datetime.fromisoformat(dt_str)
                # Drop timezone info for naive comparison
                if dt.tzinfo is not None:
                    dt = dt.replace(tzinfo=None)
                return dt
            except Exception:
                pass
        # Handle month‑day timestamps (no year) using DEFAULT_YEAR
        if dt_str and re.fullmatch(r"\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}", dt_str):
            try:
                dt = datetime.datetime.strptime(dt_str, "%b %d %H:%M:%S")
                if DEFAULT_YEAR is not None:
                    dt = dt.replace(year=DEFAULT_YEAR)
                return dt
            except ValueError:
                pass
        for fmt in (
            "%Y-%m-%d %H:%M:%S",               # dpkg and standard ISO
            "%a %b %d %H:%M:%S %z %Y",        # boot log
            "%Y-%m-%d  %H:%M:%S",             # apt history / apt term (double space)
        ):
            try:
                return datetime.datetime.strptime(dt_str, fmt)
            except ValueError:
                continue
    return None

# ----------------------------------------------------------------------
# 4. Core line‑filtering logic (single file)
# ----------------------------------------------------------------------
def filter_lines(
    src_path: Path,
    dst_path: Path,
    start: datetime.datetime,
    end: datetime.datetime,
) -> None:
    """Read *src_path*, write only lines whose datetime is within [start, end].
    # Progress indicator
    sys.stdout.write(f"\rProcessing {src_path} ...")
    sys.stdout.flush()
    Works for plain text files and .gz compressed text files.
    If a line cannot be parsed, it is written unchanged.
    """
    is_gz = src_path.suffix == ".gz"
    open_in = gzip.open if is_gz else open
    open_out = gzip.open if is_gz else open
    dst_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open_in(src_path, "rt", encoding="utf-8", errors="replace") as fin, open_out(
            dst_path, "wt", encoding="utf-8"
        ) as fout:
            for line in fin:
                try:
                    dt = extract_dt(line)
                    if dt is None:
                        fout.write(line)  # keep unparseable line
                        continue
                    if start <= dt <= end:
                        fout.write(line)
                except Exception:
                    fout.write(line)
    except Exception as exc:
        print(f"Warning: failed to process {src_path} ({exc}); copying unchanged.", file=sys.stderr, flush=True)
        shutil.copy2(src_path, dst_path)

# ----------------------------------------------------------------------
# 5. Recursive processing helpers
# ----------------------------------------------------------------------
def is_archive(p: Path) -> bool:
    return p.suffixes[-2:] == [".tar", ".gz"] or p.suffix == ".zip" or p.suffix == ".tar"


def process_directory(
    src_root: Path,
    dst_root: Path,
    start: datetime.datetime,
    end: datetime.datetime,
    executor: ProcessPoolExecutor,
) -> None:
    """Walk *src_root* recursively. Regular files are submitted to the executor.
    Sub‑directories are created in *dst_root* and walked further.
    Archives are unpacked to a temporary dir, processed recursively, then repacked.
    """
    for entry in os.scandir(src_root):
        src_path = Path(entry.path)
        rel = src_path.relative_to(src_root)
        dst_path = dst_root / rel

        if entry.is_dir(follow_symlinks=False):
            dst_path.mkdir(parents=True, exist_ok=True)
            process_directory(src_path, dst_path, start, end, executor)

        elif entry.is_file(follow_symlinks=False):
            if is_archive(src_path):
                # Handle archive: extract → process → repack using separate src/dst dirs
                with tempfile.TemporaryDirectory() as src_tmpdir, tempfile.TemporaryDirectory() as dst_tmpdir:
                    src_dir = Path(src_tmpdir)
                    dst_dir = Path(dst_tmpdir)
                    with tarfile.open(src_path, "r:gz") as tar:
                        tar.extractall(src_dir)
                    process_directory(src_dir, dst_dir, start, end, executor)
                    dst_path.parent.mkdir(parents=True, exist_ok=True)
                    with tarfile.open(dst_path, "w:gz") as tar_out:
                        for root, _, files in os.walk(dst_dir):
                            for f in files:
                                full = Path(root) / f
                                arcname = full.relative_to(dst_dir)
                                tar_out.add(full, arcname=str(arcname))
            else:
                # Regular file (non‑archive) – submit to workers
                executor.submit(
                    filter_lines, src_path, dst_path, start, end
                )
        else:
            # Symlinks, sockets, etc.
            try:
                shutil.copy2(src_path, dst_path)
            except Exception:
                pass



def process_input(
    input_path: Path,
    output_path: Path,
    start: datetime.datetime,
    end: datetime.datetime,
    workers: int,
) -> None:
    """Entry point: decide whether *input_path* is a directory or a .tar.gz archive.
    The output mirrors the input type.
    """
    with ProcessPoolExecutor(max_workers=workers) as executor:
        if input_path.is_dir():
            output_path.mkdir(parents=True, exist_ok=True)
            process_directory(input_path, output_path, start, end, executor)
            executor.shutdown(wait=True)
        elif input_path.is_file() and input_path.suffixes[-2:] == [".tar", ".gz"]:
            # Archive input: extract → process → repack using separate src/dst dirs
            with tempfile.TemporaryDirectory() as src_tmpdir, tempfile.TemporaryDirectory() as dst_tmpdir:
                src_dir = Path(src_tmpdir)
                dst_dir = Path(dst_tmpdir)
                with tarfile.open(input_path, "r:gz") as tar:
                    tar.extractall(src_dir)
                process_directory(src_dir, dst_dir, start, end, executor)
                executor.shutdown(wait=True)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                with tarfile.open(output_path, "w:gz") as tar_out:
                    for root, _, files in os.walk(dst_dir):
                        for f in files:
                            full = Path(root) / f
                            arcname = full.relative_to(dst_dir)
                            tar_out.add(full, arcname=str(arcname))
        else:
            print(f"Error: input_path must be a directory or a .tar.gz archive: {input_path}", file=sys.stderr, flush=True)
            sys.exit(1)

# ----------------------------------------------------------------------
# 6. Main driver
# ----------------------------------------------------------------------
def main() -> None:
    args = parse_args()
    start_dt = iso_to_dt(args.start)
    # Set global default year for month‑day timestamps
    global DEFAULT_YEAR
    DEFAULT_YEAR = start_dt.year
    end_dt = iso_to_dt(args.end)
    if start_dt > end_dt:
        print("Error: start datetime is after end datetime.", file=sys.stderr, flush=True)
        sys.exit(1)
    process_input(
        args.input_path.resolve(),
        args.output_path.resolve(),
        start_dt,
        end_dt,
        workers=args.workers,
    )


if __name__ == "__main__":
    main()
