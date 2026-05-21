#!/usr/bin/env python3
"""Audit log filter utility.

Recursively processes a directory, tar/zip archives, and compressed text files,
filtering log lines to a provided date range. Supports multiple timestamp
formats and parallel processing.
"""

import argparse
import sys
import os
import re
import io
import tarfile
import zipfile
import gzip
import bz2
import lzma
import multiprocessing as mp
import logging
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Callable, List, Tuple

# optional zstandard support
try:
    import zstandard as zstd
except Exception:  # pragma: no cover
    zstd = None

# third‑party date parsing
from dateutil import parser as dt_parser
from tzlocal import get_localzone

# ------------------------------------------------------------
# Timestamp extraction
# ------------------------------------------------------------

def _parse_dt(dt: datetime) -> datetime:
    """Ensure timezone‑aware datetime.
    Naive datetimes are assumed to be in the local timezone.
    """
    if dt.tzinfo is None:
        return get_localzone().localize(dt)
    return dt

# each entry is (regex, extractor_function)
_TIMESTAMP_PATTERNS: List[Tuple[re.Pattern, Callable[[re.Match], Optional[datetime]]]] = []

# 1. dpkg‑style "2026-05-12 18:47:39 ..."
_REGEX_DPKG = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")

def _extract_dpkg(m: re.Match) -> Optional[datetime]:
    try:
        dt = datetime.strptime(m.group('ts'), "%Y-%m-%d %H:%M:%S")
        return _parse_dt(dt)
    except Exception:
        return None

_TIMESTAMP_PATTERNS.append((_REGEX_DPKG, _extract_dpkg))

# 2. auditd "audit(1779039207.533:... )"
_REGEX_AUDITD = re.compile(r"audit\((?P<sec>\d+)\.(?P<frac>\d+):")

def _extract_auditd(m: re.Match) -> Optional[datetime]:
    try:
        sec = int(m.group('sec'))
        frac = int(m.group('frac'))
        dt = datetime.fromtimestamp(sec, tz=get_localzone()) + timedelta(milliseconds=frac)
        return dt
    except Exception:
        return None

_TIMESTAMP_PATTERNS.append((_REGEX_AUDITD, _extract_auditd))

# 3. boot log "------------ Tue May 12 18:45:08 +08 2026 ------------"
_REGEX_BOOT = re.compile(r"^[-]+\s+(?P<dt>\w{3}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+[\+\-]\d{2}\s+\d{4})\s+[-]+")

def _extract_boot(m: re.Match) -> Optional[datetime]:
    try:
        dt = datetime.strptime(m.group('dt'), "%a %b %d %H:%M:%S %z %Y")
        return dt
    except Exception:
        return None

_TIMESTAMP_PATTERNS.append((_REGEX_BOOT, _extract_boot))

# 4. apt‑history "Start-Date: 2026-05-12  18:50:47"
_REGEX_APTHIST = re.compile(r"Start-Date:\s*(?P<ts>\d{4}-\d{2}-\d{2}\s{2,}\d{2}:\d{2}:\d{2})")

def _extract_apthist(m: re.Match) -> Optional[datetime]:
    try:
        # collapse multiple spaces to single for strptime
        ts = re.sub(r"\s+", " ", m.group('ts')).strip()
        dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
        return _parse_dt(dt)
    except Exception:
        return None

_TIMESTAMP_PATTERNS.append((_REGEX_APTHIST, _extract_apthist))

# 5. auth log without year "Jan  1 08:00:45 ..."
_REGEX_AUTH = re.compile(r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})")

def _extract_auth(m: re.Match) -> Optional[datetime]:
    try:
        now = datetime.now()
        dt_str = f"{m.group('mon')} {m.group('day')} {now.year} {m.group('time')}"
        dt = datetime.strptime(dt_str, "%b %d %Y %H:%M:%S")
        return _parse_dt(dt)
    except Exception:
        return None

_TIMESTAMP_PATTERNS.append((_REGEX_AUTH, _extract_auth))

# 6. generic ISO‑8601 (covers many other variants)
_REGEX_ISO = re.compile(r"\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:[Z]|[\+\-]\d{2}:?\d{2})?")

def _extract_iso(m: re.Match) -> Optional[datetime]:
    try:
        dt = dt_parser.isoparse(m.group(0))
        return _parse_dt(dt)
    except Exception:
        return None

_TIMESTAMP_PATTERNS.append((_REGEX_ISO, _extract_iso))


def extract_timestamp(line: str) -> Optional[datetime]:
    """Return a datetime if any known pattern matches, else None.
    The first matching pattern wins.
    """
    for regex, func in _TIMESTAMP_PATTERNS:
        m = regex.search(line)
        if m:
            return func(m)
    return None

# ------------------------------------------------------------
# Line filtering
# ------------------------------------------------------------

def line_in_range(line: str, start: datetime, end: datetime) -> bool:
    ts = extract_timestamp(line)
    if ts is None:
        # keep lines we cannot parse (as per spec)
        return True
    return start <= ts <= end

# ------------------------------------------------------------
# File processing helpers
# ------------------------------------------------------------

def _open_compressed(path: Path):
    """Return a binary file‑like object for reading a compressed file.
    Supports .gz, .bz2, .xz, .zst.
    """
    suffix = path.suffix.lower()
    if suffix == ".gz":
        return gzip.open(path, "rb")
    if suffix == ".bz2":
        return bz2.open(path, "rb")
    if suffix in {".xz", ".lzma"}:
        return lzma.open(path, "rb")
    if suffix == ".zst":
        if not zstd:
            raise RuntimeError("zstandard support not available")
        f = open(path, "rb")
        dctx = zstd.ZstdDecompressor()
        return dctx.stream_reader(f)
    raise RuntimeError(f"Unsupported compression: {path}")

def _write_compressed(data: bytes, dst: Path):
    suffix = dst.suffix.lower()
    if suffix == ".gz":
        with gzip.open(dst, "wb") as out:
            out.write(data)
    elif suffix == ".bz2":
        with bz2.open(dst, "wb") as out:
            out.write(data)
    elif suffix in {".xz", ".lzma"}:
        with lzma.open(dst, "wb") as out:
            out.write(data)
    elif suffix == ".zst":
        if not zstd:
            raise RuntimeError("zstandard support not available")
        cctx = zstd.ZstdCompressor()
        with open(dst, "wb") as f:
            cctx.copy_stream(io.BytesIO(data), f)
    else:
        raise RuntimeError(f"Unsupported compression for writing: {dst}")

def process_text_stream(in_stream: io.BufferedReader, out_stream: io.BufferedWriter, start: datetime, end: datetime) -> bool:
    """Filter lines from in_stream to out_stream.
    Handles apt history blocks (Start-Date / End-Date) as atomic units.
    Returns True if at least one line was written.
    """
    any_written = False
    # Pre‑compile regex for block detection
    start_pat = re.compile(r'^Start-Date:\s*(?P<ts>\d{4}-\d{2}-\d{2}\s{2,}\d{2}:\d{2}:\d{2})')
    end_pat = re.compile(r'^End-Date:\s*(?P<ts>\d{4}-\d{2}-\d{2}\s{2,}\d{2}:\d{2}:\d{2})')
    term_start_pat = re.compile(r'^Log started:\s*(?P<ts>\d{4}-\d{2}-\d{2}\s{2,}\d{2}:\d{2}:\d{2})')
    term_end_pat = re.compile(r'^Log ended:\s*(?P<ts>\d{4}-\d{2}-\d{2}\s{2,}\d{2}:\d{2}:\d{2})')
    while True:
        raw = in_stream.readline()
        if not raw:
            break
        try:
            line = raw.decode(errors='ignore')
        except Exception:
            line = raw.decode('utf-8', errors='ignore')
        # Detect start of apt history block
        m_start = start_pat.match(line)
        if m_start:
            block = [raw]
            # parse start datetime
            block_start_dt = None
            try:
                dt_str = m_start.group('ts')
                dt = datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S")
                block_start_dt = _parse_dt(dt)
            except Exception:
                block_start_dt = None
            # accumulate until End-Date
            block_end_dt = None
            while True:
                nxt_raw = in_stream.readline()
                if not nxt_raw:
                    break
                block.append(nxt_raw)
                try:
                    nxt_line = nxt_raw.decode(errors='ignore')
                except Exception:
                    nxt_line = nxt_raw.decode('utf-8', errors='ignore')
                m_end = end_pat.match(nxt_line)
                if m_end:
                    try:
                        dt_str2 = m_end.group('ts')
                        dt2 = datetime.strptime(dt_str2, "%Y-%m-%d %H:%M:%S")
                        block_end_dt = _parse_dt(dt2)
                    except Exception:
                        block_end_dt = None
                    break
            # Decide retention for apt history block
            if block_start_dt is not None and block_end_dt is not None:
                if block_end_dt < start or block_start_dt > end:
                    continue
                for b_raw in block:
                    try:
                        b_line = b_raw.decode(errors='ignore')
                    except Exception:
                        b_line = b_raw.decode('utf-8', errors='ignore')
                    if line_in_range(b_line, start, end):
                        out_stream.write(b_raw)
                        any_written = True
                continue
            for b_raw in block:
                try:
                    b_line = b_raw.decode(errors='ignore')
                except Exception:
                    b_line = b_raw.decode('utf-8', errors='ignore')
                if line_in_range(b_line, start, end):
                    out_stream.write(b_raw)
                    any_written = True
            continue
        # Detect start of apt term block
        m_term_start = term_start_pat.match(line)
        if m_term_start:
            term_block = [raw]
            term_start_dt = None
            try:
                dt_str = m_term_start.group('ts')
                dt = datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S")
                term_start_dt = _parse_dt(dt)
            except Exception:
                term_start_dt = None
            term_end_dt = None
            while True:
                nxt_raw = in_stream.readline()
                if not nxt_raw:
                    break
                term_block.append(nxt_raw)
                try:
                    nxt_line = nxt_raw.decode(errors='ignore')
                except Exception:
                    nxt_line = nxt_raw.decode('utf-8', errors='ignore')
                m_term_end = term_end_pat.match(nxt_line)
                if m_term_end:
                    try:
                        dt_str2 = m_term_end.group('ts')
                        dt2 = datetime.strptime(dt_str2, "%Y-%m-%d %H:%M:%S")
                        term_end_dt = _parse_dt(dt2)
                    except Exception:
                        term_end_dt = None
                    break
            if term_start_dt is not None and term_end_dt is not None:
                if term_end_dt < start or term_start_dt > end:
                    continue
                for b_raw in term_block:
                    try:
                        b_line = b_raw.decode(errors='ignore')
                    except Exception:
                        b_line = b_raw.decode('utf-8', errors='ignore')
                    if line_in_range(b_line, start, end):
                        out_stream.write(b_raw)
                        any_written = True
                continue
            for b_raw in term_block:
                try:
                    b_line = b_raw.decode(errors='ignore')
                except Exception:
                    b_line = b_raw.decode('utf-8', errors='ignore')
                if line_in_range(b_line, start, end):
                    out_stream.write(b_raw)
                    any_written = True
            continue
        # regular line processing
        if line_in_range(line, start, end):
            out_stream.write(raw)
            any_written = True
    return any_written

def process_plain_file(src: Path, dst: Path, start: datetime, end: datetime):
    """Read plain text file line‑by‑line, filter, write to dst.
    Writes empty file if nothing matches.
    """
    dst.parent.mkdir(parents=True, exist_ok=True)
    with src.open('rb') as fin, dst.open('wb') as fout:
        any_kept = process_text_stream(fin, fout, start, end)
    if not any_kept:
        # Ensure an empty file exists (overwrite any partial content)
        with dst.open('wb') as empty_f:
            pass

def process_compressed_file(src: Path, dst: Path, start: datetime, end: datetime):
    """Decompress, filter, recompress preserving original compression.
    """
    dst.parent.mkdir(parents=True, exist_ok=True)
    with _open_compressed(src) as fin:
        # Read all decompressed data into memory – typically log files are manageable.
        # For huge files a streaming approach would be needed; omitted for brevity.
        decompressed = fin.read()
        in_buf = io.BytesIO(decompressed)
        out_buf = io.BytesIO()
        any_kept = process_text_stream(in_buf, out_buf, start, end)
        out_data = out_buf.getvalue() if any_kept else b""
    _write_compressed(out_data, dst)

# ------------------------------------------------------------
# Archive handling (tar, zip)
# ------------------------------------------------------------

def _is_archive(path: Path) -> bool:
    # Recognize tar, tar.gz, tgz, and zip archives. Do not treat generic .gz as archive.
    lower = path.name.lower()
    return lower.endswith('.tar') or lower.endswith('.tar.gz') or lower.endswith('.tgz') or lower.endswith('.zip')

def process_archive(src: Path, dst: Path, start: datetime, end: datetime):
    """Process a tar or zip archive recursively.
    The output archive keeps the same compression type and name.
    """
    dst.parent.mkdir(parents=True, exist_ok=True)
    # Open tar/zip with automatic detection; preserve compression for tar based on original suffix
    suffix = src.suffix.lower()
    if suffix == '.zip':
        # ZIP handling
        with zipfile.ZipFile(src, 'r') as zin, zipfile.ZipFile(dst, 'w', compression=zipfile.ZIP_DEFLATED) as zout:
            for zi in zin.infolist():
                data = zin.read(zi)
                member_path = Path(zi.filename)
                if member_path.is_dir():
                    zout.writestr(zi, data)
                    continue
                processed = _process_member_bytes(data, member_path, start, end)
                zout.writestr(zi, processed)
    else:
        # TAR handling – use universal read mode; decide output compression
        read_mode = 'r:*'
        out_mode = 'w:gz' if suffix in {'.gz', '.tgz'} else 'w'
        with tarfile.open(src, read_mode) as tar_in, tarfile.open(dst, out_mode) as tar_out:
            for member in tar_in.getmembers():
                if member.isdir():
                    tar_out.addfile(member)
                    continue
                fobj = tar_in.extractfile(member)
                if fobj is None:
                    tar_out.addfile(member)
                    continue
                data = fobj.read()
                processed = _process_member_bytes(data, Path(member.name), start, end)
                new_info = tarfile.TarInfo(name=member.name)
                new_info.size = len(processed)
                new_info.mode = member.mode
                new_info.mtime = member.mtime
                new_info.uid = member.uid
                new_info.gid = member.gid
                new_info.uname = member.uname
                new_info.gname = member.gname
                tar_out.addfile(new_info, io.BytesIO(processed))

def _process_member_bytes(data: bytes, member_path: Path, start: datetime, end: datetime) -> bytes:
    """Process bytes of a file inside an archive.
    Handles plain text, compressed, and nested archives.
    Returns the processed (possibly empty) bytes.
    """
    suffix = member_path.suffix.lower()
    # Detect nested archive by extension
    if _is_archive(member_path):
        # write to temp files on disk to reuse archive logic (simpler)
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            inner_src = Path(tmpdir) / ('inner' + member_path.name)
            inner_dst = Path(tmpdir) / ('out' + member_path.name)
            inner_src.write_bytes(data)
            process_archive(inner_src, inner_dst, start, end)
            return inner_dst.read_bytes()
    # compressed text
    if suffix in {".gz", ".bz2", ".xz", ".zst"}:
        # decompress, filter, recompress
        if suffix == '.gz':
            decompressed = gzip.decompress(data)
        elif suffix == '.bz2':
            decompressed = bz2.decompress(data)
        elif suffix in {'.xz', '.lzma'}:
            decompressed = lzma.decompress(data)
        elif suffix == '.zst':
            if not zstd:
                raise RuntimeError('zstandard not available')
            dctx = zstd.ZstdDecompressor()
            decompressed = dctx.decompress(data)
        else:
            decompressed = data
        # filter
        in_buf = io.BytesIO(decompressed)
        out_buf = io.BytesIO()
        any_kept = process_text_stream(in_buf, out_buf, start, end)
        filtered = out_buf.getvalue() if any_kept else b""
        # recompress
        if suffix == '.gz':
            return gzip.compress(filtered)
        elif suffix == '.bz2':
            return bz2.compress(filtered)
        elif suffix in {'.xz', '.lzma'}:
            return lzma.compress(filtered)
        elif suffix == '.zst':
            cctx = zstd.ZstdCompressor()
            return cctx.compress(filtered)
    # plain text (or unknown) – treat as text
    in_buf = io.BytesIO(data)
    out_buf = io.BytesIO()
    any_kept = process_text_stream(in_buf, out_buf, start, end)
    return out_buf.getvalue() if any_kept else b""

# ------------------------------------------------------------
# Dispatcher
# ------------------------------------------------------------

def process_path(src: Path, dst: Path, start: datetime, end: datetime):
    """Determine the type of src and dispatch to appropriate handler.
    This function is intended to be run inside a worker process.
    """
    try:
        if src.is_symlink():
            # ignore per spec
            return
        if src.is_dir():
            dst.mkdir(parents=True, exist_ok=True)
            return
        # Files – first try tar detection, then zip, then compressed text, then plain
        # Attempt TAR detection by trying to open; if fails, fall back to other types
        # Archive detection based on filename patterns
        lower_name = src.name.lower()
        if lower_name.endswith('.tar.gz') or lower_name.endswith('.tgz'):
            try:
                process_archive(src, dst, start, end)
                return
            except Exception:
                # Fallback to compressed handling if not a valid tar archive
                process_compressed_file(src, dst, start, end)
                return
        elif lower_name.endswith('.zip'):
            process_archive(src, dst, start, end)
        elif src.suffix.lower() in {'.gz', '.bz2', '.xz', '.zst'}:
            # Regular compressed file (not a tar archive)
            process_compressed_file(src, dst, start, end)
        else:
            # treat as plain text
            process_plain_file(src, dst, start, end)
    except Exception as exc:
        logging.warning(f"Failed processing {src}: {exc}")
        # Fallback: copy unchanged
        try:
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(src.read_bytes())
        except Exception as e2:
            logging.error(f"Fallback copy also failed for {src}: {e2}")

# ------------------------------------------------------------
# Main orchestration
# ------------------------------------------------------------

def walk_and_queue(src_root: Path, dst_root: Path, start: datetime, end: datetime, pool: mp.Pool, counter):
    tasks = []
    for src_path in src_root.rglob('*'):
        rel = src_path.relative_to(src_root)
        dst_path = dst_root / rel
        if src_path.is_dir():
            dst_path.mkdir(parents=True, exist_ok=True)
            continue
        # enqueue file processing
        tasks.append(pool.apply_async(process_path, (src_path, dst_path, start, end)))
        # increment total count for progress display
        with counter.get_lock():
            counter.value += 1
    return tasks

def progress_monitor(counter, total):
    import time, sys
    while True:
        with counter.get_lock():
            done = counter.value
        sys.stdout.write(f"\rProcessed {done}/{total} files")
        sys.stdout.flush()
        if done >= total:
            break
        time.sleep(0.5)
    sys.stdout.write('\n')

def main():
    parser = argparse.ArgumentParser(description='Audit log filter by date range')
    parser.add_argument('input_path', type=Path, help='Input file, directory or archive')
    parser.add_argument('output_path', type=Path, help='Output directory')
    parser.add_argument('--start', required=True, help='Start datetime (ISO8601, bare date allowed)')
    parser.add_argument('--end', required=True, help='End datetime (ISO8601, inclusive)')
    parser.add_argument('-j', '--jobs', type=int, default=os.cpu_count(), help='Number of parallel workers')
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s', stream=sys.stderr)

    try:
        start_dt = dt_parser.isoparse(args.start)
        end_dt = dt_parser.isoparse(args.end)
    except Exception as e:
        logging.error(f"Invalid date format: {e}")
        sys.exit(1)
    # ensure timezone awareness
    start_dt = _parse_dt(start_dt)
    end_dt = _parse_dt(end_dt)

    src = args.input_path.resolve()
    dst_root = args.output_path.resolve()
    dst_root.mkdir(parents=True, exist_ok=True)

    # Shared counters without a manager (simpler and lock‑compatible)
    processed_counter = mp.Value('i', 0)  # processed files count
    total_files = sum(1 for _ in src.rglob('*') if _.is_file())

    pool = mp.Pool(processes=args.jobs)
    monitor = mp.Process(target=progress_monitor, args=(processed_counter, total_files))
    monitor.start()

    tasks = []
    for src_path in src.rglob('*'):
        rel = src_path.relative_to(src)
        dst_path = dst_root / rel
        if src_path.is_dir():
            dst_path.mkdir(parents=True, exist_ok=True)
            continue
        # submit task
        tasks.append(pool.apply_async(process_path, (src_path, dst_path, start_dt, end_dt)))
    # wait and update processed counter
    for t in tasks:
        t.wait()
        with processed_counter.get_lock():
            processed_counter.value += 1
    pool.close()
    pool.join()
    monitor.join()
    logging.info('Processing complete.')

if __name__ == '__main__':
    main()
