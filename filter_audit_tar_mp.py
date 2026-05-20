#!/usr/bin/env python3
"""
Filter audit logs inside a tar/tar.gz by audit epoch timestamps, preserving paths+names.

Usage:
  python3 filter_audit_tar.py input.tar.gz output.tar.gz START END [--nparallel N]

START / END:
  - Use "-" for open-ended.
  - Accepts:
      2025-11-01
      2025-11-01T01:35:00
      2025-11-01 01:35:00   (quote it!)
      2026.1.31             (also accepts / and . as separators)
  - If only a date is given:
      START defaults to 00:00:00 local time
      END   defaults to 23:59:59.999999 local time
Range is inclusive on both ends.

Examples:
  python3 filter_audit_tar.py input.tar.gz output.tar.gz 2025-11-01 2026-01-31
  python3 filter_audit_tar.py input.tar.gz output.tar.gz 2025-11-01T01:35:00 -
  python3 filter_audit_tar.py input.tar.gz output.tar.gz - 2026.1.31
  python3 filter_audit_tar.py input.tar.gz output.tar.gz 2025-11-01 2026-01-31 --nparallel 8
"""

from __future__ import annotations

import copy
import datetime as dt
import gzip
import os
import re
import sys
import tarfile
import tempfile
from concurrent.futures import ProcessPoolExecutor
from typing import Iterable, Optional, Tuple

AUDIT_RE = re.compile(rb"msg=audit\((\d+)(?:\.(\d+))?:")  # msg=audit(SECONDS.FRACTION:...)

BATCH_LINES = 100


def _local_tzinfo() -> dt.tzinfo:
    # Current system timezone
    return dt.datetime.now().astimezone().tzinfo  # type: ignore[return-value]


def _epoch_us_from_local(dt_local: dt.datetime) -> int:
    """Convert aware datetime to microseconds since Unix epoch using integer arithmetic."""
    if dt_local.tzinfo is None:
        raise ValueError("datetime must be timezone-aware")
    dt_utc = dt_local.astimezone(dt.timezone.utc)
    epoch = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
    delta = dt_utc - epoch
    return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds


def _parse_datetime_like(s: str, *, is_end: bool) -> Optional[dt.datetime]:
    """
    Parse a flexible local datetime. Returns timezone-aware datetime in local timezone.
    "-" => None (open ended).
    """
    s = s.strip()
    if s == "-" or s == "":
        return None

    # Normalize separators
    s_norm = s.replace("/", "-").replace(".", "-").replace("T", " ")
    s_norm = re.sub(r"\s+", " ", s_norm).strip()

    # Patterns:
    #   YYYY-M-D
    #   YYYY-M-D HH:MM
    #   YYYY-M-D HH:MM:SS
    #   YYYY-M-D HH:MM:SS.micro
    m = re.match(
        r"^(\d{4})-(\d{1,2})-(\d{1,2})"
        r"(?:\s+(\d{1,2})(?::(\d{1,2})(?::(\d{1,2})(?:\.(\d{1,6}))?)?)?)?$",
        s_norm,
    )
    if not m:
        raise ValueError(f"Could not parse datetime: {s!r}")

    year = int(m.group(1))
    month = int(m.group(2))
    day = int(m.group(3))

    hh = m.group(4)
    mm = m.group(5)
    ss = m.group(6)
    micros = m.group(7)

    if hh is None:
        # Date only
        hour = 23 if is_end else 0
        minute = 59 if is_end else 0
        second = 59 if is_end else 0
        micro = 999_999 if is_end else 0
    else:
        hour = int(hh)
        minute = int(mm) if mm is not None else (59 if is_end else 0)
        second = int(ss) if ss is not None else (59 if is_end else 0)
        if micros is None:
            micro = 999_999 if (is_end and (mm is None or ss is None)) else 0
        else:
            micro = int(micros.ljust(6, "0")[:6])

    tz = _local_tzinfo()
    # Note: assigning tzinfo directly is generally fine; DST edge cases may be ambiguous.
    return dt.datetime(year, month, day, hour, minute, second, micro, tzinfo=tz)


def _parse_range_args(args: list[str]) -> Tuple[Optional[str], Optional[str]]:
    """
    Accept:
      START END
      or a single string "START END"
      or START with spaces (unquoted) + END as last token (best-effort)
    """
    if len(args) == 0:
        return None, None

    if len(args) == 1:
        parts = args[0].strip().split()
        if len(parts) != 2:
            raise ValueError("Range must be two values: START END (use '-' for open-ended).")
        return parts[0], parts[1]

    if len(args) == 2:
        return args[0], args[1]

    # Best effort: treat last token as END; everything before as START (allows unquoted start with spaces)
    start = " ".join(args[:-1]).strip()
    end = args[-1].strip()
    return start, end


def _clone_tarinfo(m: tarfile.TarInfo, *, size: Optional[int] = None) -> tarfile.TarInfo:
    t = tarfile.TarInfo(name=m.name)
    t.mode = m.mode
    t.uid = m.uid
    t.gid = m.gid
    t.mtime = m.mtime
    t.type = m.type
    t.linkname = m.linkname
    t.uname = m.uname
    t.gname = m.gname
    t.devmajor = m.devmajor
    t.devminor = m.devminor
    t.pax_headers = copy.deepcopy(getattr(m, "pax_headers", {}))
    # size matters for regular files
    t.size = m.size if size is None else size
    return t


def _is_audit_log_path(path: str) -> bool:
    base = os.path.basename(path)
    # Common names: audit.log, audit.log.1, audit.log.2.gz, etc.
    return base.startswith("audit.log")


def _line_ts_us(line: bytes) -> Optional[int]:
    m = AUDIT_RE.search(line)
    if not m:
        return None
    sec = int(m.group(1))
    frac = m.group(2) or b"0"
    # audit uses seconds with fractional part; store as microseconds
    frac6 = frac[:6].ljust(6, b"0")
    return sec * 1_000_000 + int(frac6)


def _filter_lines_chunk(
    payload: tuple[int, list[bytes], Optional[int], Optional[int]]
) -> tuple[int, bytes]:
    """
    Worker: filter a chunk of lines; preserve non-matching lines.
    Returns (chunk_index, filtered_bytes).
    """
    idx, lines, start_us, end_us = payload

    def in_range(ts_us: int) -> bool:
        if start_us is not None and ts_us < start_us:
            return False
        if end_us is not None and ts_us > end_us:
            return False
        return True

    out = bytearray()
    for line in lines:
        ts = _line_ts_us(line)
        if ts is None or in_range(ts):
            out.extend(line)
    return idx, bytes(out)


def _iter_line_batches(stream: Iterable[bytes], batch_lines: int) -> Iterable[list[bytes]]:
    batch: list[bytes] = []
    for line in stream:
        batch.append(line)
        if len(batch) >= batch_lines:
            yield batch
            batch = []
    if batch:
        yield batch


def filter_tar(
    input_path: str,
    output_path: str,
    start_us: Optional[int],
    end_us: Optional[int],
    *,
    nparallel: int,
    batch_lines: int = BATCH_LINES,
) -> None:
    # If nparallel <= 1, do everything in the main process.
    executor: Optional[ProcessPoolExecutor] = None
    if nparallel and nparallel > 1:
        executor = ProcessPoolExecutor(max_workers=nparallel)

    try:
        with tarfile.open(input_path, "r:*") as tin, tarfile.open(output_path, "w:gz") as tout:
            for member in tin.getmembers():
                # Preserve dirs/links/etc as-is
                if not member.isreg():
                    tout.addfile(_clone_tarinfo(member))
                    continue

                in_f = tin.extractfile(member)
                if in_f is None:
                    # Shouldn't happen for regular files, but be safe
                    tout.addfile(_clone_tarinfo(member))
                    continue

                # If it's not an audit log, copy bytes unchanged
                if not _is_audit_log_path(member.name):
                    tarinfo = _clone_tarinfo(member, size=member.size)
                    tout.addfile(tarinfo, fileobj=in_f)
                    continue

                is_gz = member.name.endswith(".gz")

                tmp = tempfile.NamedTemporaryFile(prefix="audit_filter_", delete=False)
                tmp_path = tmp.name

                try:
                    if is_gz:
                        out_stream = gzip.GzipFile(fileobj=tmp, mode="wb")
                        in_stream = gzip.GzipFile(fileobj=in_f, mode="rb")
                    else:
                        out_stream = tmp
                        in_stream = in_f

                    try:
                        # Build a payload stream of (chunk_idx, lines, start_us, end_us)
                        def payloads() -> Iterable[tuple[int, list[bytes], Optional[int], Optional[int]]]:
                            for idx, lines in enumerate(_iter_line_batches(in_stream, batch_lines)):
                                yield (idx, lines, start_us, end_us)

                        if executor is None:
                            # Single-process path
                            for p in payloads():
                                _, filtered = _filter_lines_chunk(p)
                                if filtered:
                                    out_stream.write(filtered)
                        else:
                            # Multi-process path (preserves ordering via executor.map)
                            for _, filtered in executor.map(_filter_lines_chunk, payloads(), chunksize=1):
                                if filtered:
                                    out_stream.write(filtered)

                    finally:
                        try:
                            in_stream.close()
                        except Exception:
                            pass
                        try:
                            out_stream.close()
                        except Exception:
                            pass

                    # Add filtered file to output tar, preserving name & metadata
                    size = os.path.getsize(tmp_path)
                    tarinfo = _clone_tarinfo(member, size=size)
                    with open(tmp_path, "rb") as rf:
                        tout.addfile(tarinfo, fileobj=rf)

                finally:
                    try:
                        tmp.close()
                    except Exception:
                        pass
                    try:
                        os.unlink(tmp_path)
                    except Exception:
                        pass
    finally:
        if executor is not None:
            executor.shutdown(wait=True)


def _usage_and_exit(msg: str = "") -> None:
    if msg:
        print(f"Error: {msg}\n", file=sys.stderr)
    print(__doc__.strip(), file=sys.stderr)
    sys.exit(2)


def _extract_nparallel(argv: list[str]) -> tuple[list[str], int]:
    """
    Pull --nparallel N (or -j N) out of argv, returning (argv_without_option, nparallel).
    Options can appear anywhere.
    """
    nparallel = os.cpu_count() or 1
    out: list[str] = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("--nparallel", "-j"):
            if i + 1 >= len(argv):
                _usage_and_exit(f"Missing value after {a}")
            try:
                nparallel = int(argv[i + 1])
            except ValueError:
                _usage_and_exit(f"Invalid integer for {a}: {argv[i + 1]!r}")
            i += 2
            continue
        out.append(a)
        i += 1

    if nparallel < 1:
        _usage_and_exit("--nparallel must be >= 1")
    return out, nparallel


def main(argv: list[str]) -> int:
    argv, nparallel = _extract_nparallel(argv)

    if len(argv) < 5:
        _usage_and_exit("Missing required arguments.")

    input_path = argv[1]
    output_path = argv[2]

    if not os.path.exists(input_path):
        _usage_and_exit(f"Input file not found: {input_path}")

    start_s, end_s = _parse_range_args(argv[3:])
    if start_s is None or end_s is None:
        _usage_and_exit("You must provide START and END (use '-' for open-ended).")

    try:
        start_dt = _parse_datetime_like(start_s, is_end=False)
        end_dt = _parse_datetime_like(end_s, is_end=True)
    except ValueError as e:
        _usage_and_exit(str(e))

    start_us = _epoch_us_from_local(start_dt) if start_dt is not None else None
    end_us = _epoch_us_from_local(end_dt) if end_dt is not None else None

    if start_us is not None and end_us is not None and start_us > end_us:
        _usage_and_exit("START must be <= END.")

    # Overwrite output if exists
    try:
        if os.path.exists(output_path):
            os.remove(output_path)
    except OSError as e:
        _usage_and_exit(f"Cannot overwrite output file: {e}")

    filter_tar(
        input_path,
        output_path,
        start_us,
        end_us,
        nparallel=nparallel,
        batch_lines=BATCH_LINES,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

