#!/usr/bin/env python3
"""
Filter audit logs inside a tar/tar.gz by audit epoch timestamps, preserving paths+names.

Usage:
  python3 filter_audit_tar.py input.tar.gz output.tar.gz START END

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
from typing import Optional, Tuple


AUDIT_RE = re.compile(rb"msg=audit\((\d+)(?:\.(\d+))?:")  # msg=audit(SECONDS.FRACTION:...)


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
    if size is None:
        t.size = m.size
    else:
        t.size = size
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


def filter_tar(
    input_path: str,
    output_path: str,
    start_us: Optional[int],
    end_us: Optional[int],
) -> None:
    def in_range(ts_us: int) -> bool:
        if start_us is not None and ts_us < start_us:
            return False
        if end_us is not None and ts_us > end_us:
            return False
        return True

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

            # Determine whether the member content is gzip-compressed
            is_gz = member.name.endswith(".gz")

            # Read lines from possibly-gz content, filter, then write to temp (gz or plain)
            tmp = tempfile.NamedTemporaryFile(prefix="audit_filter_", delete=False)
            tmp_path = tmp.name

            try:
                if is_gz:
                    out_stream = gzip.GzipFile(fileobj=tmp, mode="wb")
                    in_stream = gzip.GzipFile(fileobj=in_f, mode="rb")
                else:
                    out_stream = tmp
                    in_stream = in_f

                kept_any = False
                try:
                    for line in in_stream:
                        ts = _line_ts_us(line)
                        if ts is None:
                            # Keep non-matching lines (rare, but "typically" audit lines match)
                            out_stream.write(line)
                            kept_any = True
                        else:
                            if in_range(ts):
                                out_stream.write(line)
                                kept_any = True
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


def _usage_and_exit(msg: str = "") -> None:
    if msg:
        print(f"Error: {msg}\n", file=sys.stderr)
    print(__doc__.strip(), file=sys.stderr)
    sys.exit(2)


def main(argv: list[str]) -> int:
    if len(argv) < 3:
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

    filter_tar(input_path, output_path, start_us, end_us)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

