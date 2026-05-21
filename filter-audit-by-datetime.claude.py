#!/usr/bin/env python3
import argparse, os, re, sys, shutil, tarfile, tempfile
from datetime import datetime, timezone
warnings = []

# ---------- datetime parsing ----------
def parse_dt(line: str):
    # dpkg log: "2026-05-12 18:47:39"
    m = re.search(r"(\d{4}-\d{2}-\d{2})[ \t]+(\d{2}:\d{2}:\d{2})", line)
    if m:
        try:
            return datetime.strptime(m.group(0), "%Y-%m-%d %H:%M:%S")
        except Exception:
            pass
    # auditd log: msg=audit(1779039207.533:33367473)
    m = re.search(r"msg=audit\(([0-9\.]+):", line)
    if m:
        try:
            ts = float(m.group(1))
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        except Exception:
            pass
    # boot log: "Tue May 12 18:45:08 +08 2026"
    m = re.search(r"[A-Za-z]{3} [A-Za-z]{3} \d{2} \d{2}:\d{2}:\d{2} [+-]\d{2} \d{4}", line)
    if m:
        try:
            return datetime.strptime(m.group(0), "%a %b %d %H:%M:%S %z %Y")
        except Exception:
            pass
    # ISO 8601 with timezone (e.g., "2026-05-18T16:12:07.314659+08:00")
    m = re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?[+-]\d{2}:?\d{2}", line)
    if m:
        try:
            dt = datetime.fromisoformat(m.group(0))
            # Convert to UTC for comparison
            return dt.astimezone(timezone.utc)
        except Exception:
            pass
    # apt history/start/end: "Start-Date: 2026-05-12  18:50:47"
    m = re.search(r"Start-Date:\s*(\d{4}-\d{2}-\d{2})[ \t]+(\d{2}:\d{2}:\d{2})", line)
    if not m:
        m = re.search(r"End-Date:\s*(\d{4}-\d{2}-\d{2})[ \t]+(\d{2}:\d{2}:\d{2})", line)
    if m:
        try:
            return datetime.strptime(m.group(0), "%Y-%m-%d %H:%M:%S")
        except Exception:
            pass
    # apt term log: "Log started: 2026-05-12  18:47:39"
    m = re.search(r"Log started:\s*(\d{4}-\d{2}-\d{2})[ \t]+(\d{2}:\d{2}:\d{2})", line)
    if m:
        try:
            return datetime.strptime(m.group(0), "%Y-%m-%d %H:%M:%S")
        except Exception:
            pass
    return None

def filter_file(in_path, out_path, start, end):
    # Determine if the file is gzipped
    if in_path.endswith('.gz'):
        import gzip
        open_in = lambda p: gzip.open(p, 'rt', errors='ignore')
        open_out = lambda p: gzip.open(p, 'wt')
    else:
        open_in = lambda p: open(p, 'rt', errors='ignore')
        open_out = lambda p: open(p, 'wt')
    try:
        with open_in(in_path) as fin:
            lines = fin.readlines()
    except Exception as e:
        # binary or unreadable, copy as is and log warning
        shutil.copy2(in_path, out_path)
        warnings.append(f"[WARN] Could not read {in_path}: {e}")
        return
    kept = []
    for line in lines:
        try:
            dt = parse_dt(line)
            if dt is None:
                kept.append(line)
            else:
                if start <= dt.replace(tzinfo=timezone.utc) <= end:
                    kept.append(line)
        except Exception:
            kept.append(line)
    # Write result (may be empty)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open_out(out_path) as fout:
        fout.writelines(kept)

def process_path(in_path, out_path, start, end):
    if os.path.isdir(in_path):
        for name in os.listdir(in_path):
            process_path(os.path.join(in_path, name), os.path.join(out_path, name), start, end)
    elif tarfile.is_tarfile(in_path):
        # unpack, process, repack using separate input/output temp dirs
        with tempfile.TemporaryDirectory() as td_in, tempfile.TemporaryDirectory() as td_out:
            with tarfile.open(in_path) as tar:
                tar.extractall(td_in)
            # process extracted files into td_out
            process_path(td_in, td_out, start, end)
            # repack processed output directory
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            with tarfile.open(out_path, 'w:gz') as tar_out:
                for root, _, files in os.walk(td_out):
                    for f in files:
                        full = os.path.join(root, f)
                        arc = os.path.relpath(full, td_out)
                        tar_out.add(full, arcname=arc)
    else:
        # regular file
        filter_file(in_path, out_path, start, end)

def worker(args):
    return process_path(*args)

def main():
    p = argparse.ArgumentParser(description='Filter audit logs by datetime range.')
    p.add_argument('input', help='Input folder or .tar.gz archive')
    p.add_argument('output', help='Output folder or .tar.gz archive')
    p.add_argument('start', help='Start datetime (ISO 8601)')
    p.add_argument('end', help='End datetime (ISO 8601)')
    args = p.parse_args()
    start = datetime.fromisoformat(args.start).replace(tzinfo=timezone.utc)
    end = datetime.fromisoformat(args.end).replace(tzinfo=timezone.utc)
    # Sequential processing with progress display
    entries = []
    if os.path.isdir(args.input):
        entries = [(os.path.join(args.input, e), os.path.join(args.output, e), start, end) for e in os.listdir(args.input)]
        total = len(entries)
        for i, entry in enumerate(entries, 1):
            sys.stdout.write(f"\rProcessing {i}/{total}: {entry[0]}")
            sys.stdout.flush()
            process_path(*entry)
        sys.stdout.write("\n")
    else:
        sys.stdout.write(f"\rProcessing file: {args.input}\n")
        sys.stdout.flush()
        process_path(args.input, args.output, start, end)
    # Print any warnings collected
    if warnings:
        sys.stderr.write('\nWarnings encountered:\n')
        for w in warnings:
            sys.stderr.write(w + '\n')

if __name__ == '__main__':
    main()
