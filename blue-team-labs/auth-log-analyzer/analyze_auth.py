#!/usr/bin/env python3
"""Offline SSH auth-log triage for defensive SOC learning."""
from __future__ import annotations
import argparse
import re
from collections import Counter, defaultdict
from pathlib import Path

FAILED = re.compile(r"Failed password for (?:invalid user )?(\S+) from ([0-9.]+)")
ACCEPTED = re.compile(r"Accepted (?:password|publickey) for (\S+) from ([0-9.]+)")

def analyze(text: str, threshold: int = 5) -> list[str]:
    failures: Counter[str] = Counter()
    failed_lines: dict[str, list[int]] = defaultdict(list)
    accepted: list[tuple[int, str, str]] = []
    for line_no, line in enumerate(text.splitlines(), 1):
        match = FAILED.search(line)
        if match:
            user, ip = match.groups()
            failures[ip] += 1
            failed_lines[ip].append(line_no)
            continue
        match = ACCEPTED.search(line)
        if match:
            user, ip = match.groups()
            accepted.append((line_no, user, ip))

    alerts = []
    for ip, count in failures.items():
        if count >= threshold:
            alerts.append(f"[HIGH] {ip}: {count} failed SSH attempts (lines {failed_lines[ip]})")
    for line_no, user, ip in accepted:
        if failures[ip] >= threshold:
            alerts.append(f"[CRITICAL] Successful SSH login for {user} from {ip} after {failures[ip]} failures (line {line_no})")
    return alerts or ["[INFO] No detections at the configured threshold."]

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("logfile", type=Path)
    parser.add_argument("--threshold", type=int, default=5)
    args = parser.parse_args()
    if args.threshold < 1:
        parser.error("--threshold must be at least 1")
    try:
        alerts = analyze(args.logfile.read_text(errors="replace"), args.threshold)
    except OSError as exc:
        parser.error(str(exc))
    print("\n".join(alerts))

if __name__ == "__main__":
    main()
