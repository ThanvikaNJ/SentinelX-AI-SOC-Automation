#!/usr/bin/env python3
"""Compare CSV indicators with a local watchlist; no network requests are made."""
from __future__ import annotations
import argparse
import csv
from pathlib import Path

def load_watchlist(path: Path) -> set[str]:
    return {line.strip().lower() for line in path.read_text().splitlines()
            if line.strip() and not line.lstrip().startswith("#")}

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="CSV with type,value columns")
    parser.add_argument("--watchlist", required=True, type=Path)
    args = parser.parse_args()
    watchlist = load_watchlist(args.watchlist)
    try:
        with args.input.open(newline="", encoding="utf-8") as handle:
            rows = csv.DictReader(handle)
            if not {"type", "value"}.issubset(rows.fieldnames or []):
                parser.error("CSV must contain type,value columns")
            for row in rows:
                value = (row.get("value") or "").strip()
                kind = (row.get("type") or "unknown").strip()
                status = "MATCH - REVIEW" if value.lower() in watchlist else "No local match"
                print(f"{kind:8} {value:40} {status}")
    except OSError as exc:
        parser.error(str(exc))

if __name__ == "__main__":
    main()
