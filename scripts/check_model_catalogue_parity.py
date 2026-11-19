#!/usr/bin/env python3
"""Fail CI if the UI and canonical model catalogue copies drift."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
CANONICAL = ROOT / "catalogs" / "local-model-catalog-v1.json"
MIRRORS = (
    ROOT / "apps" / "desktop" / "src" / "model-catalog.json",
    ROOT / "apps" / "operator-console" / "model-catalog.json",
)

def main() -> int:
    existing = [path for path in MIRRORS if path.is_file()]
    if not CANONICAL.is_file() or len(existing) != 1:
        print("expected canonical catalogue and exactly one app mirror; found: " + ", ".join(str(p) for p in existing), file=sys.stderr)
        return 2
    mirror = existing[0]
    if CANONICAL.read_bytes() != mirror.read_bytes():
        print(f"catalogue drift detected: {CANONICAL.relative_to(ROOT)} != {mirror.relative_to(ROOT)}", file=sys.stderr)
        return 1
    print(f"catalogue parity OK: {CANONICAL.relative_to(ROOT)} == {mirror.relative_to(ROOT)}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
