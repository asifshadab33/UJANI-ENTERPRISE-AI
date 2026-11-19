#!/usr/bin/env python3
"""Fail CI if the application model-catalogue mirror drifts from its source."""
from argparse import ArgumentParser
from pathlib import Path
import sys

MIRROR_CANDIDATES = (Path("apps/desktop/src/model-catalog.json"), Path("apps/operator-console/model-catalog.json"))

def catalogue_paths(root: Path):
    source = root / "catalogs" / "local-model-catalog-v1.json"
    mirrors = [root / rel for rel in MIRROR_CANDIDATES if (root / rel).is_file()]
    if not source.is_file() or len(mirrors) != 1:
        return None, None, f"expected source and exactly one mirror; found {len(mirrors)}"
    return source, mirrors[0], None

def check_catalogue(root: Path) -> int:
    source, mirror, error = catalogue_paths(root)
    if error:
        print(error, file=sys.stderr)
        return 2
    if source.read_bytes() != mirror.read_bytes():
        print(f"catalogue drift: {source.relative_to(root)} != {mirror.relative_to(root)}", file=sys.stderr)
        return 1
    print(f"catalogue parity OK: {source.relative_to(root)} == {mirror.relative_to(root)}")
    return 0

def main() -> int:
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    return check_catalogue(parser.parse_args().root.resolve())

if __name__ == "__main__":
    raise SystemExit(main())
