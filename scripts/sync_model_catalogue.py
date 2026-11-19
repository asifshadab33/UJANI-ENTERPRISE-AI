#!/usr/bin/env python3
"""Regenerate the application catalogue mirror from the repository source."""
from argparse import ArgumentParser
from pathlib import Path
import shutil

MIRROR_CANDIDATES = (Path("apps/desktop/src/model-catalog.json"), Path("apps/operator-console/model-catalog.json"))

def sync_catalogue(root: Path) -> int:
    source = root / "catalogs" / "local-model-catalog-v1.json"
    targets = [root / rel for rel in MIRROR_CANDIDATES if (root / rel).is_file()]
    if not source.is_file() or len(targets) != 1:
        raise SystemExit("Expected catalogue source and exactly one application mirror.")
    target = targets[0]
    shutil.copyfile(source, target)
    print(f"Generated {target.relative_to(root)} from {source.relative_to(root)}")
    return 0

def main() -> int:
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    return sync_catalogue(parser.parse_args().root.resolve())

if __name__ == "__main__":
    raise SystemExit(main())
