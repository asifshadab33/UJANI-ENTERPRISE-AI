#!/usr/bin/env python3
"""Regenerate the application model-catalogue mirror from the repository catalogue."""
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "catalogs" / "local-model-catalog-v1.json"
TARGET_CANDIDATES = (
    ROOT / "apps" / "desktop" / "src" / "model-catalog.json",
    ROOT / "apps" / "operator-console" / "model-catalog.json",
)

def main() -> int:
    targets = [path for path in TARGET_CANDIDATES if path.is_file()]
    if not SOURCE.is_file() or len(targets) != 1:
        raise SystemExit("Expected catalogue source and exactly one application mirror.")
    target = targets[0]
    shutil.copyfile(SOURCE, target)
    print(f"Generated {target.relative_to(ROOT)} from {SOURCE.relative_to(ROOT)}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
