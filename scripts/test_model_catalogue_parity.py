import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

CHECK = Path(__file__).resolve().parent / "check_model_catalogue_parity.py"
SYNC = Path(__file__).resolve().parent / "sync_model_catalogue.py"

def fixture(root: Path, relative: str):
    src = root / "catalogs/local-model-catalog-v1.json"
    dst = root / relative
    src.parent.mkdir(parents=True, exist_ok=True)
    dst.parent.mkdir(parents=True, exist_ok=True)
    src.write_text("catalogue source\n", encoding="utf-8")
    dst.write_text("catalogue source\n", encoding="utf-8")
    return src, dst

class CatalogueParityTests(unittest.TestCase):
    def check(self, root):
        return subprocess.run([sys.executable, str(CHECK), "--root", str(root)], capture_output=True, text=True)

    def test_repository_catalogue_mirror_matches(self):
        result = self.check(CHECK.parents[1])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_drift_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _, dst = fixture(root, "apps/desktop/src/model-catalog.json")
            dst.write_text("drift\n", encoding="utf-8")
            result = self.check(root)
            self.assertEqual(result.returncode, 1)
            self.assertIn("catalogue drift", result.stderr)

    def test_sync_rewrites_stale_mirror(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src, dst = fixture(root, "apps/operator-console/model-catalog.json")
            src.write_text("canonical\n", encoding="utf-8")
            dst.write_text("stale\n", encoding="utf-8")
            result = subprocess.run([sys.executable, str(SYNC), "--root", str(root)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(src.read_bytes(), dst.read_bytes())

if __name__ == "__main__":
    unittest.main()
