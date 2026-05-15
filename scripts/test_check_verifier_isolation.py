"""Tests for scripts/check-verifier-isolation.sh."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check-verifier-isolation.sh"


class TestCheckVerifierIsolation(unittest.TestCase):
    def _run(self, tree_output: str) -> subprocess.CompletedProcess[str]:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as tmp:
            tmp.write(tree_output)
            tmp_path = Path(tmp.name)
        self.addCleanup(lambda: tmp_path.unlink(missing_ok=True))
        env = os.environ.copy()
        env["TRELLIS_VERIFY_TREE_OUTPUT_FILE"] = str(tmp_path)
        env["TRELLIS_MANIFEST_PATH"] = "/tmp/trellis-test-manifest/Cargo.toml"
        return subprocess.run(
            ["bash", str(SCRIPT)],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_passes_when_no_forbidden_crates_present(self) -> None:
        result = self._run(
            "integrity-verify v0.1.0\n"
            "├── integrity-cose v0.1.0\n"
            "└── trellis-types v0.1.0\n"
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("OK: integrity-verify is HPKE-clean.", result.stdout)
        self.assertIn("manifest: /tmp/trellis-test-manifest/Cargo.toml", result.stdout)

    def test_fails_when_forbidden_crate_present(self) -> None:
        result = self._run(
            "integrity-verify v0.1.0\n"
            "└── trellis-types v0.1.0\n"
            "    └── hkdf v0.12.4\n"
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("FAIL: integrity-verify dependency graph includes", result.stderr)
        self.assertIn("hkdf v0.12.4", result.stderr)


if __name__ == "__main__":
    unittest.main()
