"""Tests for scripts/check-verifier-isolation.sh."""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check-verifier-isolation.sh"

_DELETED_TREE_PKG = r"(?:trellis-verify|trellis-hpke)"
# `cargo tree` accepts `-p`, `--package`, and `-p=<pkg>`; allow a little slack for
# line continuations. `--package` is matched via an optional extra `-`.
_DELETE_SURFACE_TREE_RE = re.compile(
    rf"cargo\s+tree(?:.|\n)*?-{1,2}(?:p|package)(?:=|\s+){_DELETED_TREE_PKG}\b",
    re.MULTILINE,
)


class TestDeleteSurfaceVerifierIsolationTargets(unittest.TestCase):
    """TWREF-039 / TWREF-047 — guards against regressions to deleted `cargo tree` targets."""

    def test_shell_script_trees_integrity_verify_only(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("cargo tree -p integrity-verify", text)
        self.assertIsNone(
            _DELETE_SURFACE_TREE_RE.search(text),
            "script must not invoke cargo tree on deleted trellis-verify / trellis-hpke",
        )

    def test_makefile_has_no_deleted_verifier_tree_targets(self) -> None:
        makefile = ROOT / "Makefile"
        text = makefile.read_text(encoding="utf-8")
        self.assertIsNone(
            _DELETE_SURFACE_TREE_RE.search(text),
            "Makefile must not invoke cargo tree on deleted trellis-verify / trellis-hpke",
        )

    def test_makefile_documents_integrity_verify_gate(self) -> None:
        text = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn("integrity-verify", text)
        self.assertIn("check-verifier-isolation", text)


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

    def test_passes_when_forbidden_name_is_only_substring_of_another_crate(self) -> None:
        """Regression guard: do not flag e.g. `my-hkdf-tool` or `hpke-helper`."""
        result = self._run(
            "integrity-verify v0.1.0\n"
            "├── hpke-helper-not-forbidden v0.1.0\n"
            "└── my-hkdf-tool v0.1.0\n"
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)

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
