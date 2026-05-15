#!/usr/bin/env python3
"""Regression guard: `gen_export_001.py` remains byte-aligned with the corpus.

Given the committed `export/001-two-event-chain` directory, when the generator
runs into a temp directory, every generated artifact (all files other than
manifest.toml and derivation.md) must match the committed bytes exactly.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GEN = ROOT / "fixtures" / "vectors" / "_generator" / "gen_export_001.py"
GOLDEN = ROOT / "fixtures" / "vectors" / "export" / "001-two-event-chain"

# Authoring metadata only; not emitted by the generator.
SKIP = {"manifest.toml", "derivation.md"}


def tree_bytes(base: Path) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    for path in sorted(base.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(base).as_posix()
        if rel in SKIP:
            continue
        files[rel] = path.read_bytes()
    return files


def main() -> int:
    try:
        import cbor2  # noqa: F401
        import cryptography  # noqa: F401
    except ImportError:
        print(
            "Missing generator deps (cbor2, cryptography). Install with:\n"
            "  pip install -e ./trellis-py",
            file=sys.stderr,
        )
        return 2

    if not GEN.is_file():
        print(f"generator not found at {GEN}", file=sys.stderr)
        return 2
    if not GOLDEN.is_dir():
        print(f"golden fixture missing at {GOLDEN}", file=sys.stderr)
        return 2

    expected = tree_bytes(GOLDEN)
    with tempfile.TemporaryDirectory() as tmp_str:
        tmp = Path(tmp_str)
        proc = subprocess.run(
            [sys.executable, str(GEN), "--out-dir", str(tmp)],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            print(proc.stdout, end="")
            print(proc.stderr, end="", file=sys.stderr)
            print("gen_export_001.py failed", file=sys.stderr)
            return 1

        actual = tree_bytes(tmp)
        if actual.keys() != expected.keys():
            only_golden = sorted(expected.keys() - actual.keys())
            only_tmp = sorted(actual.keys() - expected.keys())
            print(
                "Generated file sets differ:\n"
                f"  only in golden: {only_golden}\n"
                f"  only in temp: {only_tmp}",
                file=sys.stderr,
            )
            return 1

        for rel in sorted(actual.keys()):
            if actual[rel] != expected[rel]:
                print(f"bytes differ: {rel}", file=sys.stderr)
                return 1

    print("OK: gen_export_001.py matches committed export/001-two-event-chain/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
