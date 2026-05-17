#!/usr/bin/env python3
"""Regression guard for SignedAct projection corpus parity.

The WOS/Formspec signature export generator is the Python oracle for the
projection fixture bytes. This check regenerates its output into a temp tree,
compares every generated binary artifact with the committed corpus, and runs
the Python WOS verifier over the signed-acts positive and negative vectors.
Rust consumes the same corpus through `cargo nextest run -p trellis-verify-wos`.
"""

from __future__ import annotations

import importlib.util
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "trellis-py" / "src"))

GENERATOR = ROOT / "fixtures" / "vectors" / "_generator" / "gen_signature_export_006.py"
VECTORS = ROOT / "fixtures" / "vectors"
AUTHORING_FILES = {"manifest.toml", "derivation.md"}
GENERATED_DIRS = [
    ("export", "006-signature-affirmations-inline"),
    ("export", "007-signature-admission-failed-inline"),
    ("export", "008-signed-acts-fallback-act-id"),
    ("verify", "014-export-006-signature-row-mismatch"),
    ("verify", "019-export-006-signed-acts-projection-mismatch"),
    ("verify", "020-export-006-signed-acts-unsupported-rule"),
    ("tamper", "014-signature-catalog-digest-mismatch"),
    ("tamper", "055-signed-acts-catalog-digest-mismatch"),
    ("tamper", "056-policy-closure-digest-mismatch"),
]


def tree_bytes(base: Path) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    for path in sorted(base.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(base).as_posix()
        if rel in AUTHORING_FILES:
            continue
        files[rel] = path.read_bytes()
    return files


def load_generator():
    spec = importlib.util.spec_from_file_location("gen_signature_export_006", GENERATOR)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load generator at {GENERATOR}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_generator(tmp: Path) -> None:
    module = load_generator()
    module.OUT_EXPORT_006 = tmp / "export" / "006-signature-affirmations-inline"
    module.OUT_EXPORT_007 = tmp / "export" / "007-signature-admission-failed-inline"
    module.OUT_EXPORT_008 = tmp / "export" / "008-signed-acts-fallback-act-id"
    module.OUT_VERIFY_014 = tmp / "verify" / "014-export-006-signature-row-mismatch"
    module.OUT_VERIFY_019 = tmp / "verify" / "019-export-006-signed-acts-projection-mismatch"
    module.OUT_VERIFY_020 = tmp / "verify" / "020-export-006-signed-acts-unsupported-rule"
    module.OUT_TAMPER_014 = tmp / "tamper" / "014-signature-catalog-digest-mismatch"
    module.OUT_TAMPER_055 = tmp / "tamper" / "055-signed-acts-catalog-digest-mismatch"
    module.OUT_TAMPER_056 = tmp / "tamper" / "056-policy-closure-digest-mismatch"
    module.main()


def compare_generated_tree(tmp: Path) -> bool:
    ok = True
    for op, name in GENERATED_DIRS:
        rel = Path(op) / name
        if not (VECTORS / rel).is_dir():
            print(f"committed vector directory missing: {rel}", file=sys.stderr)
            ok = False
            continue
        if not (tmp / rel).is_dir():
            print(f"generator did not emit vector directory: {rel}", file=sys.stderr)
            ok = False
            continue
        expected = tree_bytes(VECTORS / rel)
        actual = tree_bytes(tmp / rel)
        if actual.keys() != expected.keys():
            only_expected = sorted(expected.keys() - actual.keys())
            only_actual = sorted(actual.keys() - expected.keys())
            print(
                f"Generated file set differs for {rel}:\n"
                f"  only in committed corpus: {only_expected}\n"
                f"  only in generated tree: {only_actual}",
                file=sys.stderr,
            )
            ok = False
            continue
        for child in sorted(actual):
            if actual[child] != expected[child]:
                print(f"bytes differ: {rel / child}", file=sys.stderr)
                ok = False
    return ok


def assert_no_wos_failures(verify_wos, export_zip: Path) -> None:
    report = verify_wos.verify_export_zip(export_zip.read_bytes())
    failures = [finding.kind for finding in report.wos_findings if finding.severity == "failure"]
    if failures:
        raise AssertionError(f"{export_zip} emitted WOS failures: {failures}")
    if report.verdict.projection_integrity != "pass":
        raise AssertionError(
            f"{export_zip} projection_integrity={report.verdict.projection_integrity}"
        )


def assert_wos_failure(
    verify_wos,
    export_zip: Path,
    expected_failures: set[str],
    *,
    projection_integrity: str,
    blocking_reasons: list[str],
) -> None:
    report = verify_wos.verify_export_zip(export_zip.read_bytes())
    if not report.trellis.structure_verified:
        raise AssertionError(f"{export_zip} did not preserve substrate structure")
    if not report.trellis.integrity_verified:
        raise AssertionError(f"{export_zip} did not preserve substrate integrity")
    if not report.trellis.readability_verified:
        raise AssertionError(f"{export_zip} did not preserve substrate readability")
    if report.integrity_verified:
        raise AssertionError(f"{export_zip} unexpectedly passed composed integrity")
    if report.verdict.cryptographic_integrity != "pass":
        raise AssertionError(
            f"{export_zip} cryptographic_integrity={report.verdict.cryptographic_integrity}"
        )
    if report.verdict.projection_integrity != projection_integrity:
        raise AssertionError(
            f"{export_zip} projection_integrity={report.verdict.projection_integrity}"
        )
    if report.verdict.relying_party_result != "invalid":
        raise AssertionError(
            f"{export_zip} relying_party_result={report.verdict.relying_party_result}"
        )
    if report.verdict.domain_admissibility != "pass":
        raise AssertionError(
            f"{export_zip} domain_admissibility={report.verdict.domain_admissibility}"
        )
    if report.verdict.blocking_reasons != blocking_reasons:
        raise AssertionError(
            f"{export_zip} blocking_reasons={report.verdict.blocking_reasons}"
        )
    failures = {
        finding.kind for finding in report.wos_findings if finding.severity == "failure"
    }
    if failures != expected_failures:
        raise AssertionError(
            f"{export_zip} failures {sorted(failures)}, expected {sorted(expected_failures)}"
        )


def check_python_verifier_vectors() -> None:
    from trellis_py import verify_wos

    assert_no_wos_failures(
        verify_wos,
        VECTORS / "export/006-signature-affirmations-inline/expected-export.zip"
    )
    assert_no_wos_failures(
        verify_wos,
        VECTORS / "export/007-signature-admission-failed-inline/expected-export.zip"
    )
    assert_no_wos_failures(
        verify_wos,
        VECTORS / "export/008-signed-acts-fallback-act-id/expected-export.zip"
    )
    assert_wos_failure(
        verify_wos,
        VECTORS / "verify/019-export-006-signed-acts-projection-mismatch/input-export.zip",
        {"signed_acts_projection_mismatch"},
        projection_integrity="fail",
        blocking_reasons=["projection_mismatch"],
    )
    assert_wos_failure(
        verify_wos,
        VECTORS / "verify/020-export-006-signed-acts-unsupported-rule/input-export.zip",
        {"signed_acts_catalog_invalid"},
        projection_integrity="fail",
        blocking_reasons=["projection_integrity"],
    )
    assert_wos_failure(
        verify_wos,
        VECTORS / "tamper/055-signed-acts-catalog-digest-mismatch/input-export.zip",
        {
            "signed_acts_catalog_digest_mismatch",
            "signed_acts_projection_mismatch",
        },
        projection_integrity="fail",
        blocking_reasons=["projection_mismatch"],
    )


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

    if not GENERATOR.is_file():
        print(f"generator not found at {GENERATOR}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory() as tmp_str:
        tmp = Path(tmp_str)
        run_generator(tmp)
        if not compare_generated_tree(tmp):
            return 1

    check_python_verifier_vectors()
    print("OK: signed-acts projection generator and Python verifier match the corpus")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
