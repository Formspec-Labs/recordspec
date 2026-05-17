"""ADR 0109 tamper-vector parity checks."""

from __future__ import annotations

from pathlib import Path

from trellis_py.verify import verify_tampered_ledger


def _vectors_root() -> Path:
    return Path(__file__).resolve().parents[2] / "fixtures" / "vectors" / "tamper"


def _assert_tamper_vector(vector: str, reason: str) -> None:
    root = _vectors_root() / vector
    report = verify_tampered_ledger(
        (root / "input-signing-key-registry.cbor").read_bytes(),
        (root / "input-tampered-ledger.cbor").read_bytes(),
    )

    assert report.structure_verified is False
    assert report.integrity_verified is False
    assert report.readability_verified is False
    assert report.event_failures[0].kind == "malformed_cose"
    assert any(reason in warning for warning in report.warnings)


def test_unknown_artifact_type_tamper_fixture_rejects_with_named_reason() -> None:
    _assert_tamper_vector("053-unknown-artifact-type", "ArtifactTypeUnknown")


def test_retired_dispatch_label_tamper_fixture_rejects_with_named_reason() -> None:
    _assert_tamper_vector("054-retired-dispatch-label", "RetiredDispatchLabelPresent")
