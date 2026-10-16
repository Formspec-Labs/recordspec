"""Parametrized G-5 tamper vectors for ADR 0010 user-content-attestation.

Corpus-wide parity remains `python -m trellis_py.conformance`; these tests
pin a small UCA subset so regressions surface under pytest without running
the full stranger gate.
"""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from trellis_py.conformance import _assert_tamper, _load_manifest
from trellis_py import verify
from trellis_py import verify_wos
from trellis_py.verify import _is_identity_attestation_event_type, _is_operator_uri


def _vectors_root() -> Path:
    # trellis/trellis-py/tests/this_file.py → trellis/
    return Path(__file__).resolve().parents[2] / "fixtures" / "vectors"


def _uca_tamper_dirs() -> list[Path]:
    root = _vectors_root() / "tamper"
    if not root.is_dir():
        return []
    return sorted(p for p in root.iterdir() if p.is_dir() and "-uca-" in p.name)


@pytest.mark.parametrize("vector_dir", _uca_tamper_dirs(), ids=lambda p: p.name)
def test_uca_tamper_vectors_match_manifest(vector_dir: Path) -> None:
    manifest = _load_manifest(vector_dir)
    _assert_tamper(vector_dir, manifest)


def test_core_identity_attestation_event_type_is_fixture_only() -> None:
    assert not _is_identity_attestation_event_type(
        "wos.assurance.identity_attestation"
    )
    assert _is_identity_attestation_event_type("x-trellis-test/identity-attestation/v1")
    assert not _is_identity_attestation_event_type("wos.identity.authentication_method")


def test_wos_identity_attestation_event_type_is_adapter_owned() -> None:
    assert verify_wos._is_wos_identity_attestation_event_type(  # noqa: SLF001
        "wos.assurance.identity_attestation"
    )
    assert not verify_wos._is_wos_identity_attestation_event_type(  # noqa: SLF001
        "wos.identity.identity_attestation"
    )
    assert not verify_wos._is_wos_identity_attestation_event_type(  # noqa: SLF001
        "wos.identity.authentication_method"
    )


def test_wos_operator_uri_prefix_is_adapter_owned() -> None:
    assert _is_operator_uri("urn:trellis:operator:reviewer")
    assert not _is_operator_uri("urn:wos:operator:caseworker")
    assert verify_wos._is_wos_operator_uri("urn:wos:operator:caseworker")  # noqa: SLF001
    assert not verify_wos._is_wos_operator_uri(  # noqa: SLF001
        "urn:trellis:operator:reviewer"
    )


def test_core_operator_uri_hook_preserves_positional_resolver_slot() -> None:
    assert list(inspect.signature(verify.verify_export_zip).parameters) == [
        "export_zip",
        "identity_event_type_admitted",
        "resolver",
        "operator_uri_admitted",
        "certificate_authorities",
    ]
    assert list(inspect.signature(verify.verify_tampered_ledger).parameters) == [
        "signing_key_registry",
        "ledger",
        "initial_posture_declaration",
        "posture_declaration",
        "identity_event_type_admitted",
        "resolver",
        "operator_uri_admitted",
    ]
    assert list(inspect.signature(verify.verify_single_event).parameters) == [
        "public_key_bytes",
        "signed_event",
        "identity_event_type_admitted",
        "resolver",
        "operator_uri_admitted",
    ]
    for fn in (
        verify.verify_export_zip,
        verify.verify_tampered_ledger,
        verify.verify_single_event,
    ):
        assert (
            inspect.signature(fn).parameters["operator_uri_admitted"].kind
            is inspect.Parameter.KEYWORD_ONLY
        )
