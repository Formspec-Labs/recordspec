"""Unit tests for ADR 0007 certificate-of-completion verification.

Mirrors the focused unit tests in `crates/trellis-verify/src/lib.rs` so
Rust + Python stay byte-equivalent on the verifier-side semantics. G-5
corpus parity (the same fixtures pass on both runtimes) is asserted by
`trellis_py.conformance` against the committed `append/028..030`,
`tamper/020..026`, and `export/010` vectors; these tests cover the
focused decode + finalize + catalog helpers.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Optional

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from trellis_py import verify, verify_wos
from trellis_py.verify import (
    CertificateResponseProof,
    MalformedResponseDigestError,
    CertificateDetails,
    CertificateOfCompletionOutcome,
    PresentationArtifactDetails,
    ChainSummaryDetails,
    SignerDisplayDetails,
    TrellisTimestamp,
    TrustedCertificateAuthority,
    VerificationFailure,
    VerifyError,
    _attestation_preimage,
    _decode_certificate_payload,
    _finalize_certificates_of_completion,
    _parse_certificate_export_extension,
    _parse_certificate_catalog_entries,
)


# ---------------------------------------------------------------------------
# Builders.
# ---------------------------------------------------------------------------


def one_attestation(authority_class: str = "new") -> dict:
    return {
        "authority": f"urn:trellis:authority:test-{authority_class}",
        "authority_class": authority_class,
        "signature": b"\x00" * 64,
    }


def signer_display_entry(
    *,
    principal_ref: str = "applicant",
    display_name: str = "Test Signer",
    display_role: Optional[str] = "applicant",
    signed_at: int = 1_776_900_000,
) -> dict:
    return {
        "principal_ref": principal_ref,
        "display_name":  display_name,
        "display_role":  display_role,
        "signed_at":     [signed_at, 0],
    }


def presentation_artifact(
    *,
    content_hash: bytes = b"\xa1" * 32,
    media_type: str = "application/pdf",
    byte_length: int = 64,
    attachment_id: str = "urn:trellis:attachment:test",
    template_id: Optional[str] = None,
    template_hash: Optional[bytes] = None,
) -> dict:
    return {
        "content_hash":  content_hash,
        "media_type":    media_type,
        "byte_length":   byte_length,
        "attachment_id": attachment_id,
        "template_id":   template_id,
        "template_hash": template_hash,
    }


def chain_summary(
    *,
    signer_count: int = 1,
    signer_display: Optional[list[dict]] = None,
    response_ref: Optional[bytes] = None,
    workflow_status: str = "completed",
    impact_level: Optional[str] = None,
    covered_claims: Optional[list[str]] = None,
) -> dict:
    if signer_display is None:
        signer_display = [signer_display_entry()]
    if covered_claims is None:
        covered_claims = []
    return {
        "signer_count":    signer_count,
        "signer_display":  signer_display,
        "response_ref":    response_ref,
        "workflow_status": workflow_status,
        "impact_level":    impact_level,
        "covered_claims":  covered_claims,
    }


def certificate_extensions(
    *,
    certificate_id: str = "urn:trellis:certificate:test:1",
    case_ref: Optional[str] = None,
    completed_at: int = 1_776_899_500,
    pa: Optional[dict] = None,
    cs: Optional[dict] = None,
    signing_events: Optional[list[bytes]] = None,
    workflow_ref: Optional[str] = None,
    attestations: Optional[list[dict]] = None,
) -> dict:
    if pa is None:
        pa = presentation_artifact()
    if cs is None:
        cs = chain_summary()
    if signing_events is None:
        signing_events = [b"\x80" * 32]
    if attestations is None:
        attestations = [one_attestation("new")]
    return {
        "trellis.certificate-of-completion.v1": {
            "certificate_id":        certificate_id,
            "case_ref":              case_ref,
            "completed_at":          [completed_at, 0],
            "presentation_artifact": pa,
            "chain_summary":         cs,
            "signing_events":        signing_events,
            "workflow_ref":          workflow_ref,
            "attestations":          attestations,
            "extensions":            None,
        }
    }


# ---------------------------------------------------------------------------
# Decode tests.
# ---------------------------------------------------------------------------


def test_decode_minimal_certificate_succeeds():
    exts = certificate_extensions()
    cert = _decode_certificate_payload(exts)
    assert cert is not None
    assert cert.certificate_id == "urn:trellis:certificate:test:1"
    assert cert.case_ref is None
    assert cert.chain_summary.signer_count == 1
    assert len(cert.signing_events) == 1
    assert cert.attestation_signatures_well_formed is True


def test_decode_returns_none_when_extension_absent():
    cert = _decode_certificate_payload({})
    assert cert is None


def test_decode_signer_count_mismatch_flips_kind():
    """ADR 0007 step 2 first invariant — signer_count != len(signing_events)."""
    exts = certificate_extensions(
        cs=chain_summary(signer_count=2),  # but signing_events has 1
    )
    with pytest.raises(VerifyError) as exc:
        _decode_certificate_payload(exts)
    assert exc.value.kind == "certificate_chain_summary_mismatch"


def test_decode_signer_display_length_mismatch_flips_kind():
    """ADR 0007 step 2 first invariant — len(signer_display) != len(signing_events)."""
    exts = certificate_extensions(
        cs=chain_summary(
            signer_count=1,
            signer_display=[signer_display_entry(), signer_display_entry()],
        ),
        signing_events=[b"\x80" * 32],  # one event but two signer_display entries
    )
    with pytest.raises(VerifyError) as exc:
        _decode_certificate_payload(exts)
    # signer_count=1 but signer_display=2 — chain-summary invariant failure.
    # (Implementation-wise: we set signer_count=1 to align with signing_events
    # length, then signer_display length=2 trips the second clause.)
    assert exc.value.kind == "certificate_chain_summary_mismatch"


def test_decode_html_without_template_hash_flips_malformed_cose():
    """ADR 0007 §"Wire shape" PresentationArtifact.template_hash — HTML
    binding requires non-null template_hash."""
    exts = certificate_extensions(
        pa=presentation_artifact(media_type="text/html", template_hash=None),
    )
    with pytest.raises(VerifyError) as exc:
        _decode_certificate_payload(exts)
    assert exc.value.kind == "malformed_cose"


def test_decode_html_with_template_hash_succeeds():
    exts = certificate_extensions(
        pa=presentation_artifact(media_type="text/html", template_hash=b"\xf1" * 32),
    )
    cert = _decode_certificate_payload(exts)
    assert cert is not None
    assert cert.presentation_artifact.media_type == "text/html"
    assert cert.presentation_artifact.template_hash == b"\xf1" * 32


def test_decode_short_attestation_signature_flips_well_formed_false():
    """ADR 0007 step 3 — Phase-1 structural attestation contract: signature
    bytes != 64 sets `attestation_signatures_well_formed = False`."""
    short_sig = {
        "authority":       "urn:trellis:authority:test-new",
        "authority_class": "new",
        "signature":       b"\x00" * 63,
    }
    exts = certificate_extensions(attestations=[short_sig])
    cert = _decode_certificate_payload(exts)
    assert cert is not None
    assert cert.attestation_signatures_well_formed is False


def test_decode_empty_signing_events_rejected():
    exts = certificate_extensions(signing_events=[])
    with pytest.raises(VerifyError):
        _decode_certificate_payload(exts)


def test_decode_empty_attestations_rejected():
    exts = certificate_extensions(attestations=[])
    with pytest.raises(VerifyError):
        _decode_certificate_payload(exts)


def test_decode_empty_signer_display_rejected():
    exts = certificate_extensions(
        cs=chain_summary(signer_display=[]),
    )
    with pytest.raises(VerifyError):
        _decode_certificate_payload(exts)


def test_decode_response_ref_round_trip():
    exts = certificate_extensions(
        cs=chain_summary(response_ref=b"\xfe" * 32),
    )
    cert = _decode_certificate_payload(exts)
    assert cert is not None
    assert cert.chain_summary.response_ref == b"\xfe" * 32


def test_decode_impact_level_null_admitted():
    """ADR 0007 §"Field semantics" `impact_level` clause: null is the valid
    omission for signing-only Trellis deployments."""
    exts = certificate_extensions(cs=chain_summary(impact_level=None))
    cert = _decode_certificate_payload(exts)
    assert cert is not None
    assert cert.chain_summary.impact_level is None


def test_decode_workflow_status_extension_admitted():
    """ADR 0007 §"Field semantics" `workflow_status` clause: append-only
    registry-extension `tstr` values admitted (Phase-1 reference verifier
    accepts any tstr)."""
    exts = certificate_extensions(
        cs=chain_summary(workflow_status="x-deployment/test-status"),
    )
    cert = _decode_certificate_payload(exts)
    assert cert is not None
    assert cert.chain_summary.workflow_status == "x-deployment/test-status"


def v2_extensions(*, rows: int = 2, mutate=None) -> dict:
    """ADR 0016 completion certificate: per-row response_ref, no aggregate."""
    exts = certificate_extensions(
        cs=chain_summary(
            signer_count=rows,
            signer_display=[
                {**signer_display_entry(principal_ref=f"signer-{i}"), "response_ref": bytes([0x10 + i]) * 32}
                for i in range(rows)
            ],
        ),
        signing_events=[bytes([0x80 + i]) * 32 for i in range(rows)],
    )
    body = exts.pop("trellis.certificate-of-completion.v1")
    del body["chain_summary"]["response_ref"]
    if mutate is not None:
        mutate(body)
    return {"trellis.certificate-of-completion.v2": body}


def test_decode_v2_retains_per_row_response_refs():
    cert = _decode_certificate_payload(v2_extensions())
    assert cert is not None and cert.is_v2
    assert [row.response_ref for row in cert.chain_summary.signer_display] == [
        b"\x10" * 32,
        b"\x11" * 32,
    ]


@pytest.mark.parametrize(
    "mutate",
    [
        lambda body: body["chain_summary"].update(response_ref=b"\x00" * 32),
        lambda body: body["chain_summary"]["signer_display"][0].pop("response_ref"),
        lambda body: body["chain_summary"]["signer_display"][0].update(response_ref=None),
        lambda body: body["chain_summary"]["signer_display"][0].update(response_ref=b"\x00" * 31),
    ],
    ids=["aggregate", "missing-row", "null-row", "short-row"],
)
def test_decode_v2_rejects_aggregate_or_malformed_row_digest(mutate):
    with pytest.raises(VerifyError):
        _decode_certificate_payload(v2_extensions(mutate=mutate))


def test_decode_v2_rejects_duplicate_signing_events():
    def duplicate(body: dict) -> None:
        body["signing_events"][1] = body["signing_events"][0]

    with pytest.raises(VerifyError) as excinfo:
        _decode_certificate_payload(v2_extensions(mutate=duplicate))
    assert excinfo.value.kind == "certificate_chain_summary_mismatch"


def test_decode_rejects_ambiguous_v1_and_v2_extensions():
    exts = {**certificate_extensions(), **v2_extensions()}
    with pytest.raises(VerifyError):
        _decode_certificate_payload(exts)


def test_decode_unknown_attestation_authority_class_is_not_well_formed():
    exts = certificate_extensions(attestations=[one_attestation("sideways")])
    cert = _decode_certificate_payload(exts)
    assert cert is not None and cert.attestation_signatures_well_formed is False


# ---------------------------------------------------------------------------
# Finalize tests.
# ---------------------------------------------------------------------------


def make_cert_details(
    *,
    certificate_id: str = "cert-test",
    signing_events: Optional[list[bytes]] = None,
    signer_count: int = 1,
    completed_at: int = 1_776_899_500,
    workflow_status: str = "completed",
    presentation_content_hash: bytes = b"\xa1" * 32,
    response_ref: Optional[bytes] = None,
    attestation_signatures_well_formed: bool = True,
) -> CertificateDetails:
    if signing_events is None:
        signing_events = [b"\x80" * 32]
    return CertificateDetails(
        certificate_id=certificate_id,
        case_ref=None,
        completed_at=TrellisTimestamp(seconds=completed_at, nanos=0),
        presentation_artifact=PresentationArtifactDetails(
            content_hash=presentation_content_hash,
            media_type="application/pdf",
            byte_length=64,
            attachment_id="urn:trellis:attachment:test",
            template_id=None,
            template_hash=None,
        ),
        chain_summary=ChainSummaryDetails(
            signer_count=signer_count,
            signer_display=[
                SignerDisplayDetails(
                    principal_ref="applicant",
                    display_name="Test Signer",
                    display_role="applicant",
                    signed_at=TrellisTimestamp(seconds=1_776_900_000, nanos=0),
                )
                for _ in signing_events
            ],
            response_ref=response_ref,
            workflow_status=workflow_status,
            impact_level=None,
            covered_claims=[],
        ),
        signing_events=signing_events,
        workflow_ref=None,
        attestation_signatures_well_formed=attestation_signatures_well_formed,
    )


def test_finalize_genesis_path_marks_attachment_resolved_true():
    """Phase-1 minimal-genesis posture mirror: genesis-append context lacks
    chain visibility; step 4 defers to the export-bundle path. The genesis-
    path outcome MUST NOT false-positive on `attachment_resolved`."""
    payloads = [(0, make_cert_details(certificate_id="cert-genesis"), b"\x00" * 32)]
    failures: list[VerificationFailure] = []
    outcomes = _finalize_certificates_of_completion(payloads, [], failures)
    assert len(outcomes) == 1
    assert outcomes[0].attachment_resolved is True
    assert all(
        f != "presentation_artifact_attachment_missing"
        for f in outcomes[0].failures
    )


def test_finalize_unresolved_signing_event_in_export_context():
    """When chain context is present (events list non-empty) and the
    signing_events digest doesn't resolve, emit `signing_event_unresolved`."""
    payloads = [(0, make_cert_details(), b"\x00" * 32)]
    failures: list[VerificationFailure] = []
    # Pass an empty events list — but we want to simulate "context exists,
    # digest unresolvable". The Phase-1 posture is: when slice doesn't have
    # the digest, mark unresolved. Since slice is empty, no event resolves,
    # and `signing_event_unresolved` would fire. (Genesis-context posture
    # marks attachment_resolved=true but step-5 step still flags missing.)
    outcomes = _finalize_certificates_of_completion(payloads, [], failures)
    # When `events` is empty, the loop has no event_by_hash entries, so each
    # signing_events digest resolves to None → signing_event_unresolved.
    assert any(f.kind == "signing_event_unresolved" for f in failures)
    assert outcomes[0].all_signing_events_resolved is False


def test_finalize_attestation_insufficient_when_signature_malformed():
    """ADR 0007 step 3 — malformed attestation row (signature_well_formed=False)
    flips `chain_summary_consistent = false` and emits `attestation_insufficient`."""
    payloads = [
        (0, make_cert_details(attestation_signatures_well_formed=False), b"\x00" * 32)
    ]
    failures: list[VerificationFailure] = []
    outcomes = _finalize_certificates_of_completion(payloads, [], failures)
    assert outcomes[0].chain_summary_consistent is False
    assert "attestation_insufficient" in outcomes[0].failures
    assert any(f.kind == "attestation_insufficient" for f in failures)


def test_finalize_certificate_id_collision_detected():
    """Two events with same certificate_id but byte-different payloads
    (different completed_at) → certificate_id_collision on second event."""
    a = make_cert_details(certificate_id="dup", completed_at=1_776_899_500)
    b = make_cert_details(certificate_id="dup", completed_at=1_776_899_999)
    payloads = [(0, a, b"\x01" * 32), (1, b, b"\x02" * 32)]
    failures: list[VerificationFailure] = []
    _finalize_certificates_of_completion(payloads, [], failures)
    assert any(f.kind == "certificate_id_collision" for f in failures)


def test_finalize_certificate_id_no_collision_when_byte_identical():
    """Two events with same certificate_id AND byte-identical payloads
    must NOT emit certificate_id_collision."""
    a = make_cert_details(certificate_id="same")
    b = make_cert_details(certificate_id="same")
    payloads = [(0, a, b"\x01" * 32), (1, b, b"\x02" * 32)]
    failures: list[VerificationFailure] = []
    _finalize_certificates_of_completion(payloads, [], failures)
    assert not any(f.kind == "certificate_id_collision" for f in failures)


class _StubResolver:
    """Resolver stub: payload bytes are the row index; behaviour per index."""

    def __init__(self, principals, proofs):
        self.principals, self.proofs = principals, proofs

    def resolve_principal_ref(self, payload: bytes):
        return self.principals[payload[0]]

    def resolve(self, payload: bytes):
        proof = self.proofs[payload[0]]
        if isinstance(proof, Exception):
            raise proof
        return None if proof is None else CertificateResponseProof(response_hash=proof)


def _finalize_v2(monkeypatch, principals, proofs):
    """Runs v2 finalize with chain-present, readable signing events so each row
    actually reaches the resolver (events=[] never would)."""
    cert = _decode_certificate_payload(v2_extensions())
    assert cert is not None
    stubs = {
        h: SimpleNamespace(
            canonical_event_hash=h,
            authored_at=cert.chain_summary.signer_display[i].signed_at,
            payload_ref_inline=bytes([i]),
            payload_ref_external=False,
            content_hash=h,
        )
        for i, h in enumerate(cert.signing_events)
    }
    events = list(stubs)
    monkeypatch.setattr(verify, "_decode_event_details", lambda event: stubs[event])
    failures: list[VerificationFailure] = []
    outcomes = _finalize_certificates_of_completion(
        [(0, cert, b"\x00" * 32)], events, failures, resolver=_StubResolver(principals, proofs)
    )
    return outcomes[0], [f.kind for f in failures]


GOOD_PROOFS = [b"\x10" * 32, b"\x11" * 32]


def test_v2_all_rows_matching_verifies(monkeypatch):
    outcome, kinds = _finalize_v2(monkeypatch, ["signer-0", "signer-1"], GOOD_PROOFS)
    assert kinds == [] and outcome.failures == []
    assert outcome.attestation_authority == "unchecked"


def test_v2_swapped_digests_fail_each_row(monkeypatch):
    _, kinds = _finalize_v2(monkeypatch, ["signer-0", "signer-1"], GOOD_PROOFS[::-1])
    assert kinds == ["response_ref_mismatch"] * 2


def test_v2_malformed_digest_fails_closed(monkeypatch):
    _, kinds = _finalize_v2(
        monkeypatch, ["signer-0", "signer-1"], [MalformedResponseDigestError("x"), GOOD_PROOFS[1]]
    )
    assert kinds == ["malformed_response_digest"]


@pytest.mark.parametrize("principal", [None, ""], ids=["missing", "empty"])
def test_v2_missing_or_empty_principal_is_unresolved(monkeypatch, principal):
    outcome, kinds = _finalize_v2(monkeypatch, [principal, "signer-1"], GOOD_PROOFS)
    assert kinds == ["signing_event_unresolved"]
    assert outcome.all_signing_events_resolved is False
    assert outcome.chain_summary_consistent is True


def test_v2_wrong_principal_is_a_summary_mismatch(monkeypatch):
    _, kinds = _finalize_v2(monkeypatch, ["someone-else", "signer-1"], GOOD_PROOFS)
    assert kinds == ["certificate_chain_summary_mismatch"]


def test_v2_absent_proof_is_unresolved(monkeypatch):
    outcome, kinds = _finalize_v2(monkeypatch, ["signer-0", "signer-1"], [None, GOOD_PROOFS[1]])
    assert kinds == ["signing_event_unresolved"]
    assert outcome.chain_summary_consistent is True


def test_v1_unreadable_signing_event_payload_is_unresolved(monkeypatch):
    """Core step 5: a chain-present event with no readable payload is unresolved."""
    cert = _decode_certificate_payload(certificate_extensions())
    assert cert is not None
    h = cert.signing_events[0]
    stub = SimpleNamespace(
        canonical_event_hash=h,
        authored_at=cert.chain_summary.signer_display[0].signed_at,
        payload_ref_inline=None,
        payload_ref_external=False,
        payload_ref_protected=False,
        content_hash=h,
    )
    monkeypatch.setattr(verify, "_decode_event_details", lambda event: stub)
    failures: list[VerificationFailure] = []
    outcomes = _finalize_certificates_of_completion([(0, cert, b"\x00" * 32)], [h], failures)
    assert outcomes[0].all_signing_events_resolved is False
    assert [f.kind for f in failures] == ["signing_event_unresolved"]


def test_v2_whole_payload_collision(monkeypatch):
    a = _decode_certificate_payload(v2_extensions())
    b = _decode_certificate_payload(v2_extensions(mutate=lambda body: body.update(workflow_ref="x")))
    assert a is not None and b is not None
    failures: list[VerificationFailure] = []
    _finalize_certificates_of_completion(
        [(0, a, b"\x01" * 32), (1, b, b"\x02" * 32)], [], failures
    )
    assert any(f.kind == "certificate_id_collision" for f in failures)


def test_finalize_v2_status_and_claim_registries_are_empty():
    def unregistered(body: dict) -> None:
        body["chain_summary"]["workflow_status"] = "x-deployment/status"
        body["chain_summary"]["covered_claims"] = ["x-claim"]

    cert = _decode_certificate_payload(v2_extensions(mutate=unregistered))
    assert cert is not None
    failures: list[VerificationFailure] = []
    _finalize_certificates_of_completion([(0, cert, b"\x00" * 32)], [], failures)
    kinds = {f.kind for f in failures}
    assert {"certificate_enum_extension_unknown", "certificate_covered_claim_unknown"} <= kinds


# ---------------------------------------------------------------------------
# Export-extension parser tests.
# ---------------------------------------------------------------------------


def test_parse_certificate_export_extension_round_trip():
    manifest_map = {
        "extensions": {
            "trellis.export.certificates-of-completion.v1": {
                "catalog_ref":    "065-certificates-of-completion.cbor",
                "catalog_digest": b"\xab" * 32,
                "entry_count":    3,
            }
        }
    }
    result = _parse_certificate_export_extension(manifest_map)
    assert result is not None
    catalog_ref, catalog_digest, entry_count = result
    assert catalog_ref == "065-certificates-of-completion.cbor"
    assert catalog_digest == b"\xab" * 32
    assert entry_count == 3


def test_parse_certificate_export_extension_returns_none_when_absent():
    assert _parse_certificate_export_extension({}) is None
    assert _parse_certificate_export_extension({"extensions": {}}) is None


def test_parse_certificate_export_extension_rejects_non_ascii_catalog_ref():
    manifest_map = {
        "extensions": {
            "trellis.export.certificates-of-completion.v1": {
                "catalog_ref":    "065-certificates-of-completion-é.cbor",
                "catalog_digest": b"\xab" * 32,
                "entry_count":    1,
            }
        }
    }
    with pytest.raises(VerifyError):
        _parse_certificate_export_extension(manifest_map)


# ---------------------------------------------------------------------------
# Catalog parser tests.
# ---------------------------------------------------------------------------


def test_parse_certificate_catalog_entries_round_trip():
    import cbor2

    catalog = [
        {
            "canonical_event_hash": b"\xc1" * 32,
            "certificate_id":       "cert-1",
            "completed_at":         [1_776_899_500, 0],
            "signer_count":         2,
            "media_type":           "application/pdf",
            "attachment_id":        "urn:trellis:attachment:cert-1",
            "workflow_status":      "countersigned",
        }
    ]
    rows = _parse_certificate_catalog_entries(cbor2.dumps(catalog, canonical=True))
    assert len(rows) == 1
    assert rows[0]["canonical_event_hash"] == b"\xc1" * 32
    assert rows[0]["certificate_id"] == "cert-1"
    assert rows[0]["signer_count"] == 2
    assert rows[0]["workflow_status"] == "countersigned"


def test_parse_certificate_catalog_entries_rejects_non_array_root():
    import cbor2

    with pytest.raises(VerifyError):
        _parse_certificate_catalog_entries(cbor2.dumps({"not": "array"}, canonical=True))


# ---------------------------------------------------------------------------
# Externally selected operator authority (ADR 0016 §Verification).
# ---------------------------------------------------------------------------

AUTHORITY_URI = "urn:trellis:authority:operator-1"
ATTEST_COMPLETED_AT = 1_776_899_500
CERTIFICATE_EXTENSION = "trellis.certificate-of-completion.v1"
VECTORS = Path(__file__).resolve().parents[2] / "fixtures" / "vectors"


def _trust(key: Ed25519PrivateKey, **overrides) -> dict[str, TrustedCertificateAuthority]:
    binding = dict(
        public_key=key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
        authority_class="new",
        allowed_purpose=CERTIFICATE_EXTENSION,
        valid_from=TrellisTimestamp(ATTEST_COMPLETED_AT, 0),
        valid_until=TrellisTimestamp(ATTEST_COMPLETED_AT + 60, 0),
    )
    return {AUTHORITY_URI: TrustedCertificateAuthority(**{**binding, **overrides})}


def _signed_certificate(key: Ed25519PrivateKey, certificate_id: str = "urn:trellis:certificate:test:1"):
    preimage = _attestation_preimage(
        certificate_id, TrellisTimestamp(ATTEST_COMPLETED_AT, 0), "new"
    )
    row = {
        "authority": AUTHORITY_URI,
        "authority_class": "new",
        "signature": key.sign(preimage),
    }
    cert = _decode_certificate_payload(
        certificate_extensions(certificate_id=certificate_id, attestations=[row])
    )
    assert cert is not None
    return cert


def _authority_outcome(cert, authorities):
    failures: list[VerificationFailure] = []
    outcome = _finalize_certificates_of_completion(
        [(0, cert, b"\x00" * 32)], [], failures, authorities=authorities
    )[0]
    return outcome, [f.kind for f in failures]


def test_attestation_preimage_matches_the_committed_rust_preimage():
    tag = b"trellis-transition-attestation-v1"
    component = (
        VECTORS
        / "append/030-certificate-of-completion-html-template/input-attestation-preimage-00-new.cbor"
    ).read_bytes()
    assert _attestation_preimage(
        "urn:trellis:certificate:test:030", TrellisTimestamp(1_776_899_500, 0), "new"
    ) == (
        len(tag).to_bytes(4, "big") + tag + len(component).to_bytes(4, "big") + component
    )


def test_authority_is_unchecked_without_a_selected_registry():
    key = Ed25519PrivateKey.generate()
    outcome, _ = _authority_outcome(_signed_certificate(key), None)
    assert outcome.attestation_authority == "unchecked"
    assert "attestation_insufficient" not in outcome.failures


def test_authority_is_verified_by_an_exact_trusted_binding():
    key = Ed25519PrivateKey.generate()
    outcome, kinds = _authority_outcome(_signed_certificate(key), _trust(key))
    assert outcome.attestation_authority == "verified"
    assert "attestation_insufficient" not in kinds


@pytest.mark.parametrize(
    "registry",
    [
        pytest.param(lambda key: {}, id="unknown-authority"),
        pytest.param(lambda key: _trust(Ed25519PrivateKey.generate()), id="foreign-key"),
        pytest.param(lambda key: _trust(key, authority_class="prior"), id="wrong-class"),
        pytest.param(
            lambda key: _trust(key, allowed_purpose="trellis.certificate-of-completion.v2"),
            id="wrong-purpose",
        ),
        pytest.param(
            lambda key: _trust(key, valid_from=TrellisTimestamp(ATTEST_COMPLETED_AT + 1, 0)),
            id="not-yet-valid",
        ),
        pytest.param(
            lambda key: _trust(key, valid_until=TrellisTimestamp(ATTEST_COMPLETED_AT - 1, 0)),
            id="expired",
        ),
    ],
)
def test_authority_fails_closed_without_an_exact_trusted_binding(registry):
    key = Ed25519PrivateKey.generate()
    outcome, kinds = _authority_outcome(_signed_certificate(key), registry(key))
    assert outcome.attestation_authority == "failed"
    assert outcome.chain_summary_consistent is False
    assert "attestation_insufficient" in kinds


def test_authority_interval_is_inclusive_at_both_ends():
    key = Ed25519PrivateKey.generate()
    registry = _trust(
        key,
        valid_from=TrellisTimestamp(ATTEST_COMPLETED_AT, 0),
        valid_until=TrellisTimestamp(ATTEST_COMPLETED_AT, 0),
    )
    outcome, _ = _authority_outcome(_signed_certificate(key), registry)
    assert outcome.attestation_authority == "verified"


def test_attestation_rows_with_non_text_authority_are_a_decode_failure_not_a_crash():
    for bad in (
        {"authority": ["urn"], "authority_class": "new", "signature": b"\x00" * 64},
        {"authority": "urn", "authority_class": 7, "signature": b"\x00" * 64},
    ):
        with pytest.raises(VerifyError):
            _decode_certificate_payload(certificate_extensions(attestations=[bad]))


@pytest.mark.parametrize("certificate_id", [" \u3000", "x" * 1025, "é" * 513], ids=["blank", "long", "multibyte"])
def test_certificate_ids_rust_refuses_cannot_be_trusted(certificate_id):
    key = Ed25519PrivateKey.generate()
    with pytest.raises(ValueError):
        _attestation_preimage(certificate_id, TrellisTimestamp(ATTEST_COMPLETED_AT, 0), "new")
    row = {"authority": AUTHORITY_URI, "authority_class": "new", "signature": b"\x00" * 64}
    cert = _decode_certificate_payload(
        certificate_extensions(certificate_id=certificate_id, attestations=[row])
    )
    outcome, _ = _authority_outcome(cert, _trust(key))
    assert outcome.attestation_authority == "failed"


# ---------------------------------------------------------------------------
# External registry file: `verify_wos.certificate_authorities_from_json`
# mirrors Rust `trellis_verify_wos::certificate_authorities_from_json`.
# ---------------------------------------------------------------------------

REGISTRY_043 = (
    VECTORS / "verify/043-export-015-operator-authority-verified/input-certificate-authorities.json"
)


def _registry_row(**changes) -> dict:
    row = {
        "authority": "urn:test:operator",
        "publicKey": [7] * 32,
        "authorityClass": "new",
        "allowedPurpose": "trellis.certificate-of-completion.v2",
        "validFrom": [0, 0],
        "validUntil": [10, 0],
    }
    row.update(changes)
    return row


def _registry_bytes(rows) -> bytes:
    return json.dumps(rows).encode()


def test_the_committed_registry_loads_as_an_exact_binding():
    registry = verify_wos.certificate_authorities_from_json(REGISTRY_043.read_bytes())
    authority = registry["urn:test:operator"]
    assert len(registry) == 1
    assert len(authority.public_key) == 32
    assert authority.authority_class == "new"
    assert authority.allowed_purpose == "trellis.certificate-of-completion.v2"
    assert authority.valid_from == TrellisTimestamp(0, 0)
    assert authority.valid_until == TrellisTimestamp(4_102_444_800, 0)


@pytest.mark.parametrize(
    "rows",
    [
        pytest.param({}, id="root-not-array"),
        pytest.param([_registry_row(extra=1)], id="unknown-field"),
        pytest.param([{k: v for k, v in _registry_row().items() if k != "validUntil"}], id="missing-field"),
        pytest.param([_registry_row(publicKey=[7] * 31)], id="short-key"),
        pytest.param([_registry_row(publicKey=[256] + [7] * 31)], id="key-byte-out-of-range"),
        pytest.param([_registry_row(publicKey=[7.0] * 32)], id="key-byte-float"),
        pytest.param([_registry_row(publicKey=[True] * 32)], id="key-byte-bool"),
        pytest.param([_registry_row(authority=" ")], id="blank-authority"),
        pytest.param([_registry_row(authority="é" * 513)], id="authority-over-1024-bytes"),
        pytest.param([_registry_row(authorityClass="other")], id="unknown-class"),
        pytest.param([_registry_row(allowedPurpose="trellis.other")], id="unknown-purpose"),
        pytest.param([_registry_row(validFrom=[0, 1_000_000_000])], id="nanos-out-of-range"),
        pytest.param([_registry_row(validFrom=[0, 0, 0])], id="instant-shape"),
        pytest.param([_registry_row(validFrom=[10, 0])], id="empty-window"),
        pytest.param([_registry_row(), _registry_row()], id="duplicate-authority"),
        pytest.param([_registry_row(authority=f"urn:{i}") for i in range(9)], id="too-many-rows"),
    ],
)
def test_a_malformed_registry_is_refused(rows):
    with pytest.raises(ValueError):
        verify_wos.certificate_authorities_from_json(_registry_bytes(rows))


def test_a_duplicated_field_or_an_oversized_registry_is_refused():
    duplicated = _registry_bytes([_registry_row()]).replace(
        b'"authorityClass": "new"', b'"authorityClass": "new", "authorityClass": "prior"'
    )
    assert duplicated.count(b"authorityClass") == 2
    with pytest.raises(ValueError):
        verify_wos.certificate_authorities_from_json(duplicated)
    with pytest.raises(ValueError):
        verify_wos.certificate_authorities_from_json(b" " * (32 * 1024 + 1))
