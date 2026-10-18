"""Native external attachment profile (Core §9.4.1, TR-CORE-182).

The parser cases mirror Rust `trellis_cddl::external_attachment` tests input
for input. End-to-end parity with the Rust verifier is asserted by
`trellis_py.conformance` against `export/019` and by integrity-verify-parity.
"""

from __future__ import annotations

import copy
import dataclasses
from pathlib import Path
from types import SimpleNamespace

import cbor2
import pytest

from trellis_py import verify, verify_wos
from trellis_py._cbor_canonical import encode_canonical_cbor_value
from trellis_py.external_attachment import (
    ATTACHMENT_BINDING_EXTENSION,
    EXTERNAL_ATTACHMENT_PROFILE,
    PROFILE_EXTENSION,
    ExternalAttachmentProfileError,
    parse_external_attachment_profile,
)

EXPORT_019 = (
    Path(__file__).resolve().parents[2]
    / "fixtures/vectors/export/019-assembled-native-external-attachment/expected-export.zip"
).read_bytes()


def _hash_text() -> str:
    return "sha256:" + "08" * 32


def _event() -> dict:
    return {
        "version": 1,
        "ledger_scope": b"scope",
        "sequence": 0,
        "prev_hash": None,
        "header": {
            "event_type": b"substrate.append.accepted_attachment_binding",
            "classification": b"service_only",
            "authored_at": [1, 0],
            "retention_tier": 1,
            "outcome_commitment": None,
            "subject_ref_commitment": None,
            "tag_commitment": None,
            "witness_ref": None,
            "extensions": None,
        },
        "content_hash": bytes([8] * 32),
        "idempotency_key": b"\x01",
        "payload_ref": {
            "ref_type": "external",
            "content_hash": bytes([8] * 32),
            "availability": 0,
            "retrieval_hint": None,
        },
        "key_bag": {
            "entries": [
                {
                    "recipient": b"\x01",
                    "suite": 1,
                    "ephemeral_pubkey": bytes([3] * 32),
                    "wrapped_dek": bytes([4] * 48),
                }
            ]
        },
        "extensions": {
            PROFILE_EXTENSION: EXTERNAL_ATTACHMENT_PROFILE,
            ATTACHMENT_BINDING_EXTENSION: {
                "attachment_id": "logical",
                "slot_path": "/file",
                "media_type": "image/jpeg",
                "byte_length": 4,
                "attachment_sha256": _hash_text(),
                "payload_content_hash": _hash_text(),
                "filename": None,
                "prior_binding_hash": None,
            },
        },
    }


def _parse(event: dict):
    return parse_external_attachment_profile(encode_canonical_cbor_value(event))


def _rejected(event: dict) -> bool:
    try:
        _parse(event)
    except ExternalAttachmentProfileError:
        return True
    return False


def _binding(event: dict) -> dict:
    return event["extensions"][ATTACHMENT_BINDING_EXTENSION]


def test_profile_is_admitted_with_its_decoding_inputs():
    parsed = _parse(_event())
    assert parsed.original_sha256 == bytes([8] * 32)
    assert parsed.original_byte_length == 4
    assert parsed.key_bag_entries[0].wrapped_dek == bytes([4] * 48)


def test_an_unmarked_event_keeps_its_existing_reading():
    event = _event()
    event["extensions"] = None
    assert _parse(event) is None
    event["extensions"] = {"unrelated": None}
    assert _parse(event) is None


def test_an_unknown_marker_or_missing_binding_is_rejected():
    event = _event()
    event["extensions"][PROFILE_EXTENSION] = "unknown"
    assert _rejected(event)
    event["extensions"][PROFILE_EXTENSION] = EXTERNAL_ATTACHMENT_PROFILE.encode()
    assert _rejected(event)
    event = _event()
    del event["extensions"][ATTACHMENT_BINDING_EXTENSION]
    assert _rejected(event)


def test_inline_carriage_or_a_mismatched_hash_is_rejected():
    event = _event()
    event["payload_ref"]["ref_type"] = "inline"
    assert _rejected(event)
    event = _event()
    event["payload_ref"]["content_hash"] = bytes([7] * 32)
    assert _rejected(event)
    event = _event()
    _binding(event)["attachment_sha256"] = "sha256:" + "AB" * 32
    assert _rejected(event)


def test_duplicate_keys_and_noncanonical_encoding_are_rejected():
    canonical = encode_canonical_cbor_value(_event())
    reference = encode_canonical_cbor_value(_event()["payload_ref"])
    assert reference[0] == 0xA4
    duplicated = (
        b"\xa5" + reference[1:] + encode_canonical_cbor_value("ref_type")
        + encode_canonical_cbor_value("external")
    )
    with pytest.raises(ExternalAttachmentProfileError):
        parse_external_attachment_profile(canonical.replace(reference, duplicated))
    loose = cbor2.dumps(_event())
    assert loose != canonical
    with pytest.raises(ExternalAttachmentProfileError):
        parse_external_attachment_profile(loose)


def test_an_empty_key_bag_or_an_extra_reference_field_is_rejected():
    event = _event()
    event["key_bag"]["entries"] = []
    assert _rejected(event)
    event = _event()
    event["payload_ref"]["nonce"] = bytes(12)
    assert _rejected(event)


@pytest.mark.parametrize("kind", ["recipient", "ephemeral", "suite", "wrapped_dek"])
def test_duplicate_wraps_a_wrong_suite_or_a_short_wrapped_key_is_rejected(kind):
    event = _event()
    entries = event["key_bag"]["entries"]
    second = copy.deepcopy(entries[0])
    if kind == "recipient":
        second["ephemeral_pubkey"] = bytes([9] * 32)
        entries.append(second)
    elif kind == "ephemeral":
        second["recipient"] = b"\x09"
        entries.append(second)
    elif kind == "suite":
        entries[0]["suite"] = 2
    else:
        entries[0]["wrapped_dek"] = bytes([4] * 32)
    assert _rejected(event)


def test_an_invalid_pointer_or_idempotency_key_length_is_rejected():
    event = _event()
    _binding(event)["slot_path"] = "/file~2"
    assert _rejected(event)
    for length in (0, 65):
        event = _event()
        event["idempotency_key"] = b"\x01" * length
        assert _rejected(event)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("version", 2),
        ("ledger_scope", b""),
        ("sequence", "zero"),
        ("prev_hash", bytes([1] * 31)),
    ],
)
def test_malformed_root_fields_are_rejected(key, value):
    event = _event()
    event[key] = value
    assert _rejected(event)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("event_type", b"\xff"),
        ("classification", b""),
        ("authored_at", [1, 1_000_000_000]),
        ("retention_tier", 4),
        ("outcome_commitment", bytes([1] * 31)),
        ("witness_ref", "invalid"),
        ("extra", None),
    ],
)
def test_malformed_native_header_fields_are_rejected(key, value):
    event = _event()
    event["header"][key] = value
    assert _rejected(event)


def test_an_empty_header_extension_map_is_admitted():
    event = _event()
    event["header"]["extensions"] = {}
    assert _parse(event) is not None


def test_the_service_export_verifies_without_claiming_the_original_readable():
    report = verify_wos.verify_export_zip(EXPORT_019)
    assert report.trellis.structure_verified
    assert report.trellis.integrity_verified
    assert not report.trellis.readability_verified
    assert report.trellis.warnings == [verify.PROTECTED_ORIGINALS_UNCHECKED_WARNING]
    assert report.wos_findings == []


def _export_019_event() -> verify.ParsedSign1:
    return verify._parse_sign1_array(verify.parse_export_zip(EXPORT_019)["010-events.cbor"])[0]


def test_the_protected_original_is_never_offered_to_a_reader():
    event = _export_019_event()
    details = verify._decode_event_details(event)
    assert details.payload_ref_protected
    blobs = {details.content_hash: b"ciphertext"}
    assert verify._readable_payload_bytes(details, blobs) is None
    assert verify._affirmation_payload_bytes(details, blobs) is None


def test_a_signed_unknown_marker_fails_the_event_before_any_reader():
    event = _export_019_event()
    payload = cbor2.loads(event.payload)
    payload["extensions"][PROFILE_EXTENSION] = "unknown"
    event = dataclasses.replace(event, payload=encode_canonical_cbor_value(payload))
    with pytest.raises(verify.VerifyError, match="external attachment profile"):
        verify._decode_event_details(event)


def test_a_certificate_cannot_resolve_a_protected_presentation_original(monkeypatch):
    binding = SimpleNamespace(attachment_id="logical", payload_content_hash=b"\x01" * 32)
    binding_event = SimpleNamespace(
        attachment_binding=binding, payload_ref_protected=True, certificate=None
    )
    certificate = SimpleNamespace(
        presentation_artifact=SimpleNamespace(attachment_id="logical", content_hash=b"\x02" * 32)
    )
    certificate_event = SimpleNamespace(
        attachment_binding=None,
        payload_ref_protected=False,
        certificate=certificate,
        canonical_event_hash=b"\x03" * 32,
    )
    stubs = {"binding": binding_event, "certificate": certificate_event}
    monkeypatch.setattr(verify, "_decode_event_details", lambda event: stubs[event])
    outcome = verify.CertificateOfCompletionOutcome(
        certificate_id="urn:test:certificate",
        event_index=1,
        completed_at=verify.TrellisTimestamp(1, 0),
        signer_count=1,
    )
    report = verify.VerificationReport(certificates_of_completion=[outcome])
    # The ciphertext is present, so only the protection keeps it unresolved.
    blobs = {binding.payload_content_hash: b"ciphertext"}
    verify._verify_certificate_attachment_lineage(["binding", "certificate"], blobs, report)
    assert not outcome.attachment_resolved
    assert outcome.failures == ["presentation_artifact_attachment_missing"]
    assert [f.kind for f in report.event_failures] == ["presentation_artifact_attachment_missing"]
    assert "protected presentation original is unchecked" in report.warnings[0]
