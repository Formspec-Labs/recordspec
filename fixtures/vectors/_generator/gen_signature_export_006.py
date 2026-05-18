"""Generate Trellis signature-affirmation export / verify / tamper vectors.

Authoring aid only. The committed fixture bytes and derivation notes are the
evidence surface; this script exists so the CBOR and ZIP bytes are
reproducible.
"""

from __future__ import annotations

import copy
import hashlib
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cbor2  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from _lib.byte_utils import (  # noqa: E402
    ALG_EDDSA,
    CBOR_TAG_COSE_SIGN1,
    COSE_LABEL_ALG,
    COSE_LABEL_KID,
    COSE_LABEL_SUITE_ID,
    ARTIFACT_TYPE_CHECKPOINT,
    ARTIFACT_TYPE_EVENT,
    ARTIFACT_TYPE_MANIFEST,
    COSE_LABEL_ARTIFACT_TYPE,
    SUITE_ID_PHASE_1,
    dcbor,
    deterministic_zipinfo,
    domain_separated_sha256,
    trellis_cli_verify_script,
    ts,
)


ROOT = Path(__file__).resolve().parent.parent
APPEND_019 = ROOT / "append" / "019-wos-signature-affirmation"
KEY_ISSUER_001 = ROOT / "_keys" / "issuer-001.cose_key"

OUT_EXPORT_006 = ROOT / "export" / "006-signature-affirmations-inline"
OUT_EXPORT_007 = ROOT / "export" / "007-signature-admission-failed-inline"
OUT_EXPORT_008 = ROOT / "export" / "008-signed-acts-fallback-act-id"
OUT_EXPORT_009 = ROOT / "export" / "009-signed-acts-manifest-only"
OUT_VERIFY_014 = ROOT / "verify" / "014-export-006-signature-row-mismatch"
OUT_VERIFY_019 = ROOT / "verify" / "019-export-006-signed-acts-render-drift"
OUT_VERIFY_020 = ROOT / "verify" / "020-export-006-signed-acts-unsupported-rule"
OUT_VERIFY_021 = ROOT / "verify" / "021-signed-acts-manifest-tamper"
OUT_VERIFY_022 = ROOT / "verify" / "022-066-render-drift-tampered-only"
OUT_TAMPER_014 = ROOT / "tamper" / "014-signature-catalog-digest-mismatch"
OUT_TAMPER_055 = ROOT / "tamper" / "055-signed-acts-catalog-digest-mismatch"
OUT_TAMPER_056 = ROOT / "tamper" / "056-policy-closure-digest-mismatch"

TAG_TRELLIS_CHECKPOINT_V1 = "trellis-checkpoint-v1"
TAG_TRELLIS_MERKLE_LEAF_V1 = "trellis-merkle-leaf-v1"
TAG_TRELLIS_CONTENT_V1 = "trellis-content-v1"
TAG_TRELLIS_AUTHOR_EVENT_V1 = "trellis-author-event-v1"
TAG_TRELLIS_EVENT_V1 = "trellis-event-v1"
WOS_SIGNATURE_AFFIRMATION_EVENT_TYPE = "wos.kernel.signature_affirmation"
WOS_SIGNATURE_ADMISSION_FAILED_EVENT_TYPE = "wos.kernel.signature_admission_failed"
EXTENSION_KEY = "trellis.export.signature-affirmations.v1"
SIGNED_ACTS_EXTENSION_KEY = "trellis.export.signed-acts.v1"
SIGNED_ACTS_MEMBER = "066-signed-acts.cbor"
SIGNED_ACTS_DERIVATION_RULE_V1 = "signed-act-projection-wos-formspec-v1"
SIGNED_ACTS_DERIVATION_RULE_V2 = "signed-act-projection-wos-formspec-v2"
SIGNED_ACTS_DERIVATION_RULE = SIGNED_ACTS_DERIVATION_RULE_V1
FALLBACK_ACT_ID_DERIVATION_RULE = "signed-act-projection-act-id-v1"
UNSUPPORTED_SIGNED_ACTS_DERIVATION_RULE = "signed-act-projection-wos-formspec-unsupported"
# 068 signed-acts-manifest member (substrate-anchored proof of which
# signature_affirmation / signature_admission_failed events landed). Mirrors
# Rust `crates/trellis-export-writer/src/lib.rs::SIGNED_ACTS_MANIFEST_MEMBER`
# and the §6.7 extension key registered for Task A1.
SIGNED_ACTS_MANIFEST_EXTENSION_KEY = "trellis.export.signed-acts.manifest.v1"
SIGNED_ACTS_MANIFEST_MEMBER = "068-signed-acts-manifest.cbor"
SIGNED_ACTS_MANIFEST_DERIVATION_RULE_V1 = "signed-acts-manifest-v1"
POLICY_CLOSURE_EXTENSION_KEY = "trellis.export.policy-closure.v1"
POLICY_CLOSURE_MEMBER = "067-policy-closure.cbor"
POLICY_CLOSURE_VERSION = "wos-formspec-signature-policy-closure-2026-05-16"
POLICY_CLOSURE_ARTIFACT_KINDS = [
    "formspec.signing-intent-registry.v1",
    "formspec.signature-method-registry.v1",
    "wos.signature-posture-floors.v1",
    "wos.signer-authority-shape.v1",
    "wos.identity-proofing-primitives.v1",
    "wos.signature-defaults.v1",
    "wos.signature-deny-rules.v1",
    "wos.signature-tombstones.v1",
]


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def load_seed_and_pubkey(path: Path) -> tuple[bytes, bytes]:
    cose_key = cbor2.loads(path.read_bytes())
    seed = cose_key[-4]
    pubkey = cose_key[-2]
    assert isinstance(seed, bytes) and len(seed) == 32
    assert isinstance(pubkey, bytes) and len(pubkey) == 32
    return seed, pubkey


def derive_kid(suite_id: int, pubkey_raw: bytes) -> bytes:
    return hashlib.sha256(dcbor(suite_id) + pubkey_raw).digest()[:16]


def protected_header(kid: bytes, artifact_type: str = ARTIFACT_TYPE_EVENT) -> bytes:
    return dcbor(
        {
            COSE_LABEL_ALG: ALG_EDDSA,
            COSE_LABEL_KID: kid,
            COSE_LABEL_SUITE_ID: SUITE_ID_PHASE_1, COSE_LABEL_ARTIFACT_TYPE: artifact_type,
        }
    )


def cose_sign1(seed: bytes, kid: bytes, payload_bytes: bytes, artifact_type: str = ARTIFACT_TYPE_EVENT) -> bytes:
    protected = protected_header(kid, artifact_type)
    sig_structure = dcbor(["Signature1", protected, b"", payload_bytes])
    signature = Ed25519PrivateKey.from_private_bytes(seed).sign(sig_structure)
    return dcbor(cbor2.CBORTag(CBOR_TAG_COSE_SIGN1, [protected, {}, payload_bytes, signature]))


def load_sign1_payload(sign1_bytes: bytes) -> dict:
    tag = cbor2.loads(sign1_bytes)
    assert isinstance(tag, cbor2.CBORTag) and tag.tag == CBOR_TAG_COSE_SIGN1
    return cbor2.loads(tag.value[2])


def checkpoint_digest(scope: bytes, checkpoint_payload: dict) -> bytes:
    preimage = {"version": 1, "scope": scope, "checkpoint_payload": checkpoint_payload}
    return domain_separated_sha256(TAG_TRELLIS_CHECKPOINT_V1, dcbor(preimage))


def merkle_leaf_hash(canonical_hash: bytes) -> bytes:
    return domain_separated_sha256(TAG_TRELLIS_MERKLE_LEAF_V1, canonical_hash)


def build_signing_key_registry(kid: bytes, pubkey: bytes) -> bytes:
    entry = {
        "kid": kid,
        "pubkey": pubkey,
        "suite_id": SUITE_ID_PHASE_1,
        "status": 0,
        "valid_from": ts(1776877800),
        "valid_to": None,
        "supersedes": None,
        "attestation": None,
    }
    return dcbor([entry])


def build_domain_registry(*, include_admission_failed: bool = False) -> bytes:
    event_types = {
        WOS_SIGNATURE_AFFIRMATION_EVENT_TYPE: {
            "privacy_class": "restricted",
            "binding_family": "wos.signatureProfile",
        }
    }
    if include_admission_failed:
        event_types[WOS_SIGNATURE_ADMISSION_FAILED_EVENT_TYPE] = {
            "privacy_class": "restricted",
            "binding_family": "wos.signatureProfile",
        }
    return dcbor(
        {
            "governance": {
                "ruleset_id": "x-trellis-test/governance-ruleset-signature-v1",
                "ruleset_digest": sha256(b"x-trellis-test/governance-ruleset-signature-v1"),
            },
            "event_types": event_types,
            "classifications": ["x-trellis-test/unclassified"],
            "role_vocabulary": ["x-trellis-test/role-applicant-signer"],
            "registry_version": "x-trellis-test/registry-signature-v1",
        }
    )


def write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def write_zip(path: Path, *, root_dir: str, members: list[str], data: dict[str, bytes]) -> bytes:
    with zipfile.ZipFile(path, "w") as zf:
        for member in sorted(members):
            zf.writestr(deterministic_zipinfo(f"{root_dir}/{member}"), data[member])
        for info in zf.filelist:
            info.external_attr = 0
    return path.read_bytes()


def export_members_from_dir(export_dir: Path) -> tuple[str, list[str], dict[str, bytes], dict]:
    ledger_state = cbor2.loads((export_dir / "input-ledger-state.cbor").read_bytes())
    root_dir = ledger_state["root_dir"]
    members = list(ledger_state["members"])
    data = {member: (export_dir / member).read_bytes() for member in members}
    manifest_tag = cbor2.loads(data["000-manifest.cbor"])
    manifest_payload = cbor2.loads(manifest_tag.value[2])
    return root_dir, members, data, manifest_payload


def signature_catalog_entry(canonical_event_hash: bytes, wos_record: dict) -> dict:
    data = wos_record["data"]
    signing_act_id = data.get("signingActId") or data.get("sourceSignatureId") or "signing-act-1"
    presentation_hash = data.get("presentationHash") or data["documentHash"]
    signing_act_id = str(signing_act_id)
    presentation_hash = str(presentation_hash)
    entry = {
        "canonical_event_hash": canonical_event_hash,
        "signing_act_id": signing_act_id,
        "presentation_hash": presentation_hash,
        "signer_id": data["signerId"],
        "role_id": data["roleId"],
        "role": data["role"],
        "document_id": data["documentId"],
        "document_hash": data["documentHash"],
        "document_hash_algorithm": data["documentHashAlgorithm"],
        "signed_at": data["signedAt"],
        "identity_binding": data["identityBinding"],
        "consent_reference": data["consentReference"],
        "signature_provider": data["signatureProvider"],
        "ceremony_id": data["ceremonyId"],
        "profile_ref": data["profileRef"],
        "formspec_response_ref": data.get("sourceResponseRef") or data["formspecResponseRef"],
    }
    for source_key, catalog_key in [
        ("sourceSignatureSystem", "source_signature_system"),
        ("sourceSignatureId", "source_signature_id"),
        ("signedPayloadDigest", "signed_payload_digest"),
        ("signedPayloadDigestAlgorithm", "signed_payload_digest_algorithm"),
        ("signingIntent", "signing_intent"),
        ("profileKey", "profile_key"),
        ("witnessedSignatureRef", "witnessed_signature_ref"),
    ]:
        if source_key in data:
            entry[catalog_key] = data[source_key]
    return entry


def source_ref(canonical_event_hash: bytes, kind: str) -> dict:
    return {
        "layer": "wos",
        "kind": kind,
        "ref": canonical_event_hash,
    }


def sorted_source_refs(refs: list[dict]) -> list[dict]:
    return sorted(
        refs,
        key=lambda ref: (
            ref["layer"],
            ref["kind"],
            dcbor(ref["ref"]),
        ),
    )


def signed_act_projection(
    canonical_event_hash: bytes,
    wos_record: dict,
    *,
    fallback_act_id_allowed: bool = False,
) -> dict:
    event_type = wos_record.get("event")
    if event_type == WOS_SIGNATURE_ADMISSION_FAILED_EVENT_TYPE:
        return rejected_signed_act_projection(canonical_event_hash, wos_record)
    if event_type != WOS_SIGNATURE_AFFIRMATION_EVENT_TYPE:
        raise ValueError(f"unsupported signed-act source event {event_type!r}")
    return admitted_signed_act_projection(
        canonical_event_hash,
        wos_record,
        fallback_act_id_allowed=fallback_act_id_allowed,
    )


def admitted_signed_act_projection(
    canonical_event_hash: bytes,
    wos_record: dict,
    *,
    fallback_act_id_allowed: bool = False,
) -> dict:
    data = wos_record["data"]
    source_response_ref = data.get("sourceResponseRef") or data["formspecResponseRef"]
    source_refs = sorted_source_refs(
        [source_ref(canonical_event_hash, "signature-affirmation")]
    )
    return {
        "act_id": projected_act_id(
            data.get("signingActId"),
            source_refs,
            fallback_act_id_allowed=fallback_act_id_allowed,
        ),
        "signer": {
            "id": data["signerId"],
            "role": data["role"],
            "role_ref": data["roleId"],
            "identity_evidence_refs": [],
        },
        "bound": {
            "subject_kind": "formspec-response",
            "subject_hash": data.get("signedPayloadDigest"),
            "subject_hash_algorithm": data.get("signedPayloadDigestAlgorithm"),
            "presentation_hash": data["presentationHash"],
            "document_id": data["documentId"],
            "document_ref": data.get("documentRef"),
            "content_hash": data["documentHash"],
            "content_hash_algorithm": data["documentHashAlgorithm"],
        },
        "intent": data["signingIntent"],
        "consent": data["consentReference"],
        "admission": {
            "outcome": "admitted",
            "source_response_ref": source_response_ref,
            "source_signature_system": data.get("sourceSignatureSystem"),
            "source_signature_id": data.get("sourceSignatureId"),
            "signature_provider": data["signatureProvider"],
            "ceremony_id": data["ceremonyId"],
            "profile_ref": data.get("profileRef"),
            "profile_key": data.get("profileKey"),
            "signed_payload_digest": data.get("signedPayloadDigest"),
            "signed_payload_digest_algorithm": data.get("signedPayloadDigestAlgorithm"),
            "primitive_verification": data.get("primitiveVerification"),
            "failure_reason": None,
        },
        "witness_of": data.get("witnessedSignatureRef"),
        "signed_at": data["signedAt"],
        "source_refs": source_refs,
    }


def rejected_signed_act_projection(canonical_event_hash: bytes, wos_record: dict) -> dict:
    data = wos_record["data"]
    evidence = data["evidenceBindings"]
    return {
        "act_id": evidence["signatureId"],
        "signer": {
            "id": data.get("signerId"),
            "role": None,
            "role_ref": None,
            "identity_evidence_refs": [],
        },
        "bound": {
            "subject_kind": "formspec-response",
            "subject_hash": evidence["signedPayloadDigest"],
            "subject_hash_algorithm": None,
            "presentation_hash": None,
            "document_id": None,
            "document_ref": None,
            "content_hash": evidence["signedPayloadDigest"],
            "content_hash_algorithm": None,
        },
        "intent": evidence["signingIntent"],
        "consent": None,
        "admission": {
            "outcome": "rejected",
            "source_response_ref": evidence["responseId"],
            "source_signature_system": None,
            "source_signature_id": evidence["signatureId"],
            "signature_provider": None,
            "ceremony_id": None,
            "profile_ref": None,
            "profile_key": None,
            "signed_payload_digest": evidence["signedPayloadDigest"],
            "signed_payload_digest_algorithm": None,
            "primitive_verification": None,
            "failure_reason": data["reason"],
        },
        "witness_of": None,
        "signed_at": data["emittedAt"],
        "source_refs": sorted_source_refs(
            [source_ref(canonical_event_hash, "signature-admission-failed")]
        ),
    }


def projected_act_id(
    signing_act_id: object,
    source_refs: list[dict],
    *,
    fallback_act_id_allowed: bool = False,
) -> str:
    if isinstance(signing_act_id, str):
        return signing_act_id
    if signing_act_id is not None:
        raise ValueError("signingActId must be text")
    if not fallback_act_id_allowed:
        raise KeyError("signingActId")
    digest = hashlib.sha256(dcbor(source_refs)).hexdigest()
    return f"{FALLBACK_ACT_ID_DERIVATION_RULE}:{digest}"


def signed_acts_catalog(
    canonical_event_hash: bytes,
    wos_record: dict,
    *,
    derivation_rule: str = SIGNED_ACTS_DERIVATION_RULE,
) -> bytes:
    fallback_act_id_allowed = derivation_rule == SIGNED_ACTS_DERIVATION_RULE_V2
    acts = [
        signed_act_projection(
            canonical_event_hash,
            wos_record,
            fallback_act_id_allowed=fallback_act_id_allowed,
        )
    ]
    acts.sort(
        key=lambda act: (
            act["act_id"],
            act["signed_at"],
            dcbor(act["source_refs"][0]),
        )
    )
    return dcbor(
        {
            "projection_schema_version": 1,
            "derivation_rule_id": derivation_rule,
            "acts": acts,
        }
    )


def derive_signed_acts_manifest_v1_bytes(events_canonical: list[tuple[bytes, str]]) -> bytes:
    """Encode the v1 signed-acts manifest member bytes.

    Mirror of Rust `derive_signed_acts_manifest_v1` + `encode_signed_acts_manifest_v1`
    in `crates/trellis-verify-wos/src/signed_acts.rs` and Python
    `trellis_py.verify_wos.derive_signed_acts_manifest_v1` /
    `encode_signed_acts_manifest_v1` (Tasks A4 + A5).

    Layout: a CBOR array of 2-element `[bstr(hash), tstr(event_type)]` pairs,
    sorted by `(hash bytes ASC, event_type ASC)`. For homogeneous bstr/tstr
    2-tuples in a top-level array, `dcbor` (cbor2 §4.2.1) wire bytes coincide
    with §4.2.2 — preimage shape pinned by the byte-identity test landed in A5.
    """
    entries = sorted(events_canonical)
    return dcbor([[event_hash, event_type] for event_hash, event_type in entries])


def signed_acts_manifest_extension(member_bytes: bytes) -> dict:
    """Build the `trellis.export.signed-acts.manifest.v1` manifest extension."""
    return {
        "catalog_ref": SIGNED_ACTS_MANIFEST_MEMBER,
        "manifest_digest": sha256(member_bytes),
        "derivation_rule": SIGNED_ACTS_MANIFEST_DERIVATION_RULE_V1,
    }


def owner_for_policy_artifact(kind: str) -> str:
    return "formspec" if kind.startswith("formspec.") else "wos"


def policy_artifact(kind: str, index: int, domain_registry_digest: bytes) -> dict:
    return {
        "owner": owner_for_policy_artifact(kind),
        "kind": kind,
        "version": "2026-05-16",
        "ref": f"urn:formspec-stack:test-policy:{kind}:2026-05-16",
        "digest_algorithm": "sha-256",
        "digest": sha256(kind.encode("utf-8") + domain_registry_digest + bytes([index])),
        "valid_from": "2026-05-16T00:00:00Z",
        "valid_to": None,
    }


def policy_closure(domain_registry_digest: bytes) -> bytes:
    return dcbor(
        {
            "closure_schema_version": 1,
            "closure_version": POLICY_CLOSURE_VERSION,
            "sealed_at": "2026-05-16T18:31:00Z",
            "owner_scope": "wos.case.signature-admission",
            "verifier_boundary": {
                "bundle_admission_policy_evidence": True,
                "bundle_trust_roots_authoritative": False,
                "verifier_supplied_trust_roots_required": True,
                "verifier_supplied_adapter_allowlists_required": True,
                "server_operational_config_included": False,
            },
            "artifacts": [
                policy_artifact(kind, index, domain_registry_digest)
                for index, kind in enumerate(POLICY_CLOSURE_ARTIFACT_KINDS)
            ],
        }
    )


def signature_admission_failed_record() -> dict:
    return {
        "id": "sba-poc_prov_01jqt0f0wm8f4b7n1j6m2r3k4q",
        "event": WOS_SIGNATURE_ADMISSION_FAILED_EVENT_TYPE,
        "actorId": "applicant",
        "timestamp": "2026-04-22T14:31:00Z",
        "auditLayer": "facts",
        "data": {
            "reason": "method_unregistered",
            "signerId": "applicant",
            "emittedAt": "2026-04-22T14:31:00Z",
            "failureContext": {
                "methodUri": "urn:formspec:sig-method:unknown@1",
                "registryVersion": "1.0.0",
            },
            "evidenceBindings": {
                "responseId": "resp-2026-0001",
                "signedPayloadDigest": "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
                "signatureId": "sig-2026-0001",
                "signingIntent": "urn:wos:signing-intent:applicant-signature",
            },
        },
    }


def build_event_from_wos_record(
    *,
    seed: bytes,
    kid: bytes,
    scope: bytes,
    sequence: int,
    prev_hash: bytes | None,
    wos_record: dict,
    idempotency_key: bytes,
    authored_at: list[int],
) -> tuple[bytes, bytes]:
    wos_record_bytes = dcbor(wos_record)
    content_hash = domain_separated_sha256(TAG_TRELLIS_CONTENT_V1, wos_record_bytes)
    header = {
        "event_type": wos_record["event"].encode("utf-8"),
        "extensions": None,
        "authored_at": authored_at,
        "witness_ref": None,
        "classification": b"x-trellis-test/unclassified",
        "retention_tier": 0,
        "tag_commitment": None,
        "outcome_commitment": None,
        "subject_ref_commitment": None,
    }
    payload_ref = {
        "ref_type": "inline",
        "ciphertext": wos_record_bytes,
        "nonce": b"\x00" * 12,
    }
    key_bag = {"entries": []}
    authored_map = {
        "version": 1,
        "ledger_scope": scope,
        "sequence": sequence,
        "prev_hash": prev_hash,
        "causal_deps": None,
        "content_hash": content_hash,
        "header": header,
        "commitments": None,
        "payload_ref": payload_ref,
        "key_bag": key_bag,
        "idempotency_key": idempotency_key,
        "extensions": None,
    }
    author_event_hash = domain_separated_sha256(
        TAG_TRELLIS_AUTHOR_EVENT_V1, dcbor(authored_map)
    )
    event_payload = {
        "version": 1,
        "ledger_scope": scope,
        "sequence": sequence,
        "prev_hash": prev_hash,
        "causal_deps": None,
        "author_event_hash": author_event_hash,
        "content_hash": content_hash,
        "header": header,
        "commitments": None,
        "payload_ref": payload_ref,
        "key_bag": key_bag,
        "idempotency_key": idempotency_key,
        "extensions": None,
    }
    canonical_event_hash = domain_separated_sha256(
        TAG_TRELLIS_EVENT_V1,
        dcbor(
            {
                "version": 1,
                "ledger_scope": scope,
                "event_payload": event_payload,
            }
        ),
    )
    return (
        cose_sign1(seed, kid, dcbor(event_payload), ARTIFACT_TYPE_EVENT),
        canonical_event_hash,
    )


def build_export_006() -> None:
    OUT_EXPORT_006.mkdir(parents=True, exist_ok=True)

    seed, pubkey = load_seed_and_pubkey(KEY_ISSUER_001)
    kid = derive_kid(SUITE_ID_PHASE_1, pubkey)

    event_bytes = (APPEND_019 / "expected-event.cbor").read_bytes()
    event_payload = load_sign1_payload(event_bytes)
    scope = event_payload["ledger_scope"]
    canonical_event_hash = cbor2.loads((APPEND_019 / "expected-append-head.cbor").read_bytes())[
        "canonical_event_hash"
    ]
    leaf_hash = merkle_leaf_hash(canonical_event_hash)
    wos_record = cbor2.loads((APPEND_019 / "input-wos-record.dcbor").read_bytes())

    members_data: dict[str, bytes] = {}

    events_cbor = dcbor([cbor2.loads(event_bytes)])
    members_data["010-events.cbor"] = events_cbor

    inclusion_proofs = dcbor(
        {
            0: {
                "leaf_index": 0,
                "tree_size": 1,
                "leaf_hash": leaf_hash,
                "audit_path": [],
            }
        }
    )
    members_data["020-inclusion-proofs.cbor"] = inclusion_proofs

    consistency_proofs = dcbor([])
    members_data["025-consistency-proofs.cbor"] = consistency_proofs

    signing_key_registry = build_signing_key_registry(kid, pubkey)
    members_data["030-signing-key-registry.cbor"] = signing_key_registry

    checkpoint_payload = {
        "version": 1,
        "scope": scope,
        "tree_size": 1,
        "tree_head_hash": leaf_hash,
        "timestamp": ts(1776877860),
        "anchor_ref": None,
        "prev_checkpoint_hash": None,
        "extensions": None,
    }
    head_checkpoint_digest = checkpoint_digest(scope, checkpoint_payload)
    members_data["040-checkpoints.cbor"] = dcbor([cbor2.loads(cose_sign1(seed, kid, dcbor(checkpoint_payload), ARTIFACT_TYPE_CHECKPOINT))])

    domain_registry = build_domain_registry()
    domain_registry_digest = sha256(domain_registry)
    domain_registry_member = f"050-registries/{domain_registry_digest.hex()}.cbor"
    members_data[domain_registry_member] = domain_registry

    signature_catalog = dcbor([signature_catalog_entry(canonical_event_hash, wos_record)])
    members_data["062-signature-affirmations.cbor"] = signature_catalog
    signed_acts = signed_acts_catalog(canonical_event_hash, wos_record)
    members_data[SIGNED_ACTS_MEMBER] = signed_acts
    signed_acts_manifest_bytes = derive_signed_acts_manifest_v1_bytes(
        [(canonical_event_hash, WOS_SIGNATURE_AFFIRMATION_EVENT_TYPE)]
    )
    members_data[SIGNED_ACTS_MANIFEST_MEMBER] = signed_acts_manifest_bytes
    policy_closure_bytes = policy_closure(domain_registry_digest)
    members_data[POLICY_CLOSURE_MEMBER] = policy_closure_bytes

    members_data["090-verify.sh"] = trellis_cli_verify_script()
    members_data["098-README.md"] = (
        "# Trellis Export (Fixture) — export/006-signature-affirmations-inline\n\n"
        "WOS-T4 signature export fixture. `062-signature-affirmations.cbor` is a "
        "chain-derived catalog over a readable WOS `SignatureAffirmation` payload "
        "and `066-signed-acts.cbor` is the verifier-facing signing projection. "
        "`068-signed-acts-manifest.cbor` is the substrate-anchored sealed list of "
        "`(canonical_event_hash, event_type)` pairs for every signed-act source "
        "event in scope; the 066 projection bytes can drift across renderers, "
        "while the 068 manifest is the load-bearing proof. "
        "`067-policy-closure.cbor` carries the effective admission-policy evidence "
        "used at export time, while verifier trust roots and adapter allowlists "
        "remain verifier-supplied configuration.\n"
    ).encode("utf-8")

    manifest_payload = {
        "format": "trellis-export/1",
        "version": 1,
        "generator": "x-trellis-test/export-generator-006-signature",
        "generated_at": ts(1776877860),
        "scope": scope,
        "tree_size": 1,
        "head_checkpoint_digest": head_checkpoint_digest,
        "registry_bindings": [
            {
                "registry_digest": domain_registry_digest,
                "registry_format": 1,
                "registry_version": "x-trellis-test/registry-signature-v1",
                "bound_at_sequence": 0,
            }
        ],
        "signing_key_registry_digest": sha256(signing_key_registry),
        "events_digest": sha256(events_cbor),
        "checkpoints_digest": sha256(members_data["040-checkpoints.cbor"]),
        "inclusion_proofs_digest": sha256(inclusion_proofs),
        "consistency_proofs_digest": sha256(consistency_proofs),
        "payloads_inlined": False,
        "external_anchors": [],
        "posture_declaration": {
            "provider_readable": True,
            "reader_held": False,
            "delegated_compute": False,
            "external_anchor_required": False,
            "external_anchor_name": None,
            "recovery_without_user": True,
            "metadata_leakage_summary": "WOS-T4 signature export fixture with readable WOS payload bytes.",
        },
        "head_format_version": 1,
        "omitted_payload_checks": [],
        "extensions": {
            EXTENSION_KEY: {
                "signature_catalog_digest": sha256(signature_catalog),
            },
            SIGNED_ACTS_EXTENSION_KEY: {
                "catalog_digest": sha256(signed_acts),
                "catalog_ref": SIGNED_ACTS_MEMBER,
                "derivation_rule": SIGNED_ACTS_DERIVATION_RULE,
            },
            SIGNED_ACTS_MANIFEST_EXTENSION_KEY: signed_acts_manifest_extension(
                signed_acts_manifest_bytes
            ),
            POLICY_CLOSURE_EXTENSION_KEY: {
                "closure_digest": sha256(policy_closure_bytes),
                "closure_ref": POLICY_CLOSURE_MEMBER,
                "closure_version": POLICY_CLOSURE_VERSION,
            },
        },
    }
    members_data["000-manifest.cbor"] = cose_sign1(seed, kid, dcbor(manifest_payload), ARTIFACT_TYPE_MANIFEST)

    for member, member_bytes in members_data.items():
        write_bytes(OUT_EXPORT_006 / member, member_bytes)

    members = sorted(members_data)
    root_dir = f"trellis-export-{scope.decode('utf-8')}-1-{leaf_hash.hex()[:8]}"
    zip_bytes = write_zip(
        OUT_EXPORT_006 / "expected-export.zip",
        root_dir=root_dir,
        members=members,
        data=members_data,
    )
    ledger_state = {
        "version": 1,
        "scope": scope,
        "tree_size": 1,
        "root_dir": root_dir,
        "members": members,
        "notes": "Fixture ledger_state for export/006-signature-affirmations-inline; pack listed members into deterministic ZIP.",
    }
    write_bytes(OUT_EXPORT_006 / "input-ledger-state.cbor", dcbor(ledger_state))
    write_text(
        OUT_EXPORT_006 / "manifest.toml",
        f'''id          = "export/006-signature-affirmations-inline"
op          = "export"
status      = "active"
description = """Single-event WOS-T4 export that carries a WOS `SignatureAffirmation` event, binds `062-signature-affirmations.cbor` through `trellis.export.signature-affirmations.v1`, binds verifier-facing `066-signed-acts.cbor` through `trellis.export.signed-acts.v1`, and binds effective policy evidence through `067-policy-closure.cbor` / `trellis.export.policy-closure.v1`."""

[coverage]
tr_core = [
    "TR-CORE-006",
    "TR-CORE-062",
    "TR-CORE-063",
    "TR-CORE-064",
    "TR-CORE-065",
    "TR-CORE-067",
    "TR-CORE-110",
    "TR-CORE-134",
]
tr_op = [
    "TR-OP-072",
    "TR-OP-122",
]

[inputs]
ledger_state = "input-ledger-state.cbor"

[expected]
zip        = "expected-export.zip"
zip_sha256 = "{hashlib.sha256(zip_bytes).hexdigest()}"

[derivation]
document = "derivation.md"
''',
    )
    write_text(
        OUT_EXPORT_006 / "derivation.md",
        """# Derivation — `export/006-signature-affirmations-inline`

This fixture realizes the Trellis side of the WOS-T4 signature export contract.

It starts from `append/019-wos-signature-affirmation`, packages that canonical
event as the only event in the export, and derives
`062-signature-affirmations.cbor` from the readable WOS-authored
`SignatureAffirmation` payload already carried inside the signed event.
It also derives `066-signed-acts.cbor`, a verifier-facing projection over the
same signed record with nested signer, bound-subject, consent, admission, and
source-reference sections.
The export also includes `067-policy-closure.cbor`, the effective
admission-policy evidence snapshot for this signing profile. That closure
records intent/method registries, posture floors, authority shape, defaults,
deny rules, tombstones, and validity windows, but it explicitly leaves trust
roots, adapter allowlists, and server operational configuration to the verifier
or runtime environment.

Both catalogs are chain-derived rather than independently authored. Each row names
the admitting `canonical_event_hash` and repeats the WOS evidence fields needed
for verifier/reporting surfaces to summarize the signing act without redefining
canonical authority. The policy closure is evidence, not executable verifier
configuration. The human-facing certificate remains a derived artifact; the
signed Trellis export remains the authority.
""",
    )


def build_export_007() -> None:
    OUT_EXPORT_007.mkdir(parents=True, exist_ok=True)

    seed, pubkey = load_seed_and_pubkey(KEY_ISSUER_001)
    kid = derive_kid(SUITE_ID_PHASE_1, pubkey)
    scope = b"wos-case:sba-poc_case_01jqrpd32jf8xtx9qxkkv3rqsc"
    wos_record = signature_admission_failed_record()
    event_bytes, canonical_event_hash = build_event_from_wos_record(
        seed=seed,
        kid=kid,
        scope=scope,
        sequence=0,
        prev_hash=None,
        wos_record=wos_record,
        idempotency_key=sha256(b"export-007-signature-admission-failed"),
        authored_at=ts(1776877861),
    )
    leaf_hash = merkle_leaf_hash(canonical_event_hash)

    members_data: dict[str, bytes] = {}
    events_cbor = dcbor([cbor2.loads(event_bytes)])
    members_data["010-events.cbor"] = events_cbor
    inclusion_proofs = dcbor(
        {
            0: {
                "leaf_index": 0,
                "tree_size": 1,
                "leaf_hash": leaf_hash,
                "audit_path": [],
            }
        }
    )
    members_data["020-inclusion-proofs.cbor"] = inclusion_proofs
    consistency_proofs = dcbor([])
    members_data["025-consistency-proofs.cbor"] = consistency_proofs

    signing_key_registry = build_signing_key_registry(kid, pubkey)
    members_data["030-signing-key-registry.cbor"] = signing_key_registry

    checkpoint_payload = {
        "version": 1,
        "scope": scope,
        "tree_size": 1,
        "tree_head_hash": leaf_hash,
        "timestamp": ts(1776877861),
        "anchor_ref": None,
        "prev_checkpoint_hash": None,
        "extensions": None,
    }
    head_checkpoint_digest = checkpoint_digest(scope, checkpoint_payload)
    members_data["040-checkpoints.cbor"] = dcbor(
        [
            cbor2.loads(
                cose_sign1(seed, kid, dcbor(checkpoint_payload), ARTIFACT_TYPE_CHECKPOINT)
            )
        ]
    )

    domain_registry = build_domain_registry(include_admission_failed=True)
    domain_registry_digest = sha256(domain_registry)
    domain_registry_member = f"050-registries/{domain_registry_digest.hex()}.cbor"
    members_data[domain_registry_member] = domain_registry

    signed_acts = signed_acts_catalog(canonical_event_hash, wos_record)
    members_data[SIGNED_ACTS_MEMBER] = signed_acts
    signed_acts_manifest_bytes = derive_signed_acts_manifest_v1_bytes(
        [(canonical_event_hash, WOS_SIGNATURE_ADMISSION_FAILED_EVENT_TYPE)]
    )
    members_data[SIGNED_ACTS_MANIFEST_MEMBER] = signed_acts_manifest_bytes
    policy_closure_bytes = policy_closure(domain_registry_digest)
    members_data[POLICY_CLOSURE_MEMBER] = policy_closure_bytes

    members_data["090-verify.sh"] = trellis_cli_verify_script()
    members_data["098-README.md"] = (
        "# Trellis Export (Fixture) — export/007-signature-admission-failed-inline\n\n"
        "WOS-T4 signature export fixture with a readable WOS "
        "`SignatureAdmissionFailed` payload. `066-signed-acts.cbor` is the "
        "verifier-facing signing projection and must include the rejected act; "
        "`068-signed-acts-manifest.cbor` carries the substrate-anchored sealed "
        "`(canonical_event_hash, event_type)` list for the admission-failed "
        "event; `067-policy-closure.cbor` carries admission-policy evidence.\n"
    ).encode("utf-8")

    manifest_payload = {
        "format": "trellis-export/1",
        "version": 1,
        "generator": "x-trellis-test/export-generator-007-signature-admission-failed",
        "generated_at": ts(1776877861),
        "scope": scope,
        "tree_size": 1,
        "head_checkpoint_digest": head_checkpoint_digest,
        "registry_bindings": [
            {
                "registry_digest": domain_registry_digest,
                "registry_format": 1,
                "registry_version": "x-trellis-test/registry-signature-v1",
                "bound_at_sequence": 0,
            }
        ],
        "signing_key_registry_digest": sha256(signing_key_registry),
        "events_digest": sha256(events_cbor),
        "checkpoints_digest": sha256(members_data["040-checkpoints.cbor"]),
        "inclusion_proofs_digest": sha256(inclusion_proofs),
        "consistency_proofs_digest": sha256(consistency_proofs),
        "payloads_inlined": False,
        "external_anchors": [],
        "posture_declaration": {
            "provider_readable": True,
            "reader_held": False,
            "delegated_compute": False,
            "external_anchor_required": False,
            "external_anchor_name": None,
            "recovery_without_user": True,
            "metadata_leakage_summary": "WOS-T4 rejected-signature export fixture with readable WOS payload bytes.",
        },
        "head_format_version": 1,
        "omitted_payload_checks": [],
        "extensions": {
            SIGNED_ACTS_EXTENSION_KEY: {
                "catalog_digest": sha256(signed_acts),
                "catalog_ref": SIGNED_ACTS_MEMBER,
                "derivation_rule": SIGNED_ACTS_DERIVATION_RULE,
            },
            SIGNED_ACTS_MANIFEST_EXTENSION_KEY: signed_acts_manifest_extension(
                signed_acts_manifest_bytes
            ),
            POLICY_CLOSURE_EXTENSION_KEY: {
                "closure_digest": sha256(policy_closure_bytes),
                "closure_ref": POLICY_CLOSURE_MEMBER,
                "closure_version": POLICY_CLOSURE_VERSION,
            },
        },
    }
    members_data["000-manifest.cbor"] = cose_sign1(
        seed, kid, dcbor(manifest_payload), ARTIFACT_TYPE_MANIFEST
    )

    for member, member_bytes in members_data.items():
        write_bytes(OUT_EXPORT_007 / member, member_bytes)

    members = sorted(members_data)
    root_dir = f"trellis-export-{scope.decode('utf-8')}-1-{leaf_hash.hex()[:8]}"
    zip_bytes = write_zip(
        OUT_EXPORT_007 / "expected-export.zip",
        root_dir=root_dir,
        members=members,
        data=members_data,
    )
    ledger_state = {
        "version": 1,
        "scope": scope,
        "tree_size": 1,
        "root_dir": root_dir,
        "members": members,
        "notes": "Fixture ledger_state for export/007-signature-admission-failed-inline; pack listed members into deterministic ZIP.",
    }
    write_bytes(OUT_EXPORT_007 / "input-ledger-state.cbor", dcbor(ledger_state))
    write_text(
        OUT_EXPORT_007 / "manifest.toml",
        f'''id          = "export/007-signature-admission-failed-inline"
op          = "export"
status      = "active"
description = """Single-event WOS-T4 export that carries a WOS `SignatureAdmissionFailed` event and binds verifier-facing `066-signed-acts.cbor` rejected-act projection plus `067-policy-closure.cbor` effective policy evidence."""

[coverage]
tr_core = [
    "TR-CORE-006",
    "TR-CORE-062",
    "TR-CORE-064",
    "TR-CORE-065",
    "TR-CORE-067",
    "TR-CORE-110",
    "TR-CORE-134",
]
tr_op = [
    "TR-OP-072",
    "TR-OP-122",
]

[inputs]
ledger_state = "input-ledger-state.cbor"

[expected]
zip        = "expected-export.zip"
zip_sha256 = "{hashlib.sha256(zip_bytes).hexdigest()}"

[derivation]
document = "derivation.md"
''',
    )
    write_text(
        OUT_EXPORT_007 / "derivation.md",
        """# Derivation — `export/007-signature-admission-failed-inline`

This fixture realizes the rejected-signature branch of the WOS/Formspec signing
projection contract.

It packages a single readable WOS `SignatureAdmissionFailed` payload in the
Trellis export. No `062-signature-affirmations.cbor` catalog is present because
there is no successful `SignatureAffirmation` source record. The export still
derives `066-signed-acts.cbor`, and that catalog contains one rejected act whose
source reference points at the signed WOS admission-failure event.

The rejected row is privacy-minimized: signer reference, signed payload digest,
signature id, signing intent, and stable reason code are present; consent,
document placement, provider ceremony, primitive verification, and raw failed
content are null.
""",
    )


def build_export_008() -> None:
    OUT_EXPORT_008.mkdir(parents=True, exist_ok=True)

    seed, pubkey = load_seed_and_pubkey(KEY_ISSUER_001)
    kid = derive_kid(SUITE_ID_PHASE_1, pubkey)
    scope = b"wos-case:sba-poc_case_signed_acts_fallback"
    wos_record = cbor2.loads((APPEND_019 / "input-wos-record.dcbor").read_bytes())
    del wos_record["data"]["signingActId"]
    event_bytes, canonical_event_hash = build_event_from_wos_record(
        seed=seed,
        kid=kid,
        scope=scope,
        sequence=0,
        prev_hash=None,
        wos_record=wos_record,
        idempotency_key=sha256(b"export-008-signed-acts-fallback-act-id"),
        authored_at=ts(1776877862),
    )
    leaf_hash = merkle_leaf_hash(canonical_event_hash)

    members_data: dict[str, bytes] = {}
    events_cbor = dcbor([cbor2.loads(event_bytes)])
    members_data["010-events.cbor"] = events_cbor
    inclusion_proofs = dcbor(
        {
            0: {
                "leaf_index": 0,
                "tree_size": 1,
                "leaf_hash": leaf_hash,
                "audit_path": [],
            }
        }
    )
    members_data["020-inclusion-proofs.cbor"] = inclusion_proofs
    consistency_proofs = dcbor([])
    members_data["025-consistency-proofs.cbor"] = consistency_proofs

    signing_key_registry = build_signing_key_registry(kid, pubkey)
    members_data["030-signing-key-registry.cbor"] = signing_key_registry

    checkpoint_payload = {
        "version": 1,
        "scope": scope,
        "tree_size": 1,
        "tree_head_hash": leaf_hash,
        "timestamp": ts(1776877862),
        "anchor_ref": None,
        "prev_checkpoint_hash": None,
        "extensions": None,
    }
    head_checkpoint_digest = checkpoint_digest(scope, checkpoint_payload)
    members_data["040-checkpoints.cbor"] = dcbor(
        [
            cbor2.loads(
                cose_sign1(seed, kid, dcbor(checkpoint_payload), ARTIFACT_TYPE_CHECKPOINT)
            )
        ]
    )

    domain_registry = build_domain_registry()
    domain_registry_digest = sha256(domain_registry)
    domain_registry_member = f"050-registries/{domain_registry_digest.hex()}.cbor"
    members_data[domain_registry_member] = domain_registry

    signed_acts = signed_acts_catalog(
        canonical_event_hash,
        wos_record,
        derivation_rule=SIGNED_ACTS_DERIVATION_RULE_V2,
    )
    members_data[SIGNED_ACTS_MEMBER] = signed_acts
    signed_acts_manifest_bytes = derive_signed_acts_manifest_v1_bytes(
        [(canonical_event_hash, WOS_SIGNATURE_AFFIRMATION_EVENT_TYPE)]
    )
    members_data[SIGNED_ACTS_MANIFEST_MEMBER] = signed_acts_manifest_bytes
    policy_closure_bytes = policy_closure(domain_registry_digest)
    members_data[POLICY_CLOSURE_MEMBER] = policy_closure_bytes

    members_data["090-verify.sh"] = trellis_cli_verify_script()
    members_data["098-README.md"] = (
        "# Trellis Export (Fixture) — export/008-signed-acts-fallback-act-id\n\n"
        "WOS-T4 signature export fixture whose readable `SignatureAffirmation` "
        "payload has no shared signing act id. `066-signed-acts.cbor` uses "
        "`signed-act-projection-wos-formspec-v2` and derives `act_id` from "
        "sorted source references under `signed-act-projection-act-id-v1`. "
        "`068-signed-acts-manifest.cbor` is the substrate-anchored sealed list "
        "of `(canonical_event_hash, event_type)` pairs and remains identical "
        "across catalog-rule variants.\n"
    ).encode("utf-8")

    manifest_payload = {
        "format": "trellis-export/1",
        "version": 1,
        "generator": "x-trellis-test/export-generator-008-signed-acts-fallback",
        "generated_at": ts(1776877862),
        "scope": scope,
        "tree_size": 1,
        "head_checkpoint_digest": head_checkpoint_digest,
        "registry_bindings": [
            {
                "registry_digest": domain_registry_digest,
                "registry_format": 1,
                "registry_version": "x-trellis-test/registry-signature-v1",
                "bound_at_sequence": 0,
            }
        ],
        "signing_key_registry_digest": sha256(signing_key_registry),
        "events_digest": sha256(events_cbor),
        "checkpoints_digest": sha256(members_data["040-checkpoints.cbor"]),
        "inclusion_proofs_digest": sha256(inclusion_proofs),
        "consistency_proofs_digest": sha256(consistency_proofs),
        "payloads_inlined": False,
        "external_anchors": [],
        "posture_declaration": {
            "provider_readable": True,
            "reader_held": False,
            "delegated_compute": False,
            "external_anchor_required": False,
            "external_anchor_name": None,
            "recovery_without_user": True,
            "metadata_leakage_summary": "WOS-T4 fallback SignedAct id fixture with readable WOS payload bytes.",
        },
        "head_format_version": 1,
        "omitted_payload_checks": [],
        "extensions": {
            SIGNED_ACTS_EXTENSION_KEY: {
                "catalog_digest": sha256(signed_acts),
                "catalog_ref": SIGNED_ACTS_MEMBER,
                "derivation_rule": SIGNED_ACTS_DERIVATION_RULE_V2,
            },
            SIGNED_ACTS_MANIFEST_EXTENSION_KEY: signed_acts_manifest_extension(
                signed_acts_manifest_bytes
            ),
            POLICY_CLOSURE_EXTENSION_KEY: {
                "closure_digest": sha256(policy_closure_bytes),
                "closure_ref": POLICY_CLOSURE_MEMBER,
                "closure_version": POLICY_CLOSURE_VERSION,
            },
        },
    }
    members_data["000-manifest.cbor"] = cose_sign1(
        seed, kid, dcbor(manifest_payload), ARTIFACT_TYPE_MANIFEST
    )

    for member, member_bytes in members_data.items():
        write_bytes(OUT_EXPORT_008 / member, member_bytes)

    members = sorted(members_data)
    root_dir = f"trellis-export-{scope.decode('utf-8')}-1-{leaf_hash.hex()[:8]}"
    zip_bytes = write_zip(
        OUT_EXPORT_008 / "expected-export.zip",
        root_dir=root_dir,
        members=members,
        data=members_data,
    )
    ledger_state = {
        "version": 1,
        "scope": scope,
        "tree_size": 1,
        "root_dir": root_dir,
        "members": members,
        "notes": "Fixture ledger_state for export/008-signed-acts-fallback-act-id; pack listed members into deterministic ZIP.",
    }
    write_bytes(OUT_EXPORT_008 / "input-ledger-state.cbor", dcbor(ledger_state))
    write_text(
        OUT_EXPORT_008 / "manifest.toml",
        f'''id          = "export/008-signed-acts-fallback-act-id"
op          = "export"
status      = "active"
description = """Single-event WOS-T4 export that carries a WOS `SignatureAffirmation` without `data.signingActId` and binds verifier-facing `066-signed-acts.cbor` using the v2 fallback act-id rule."""

[coverage]
tr_core = [
    "TR-CORE-006",
    "TR-CORE-062",
    "TR-CORE-064",
    "TR-CORE-065",
    "TR-CORE-067",
    "TR-CORE-110",
    "TR-CORE-134",
]
tr_op = [
    "TR-OP-072",
    "TR-OP-122",
]

[inputs]
ledger_state = "input-ledger-state.cbor"

[expected]
zip        = "expected-export.zip"
zip_sha256 = "{hashlib.sha256(zip_bytes).hexdigest()}"

[derivation]
document = "derivation.md"
''',
    )
    write_text(
        OUT_EXPORT_008 / "derivation.md",
        """# Derivation — `export/008-signed-acts-fallback-act-id`

This fixture realizes the additive SignedAct projection rule for source rows
that do not carry a shared signing act id.

It packages a single readable WOS `SignatureAffirmation` payload copied from
`append/019-wos-signature-affirmation` with `data.signingActId` removed. The
manifest binds `066-signed-acts.cbor` under
`signed-act-projection-wos-formspec-v2`. The projected row derives `act_id`
as `signed-act-projection-act-id-v1:<sha256>` over the canonical CBOR bytes of
the sorted `source_refs` array.

The signed source event remains authoritative. The fallback id is only
correlation data for deterministic projection and verifier reporting.
""",
    )


def write_verify_vector() -> None:
    root_dir, members, data, manifest_payload = export_members_from_dir(OUT_EXPORT_006)
    catalog = cbor2.loads(data["062-signature-affirmations.cbor"])
    tampered_catalog = copy.deepcopy(catalog)
    tampered_catalog[0]["signing_act_id"] = "signing-act-tampered"
    catalog_bytes = dcbor(tampered_catalog)
    data_verify = dict(data)
    data_verify["062-signature-affirmations.cbor"] = catalog_bytes

    seed, pubkey = load_seed_and_pubkey(KEY_ISSUER_001)
    kid = derive_kid(SUITE_ID_PHASE_1, pubkey)
    manifest_payload_verify = copy.deepcopy(manifest_payload)
    manifest_payload_verify["extensions"][EXTENSION_KEY]["signature_catalog_digest"] = sha256(
        catalog_bytes
    )
    data_verify["000-manifest.cbor"] = cose_sign1(seed, kid, dcbor(manifest_payload_verify), ARTIFACT_TYPE_MANIFEST)

    OUT_VERIFY_014.mkdir(parents=True, exist_ok=True)
    write_zip(
        OUT_VERIFY_014 / "input-export.zip",
        root_dir=root_dir,
        members=members,
        data=data_verify,
    )
    write_text(
        OUT_VERIFY_014 / "manifest.toml",
        '''id          = "verify/014-export-006-signature-row-mismatch"
op          = "verify"
status      = "active"
description = """Negative verify vector for the WOS-T4 signature export catalog. Starts from `export/006-signature-affirmations-inline`, changes the catalog row signing act id, and re-signs the export manifest so structure stays valid while the catalog no longer matches the chain-authored WOS record."""

[coverage]
tr_core = ["TR-CORE-067"]
tr_op = ["TR-OP-122"]

[inputs]
export_zip = "input-export.zip"

[expected.report]
structure_verified   = true
integrity_verified   = false
readability_verified = true
first_failure_kind   = "signature_catalog_mismatch"

[derivation]
document = "derivation.md"
''',
    )
    write_text(
        OUT_VERIFY_014 / "derivation.md",
        """# Derivation — `verify/014-export-006-signature-row-mismatch`

This fixture starts from `export/006-signature-affirmations-inline`, mutates the
`signing_act_id` in `062-signature-affirmations.cbor`, recomputes the catalog
digest, and re-signs `000-manifest.cbor`. The ZIP remains structurally valid
and all manifest digests match the archive contents, but the signature catalog
no longer matches the chain-authored WOS `SignatureAffirmation` payload.
""",
    )


def write_signed_acts_verify_vector() -> None:
    root_dir, members, data, manifest_payload = export_members_from_dir(OUT_EXPORT_006)
    catalog = cbor2.loads(data[SIGNED_ACTS_MEMBER])
    tampered_catalog = copy.deepcopy(catalog)
    tampered_catalog["acts"][0]["signer"]["id"] = "delegate"
    catalog_bytes = dcbor(tampered_catalog)
    data_verify = dict(data)
    data_verify[SIGNED_ACTS_MEMBER] = catalog_bytes

    seed, pubkey = load_seed_and_pubkey(KEY_ISSUER_001)
    kid = derive_kid(SUITE_ID_PHASE_1, pubkey)
    manifest_payload_verify = copy.deepcopy(manifest_payload)
    manifest_payload_verify["extensions"][SIGNED_ACTS_EXTENSION_KEY][
        "catalog_digest"
    ] = sha256(catalog_bytes)
    data_verify["000-manifest.cbor"] = cose_sign1(
        seed, kid, dcbor(manifest_payload_verify), ARTIFACT_TYPE_MANIFEST
    )

    OUT_VERIFY_019.mkdir(parents=True, exist_ok=True)
    write_zip(
        OUT_VERIFY_019 / "input-export.zip",
        root_dir=root_dir,
        members=members,
        data=data_verify,
    )
    write_text(
        OUT_VERIFY_019 / "manifest.toml",
        '''id          = "verify/019-export-006-signed-acts-render-drift"
op          = "verify"
status      = "active"
description = """Advisory verify vector for the verifier-facing SignedAct projection. Starts from `export/006-signature-affirmations-inline`, mutates `066-signed-acts.cbor` (a render-time projection), recomputes its `trellis.export.signed-acts.v1` digest, and re-signs the export manifest. The substrate-anchored `068-signed-acts-manifest.cbor` is untouched and still byte-matches its derivation, so the verifier emits advisory `signed_acts_render_drift` and the relying-party verdict stays valid."""

[coverage]
tr_core = ["TR-CORE-067"]
tr_op = ["TR-OP-122"]

[inputs]
export_zip = "input-export.zip"

[expected.report]
structure_verified   = true
integrity_verified   = true
readability_verified = true

[derivation]
document = "derivation.md"
''',
    )
    write_text(
        OUT_VERIFY_019 / "derivation.md",
        """# Derivation — `verify/019-export-006-signed-acts-render-drift`

This fixture starts from `export/006-signature-affirmations-inline`, mutates
`066-signed-acts.cbor`, recomputes the `catalog_digest` under
`trellis.export.signed-acts.v1`, and re-signs `000-manifest.cbor`. The ZIP
remains structurally valid, every manifest digest matches archive contents,
and the substrate-anchored `068-signed-acts-manifest.cbor` member is untouched
and still equals the deterministic `signed-acts-manifest-v1` derivation over
the sealed events.

The 066 catalog is a downstream render-time projection whose bytes can
legitimately drift across renderers; its byte mismatch with the canonical
derivation is reported as advisory `signed_acts_render_drift`. The 068 manifest
is the substrate-anchored proof of which signed-act source events landed, so
render drift alone never blocks the relying-party verdict.
""",
    )


def write_signed_acts_unsupported_rule_verify_vector() -> None:
    root_dir, members, data, manifest_payload = export_members_from_dir(OUT_EXPORT_006)
    seed, pubkey = load_seed_and_pubkey(KEY_ISSUER_001)
    kid = derive_kid(SUITE_ID_PHASE_1, pubkey)
    manifest_payload_verify = copy.deepcopy(manifest_payload)
    manifest_payload_verify["extensions"][SIGNED_ACTS_EXTENSION_KEY][
        "derivation_rule"
    ] = UNSUPPORTED_SIGNED_ACTS_DERIVATION_RULE
    data_verify = dict(data)
    data_verify["000-manifest.cbor"] = cose_sign1(
        seed, kid, dcbor(manifest_payload_verify), ARTIFACT_TYPE_MANIFEST
    )

    OUT_VERIFY_020.mkdir(parents=True, exist_ok=True)
    write_zip(
        OUT_VERIFY_020 / "input-export.zip",
        root_dir=root_dir,
        members=members,
        data=data_verify,
    )
    write_text(
        OUT_VERIFY_020 / "manifest.toml",
        '''id          = "verify/020-export-006-signed-acts-unsupported-rule"
op          = "verify"
status      = "active"
description = """Negative verify vector for SignedAct derivation-rule dispatch. Starts from `export/006-signature-affirmations-inline`, changes the manifest extension derivation rule to an unsupported value, and re-signs the export manifest so archive structure and member digests stay valid while the WOS validator rejects the projection rule."""

[coverage]
tr_core = ["TR-CORE-067"]
tr_op = ["TR-OP-122"]

[inputs]
export_zip = "input-export.zip"

[expected.report]
structure_verified   = true
integrity_verified   = false
readability_verified = true
first_failure_kind   = "signed_acts_catalog_invalid"

[derivation]
document = "derivation.md"
''',
    )
    write_text(
        OUT_VERIFY_020 / "derivation.md",
        """# Derivation — `verify/020-export-006-signed-acts-unsupported-rule`

This fixture starts from `export/006-signature-affirmations-inline`, changes the
`trellis.export.signed-acts.v1.derivation_rule` manifest-extension value to
`signed-act-projection-wos-formspec-unsupported`, and re-signs `000-manifest.cbor`.
The ZIP remains structurally valid and all member digests match archive
contents, but the WOS validator has no registered derivation implementation
for that rule ID and must reject it as `signed_acts_catalog_invalid` without
falling back to the v1 derivation.
""",
    )


def write_tamper_vector() -> None:
    root_dir, members, data, _manifest_payload = export_members_from_dir(OUT_EXPORT_006)
    catalog = cbor2.loads(data["062-signature-affirmations.cbor"])
    tampered_catalog = copy.deepcopy(catalog)
    tampered_catalog[0]["document_hash_algorithm"] = "sha-512"
    data_tampered = dict(data)
    data_tampered["062-signature-affirmations.cbor"] = dcbor(tampered_catalog)

    OUT_TAMPER_014.mkdir(parents=True, exist_ok=True)
    write_zip(
        OUT_TAMPER_014 / "input-export.zip",
        root_dir=root_dir,
        members=members,
        data=data_tampered,
    )
    write_text(
        OUT_TAMPER_014 / "manifest.toml",
        '''id          = "tamper/014-signature-catalog-digest-mismatch"
op          = "tamper"
status      = "active"
description = """WOS-T4 export tamper. Mutates `062-signature-affirmations.cbor` after manifest signing so the required archive spine remains intact but the `trellis.export.signature-affirmations.v1.signature_catalog_digest` check fails."""

[coverage]
tr_core = ["TR-CORE-061"]

[inputs]
export_zip = "input-export.zip"

[expected.report]
structure_verified   = true
integrity_verified   = false
readability_verified = true
tamper_kind          = "signature_catalog_digest_mismatch"

[derivation]
document = "derivation.md"
''',
    )
    write_text(
        OUT_TAMPER_014 / "derivation.md",
        """# Derivation — `tamper/014-signature-catalog-digest-mismatch`

This fixture starts from `export/006-signature-affirmations-inline`, mutates
`062-signature-affirmations.cbor`, and leaves the signed `000-manifest.cbor`
unchanged. The verifier must localize the failure to the signature catalog
digest bound by `trellis.export.signature-affirmations.v1.signature_catalog_digest`.
""",
    )


def write_signed_acts_tamper_vector() -> None:
    root_dir, members, data, _manifest_payload = export_members_from_dir(OUT_EXPORT_006)
    catalog = cbor2.loads(data[SIGNED_ACTS_MEMBER])
    tampered_catalog = copy.deepcopy(catalog)
    tampered_catalog["acts"][0]["admission"]["outcome"] = "rejected"
    data_tampered = dict(data)
    data_tampered[SIGNED_ACTS_MEMBER] = dcbor(tampered_catalog)

    OUT_TAMPER_055.mkdir(parents=True, exist_ok=True)
    write_zip(
        OUT_TAMPER_055 / "input-export.zip",
        root_dir=root_dir,
        members=members,
        data=data_tampered,
    )
    write_text(
        OUT_TAMPER_055 / "manifest.toml",
        '''id          = "tamper/055-signed-acts-catalog-digest-mismatch"
op          = "tamper"
status      = "active"
description = """SignedAct projection export tamper. Mutates `066-signed-acts.cbor` after manifest signing so the required archive spine remains intact but the `trellis.export.signed-acts.v1.catalog_digest` check fails."""

[coverage]
tr_core = ["TR-CORE-061"]
tr_op = ["TR-OP-122"]

[inputs]
export_zip = "input-export.zip"

[expected.report]
structure_verified   = true
integrity_verified   = false
readability_verified = true
tamper_kind          = "signed_acts_catalog_digest_mismatch"

[derivation]
document = "derivation.md"
''',
    )
    write_text(
        OUT_TAMPER_055 / "derivation.md",
        """# Derivation — `tamper/055-signed-acts-catalog-digest-mismatch`

This fixture starts from `export/006-signature-affirmations-inline`, mutates
`066-signed-acts.cbor`, and leaves the signed `000-manifest.cbor` unchanged.
The verifier must localize the failure to the SignedAct projection catalog
digest bound by `trellis.export.signed-acts.v1.catalog_digest`.
""",
    )


def write_policy_closure_tamper_vector() -> None:
    root_dir, members, data, _manifest_payload = export_members_from_dir(OUT_EXPORT_006)
    closure = cbor2.loads(data[POLICY_CLOSURE_MEMBER])
    tampered_closure = copy.deepcopy(closure)
    tampered_closure["artifacts"][0]["version"] = "2026-05-17"
    data_tampered = dict(data)
    data_tampered[POLICY_CLOSURE_MEMBER] = dcbor(tampered_closure)

    OUT_TAMPER_056.mkdir(parents=True, exist_ok=True)
    write_zip(
        OUT_TAMPER_056 / "input-export.zip",
        root_dir=root_dir,
        members=members,
        data=data_tampered,
    )
    write_text(
        OUT_TAMPER_056 / "manifest.toml",
        '''id          = "tamper/056-policy-closure-digest-mismatch"
op          = "tamper"
status      = "active"
description = """Policy-closure export tamper. Mutates `067-policy-closure.cbor` after manifest signing so the required archive spine remains intact but the `trellis.export.policy-closure.v1.closure_digest` check fails."""

[coverage]
tr_core = ["TR-CORE-061"]
tr_op = ["TR-OP-122"]

[inputs]
export_zip = "input-export.zip"

[expected.report]
structure_verified   = true
integrity_verified   = false
readability_verified = true
tamper_kind          = "policy_closure_digest_mismatch"

[derivation]
document = "derivation.md"
''',
    )
    write_text(
        OUT_TAMPER_056 / "derivation.md",
        """# Derivation — `tamper/056-policy-closure-digest-mismatch`

This fixture starts from `export/006-signature-affirmations-inline`, mutates
`067-policy-closure.cbor`, and leaves the signed `000-manifest.cbor` unchanged.
The verifier must localize the failure to the effective policy-closure evidence
digest bound by `trellis.export.policy-closure.v1.closure_digest`.
""",
    )


def build_export_009() -> None:
    """Positive export fixture exercising the 068 signed-acts-manifest extension on its own.

    The export carries the canonical `wos.kernel.signature_affirmation` event from
    `append/019-wos-signature-affirmation` but binds only
    `trellis.export.signed-acts.manifest.v1` (substrate-anchored sealed
    `(canonical_event_hash, event_type)` list). The render-time
    `066-signed-acts.cbor` and its `trellis.export.signed-acts.v1` extension are
    absent — exercising the "manifest is the load-bearing proof; the 066
    projection is optional reporting" invariant.
    """
    OUT_EXPORT_009.mkdir(parents=True, exist_ok=True)

    seed, pubkey = load_seed_and_pubkey(KEY_ISSUER_001)
    kid = derive_kid(SUITE_ID_PHASE_1, pubkey)
    scope = b"wos-case:sba-poc_case_signed_acts_manifest_only"
    wos_record = cbor2.loads((APPEND_019 / "input-wos-record.dcbor").read_bytes())
    event_bytes, canonical_event_hash = build_event_from_wos_record(
        seed=seed,
        kid=kid,
        scope=scope,
        sequence=0,
        prev_hash=None,
        wos_record=wos_record,
        idempotency_key=sha256(b"export-009-signed-acts-manifest-only"),
        authored_at=ts(1776877863),
    )
    leaf_hash = merkle_leaf_hash(canonical_event_hash)

    members_data: dict[str, bytes] = {}
    events_cbor = dcbor([cbor2.loads(event_bytes)])
    members_data["010-events.cbor"] = events_cbor
    inclusion_proofs = dcbor(
        {
            0: {
                "leaf_index": 0,
                "tree_size": 1,
                "leaf_hash": leaf_hash,
                "audit_path": [],
            }
        }
    )
    members_data["020-inclusion-proofs.cbor"] = inclusion_proofs
    consistency_proofs = dcbor([])
    members_data["025-consistency-proofs.cbor"] = consistency_proofs

    signing_key_registry = build_signing_key_registry(kid, pubkey)
    members_data["030-signing-key-registry.cbor"] = signing_key_registry

    checkpoint_payload = {
        "version": 1,
        "scope": scope,
        "tree_size": 1,
        "tree_head_hash": leaf_hash,
        "timestamp": ts(1776877863),
        "anchor_ref": None,
        "prev_checkpoint_hash": None,
        "extensions": None,
    }
    head_checkpoint_digest = checkpoint_digest(scope, checkpoint_payload)
    members_data["040-checkpoints.cbor"] = dcbor(
        [
            cbor2.loads(
                cose_sign1(seed, kid, dcbor(checkpoint_payload), ARTIFACT_TYPE_CHECKPOINT)
            )
        ]
    )

    domain_registry = build_domain_registry()
    domain_registry_digest = sha256(domain_registry)
    domain_registry_member = f"050-registries/{domain_registry_digest.hex()}.cbor"
    members_data[domain_registry_member] = domain_registry

    signed_acts_manifest_bytes = derive_signed_acts_manifest_v1_bytes(
        [(canonical_event_hash, WOS_SIGNATURE_AFFIRMATION_EVENT_TYPE)]
    )
    members_data[SIGNED_ACTS_MANIFEST_MEMBER] = signed_acts_manifest_bytes

    members_data["090-verify.sh"] = trellis_cli_verify_script()
    members_data["098-README.md"] = (
        "# Trellis Export (Fixture) — export/009-signed-acts-manifest-only\n\n"
        "WOS-T4 signature export fixture that binds only the substrate-anchored "
        "`068-signed-acts-manifest.cbor` member through "
        "`trellis.export.signed-acts.manifest.v1`. The render-time "
        "`066-signed-acts.cbor` catalog and its `trellis.export.signed-acts.v1` "
        "extension are intentionally absent: the 068 manifest is the "
        "load-bearing proof of which signed-act source events landed, while the "
        "066 projection is an optional reporting surface that may legitimately "
        "be omitted.\n"
    ).encode("utf-8")

    manifest_payload = {
        "format": "trellis-export/1",
        "version": 1,
        "generator": "x-trellis-test/export-generator-009-signed-acts-manifest-only",
        "generated_at": ts(1776877863),
        "scope": scope,
        "tree_size": 1,
        "head_checkpoint_digest": head_checkpoint_digest,
        "registry_bindings": [
            {
                "registry_digest": domain_registry_digest,
                "registry_format": 1,
                "registry_version": "x-trellis-test/registry-signature-v1",
                "bound_at_sequence": 0,
            }
        ],
        "signing_key_registry_digest": sha256(signing_key_registry),
        "events_digest": sha256(events_cbor),
        "checkpoints_digest": sha256(members_data["040-checkpoints.cbor"]),
        "inclusion_proofs_digest": sha256(inclusion_proofs),
        "consistency_proofs_digest": sha256(consistency_proofs),
        "payloads_inlined": False,
        "external_anchors": [],
        "posture_declaration": {
            "provider_readable": True,
            "reader_held": False,
            "delegated_compute": False,
            "external_anchor_required": False,
            "external_anchor_name": None,
            "recovery_without_user": True,
            "metadata_leakage_summary": "WOS-T4 signed-acts-manifest-only export fixture with readable WOS payload bytes.",
        },
        "head_format_version": 1,
        "omitted_payload_checks": [],
        "extensions": {
            SIGNED_ACTS_MANIFEST_EXTENSION_KEY: signed_acts_manifest_extension(
                signed_acts_manifest_bytes
            ),
        },
    }
    members_data["000-manifest.cbor"] = cose_sign1(
        seed, kid, dcbor(manifest_payload), ARTIFACT_TYPE_MANIFEST
    )

    for member, member_bytes in members_data.items():
        write_bytes(OUT_EXPORT_009 / member, member_bytes)

    members = sorted(members_data)
    root_dir = f"trellis-export-{scope.decode('utf-8')}-1-{leaf_hash.hex()[:8]}"
    zip_bytes = write_zip(
        OUT_EXPORT_009 / "expected-export.zip",
        root_dir=root_dir,
        members=members,
        data=members_data,
    )
    ledger_state = {
        "version": 1,
        "scope": scope,
        "tree_size": 1,
        "root_dir": root_dir,
        "members": members,
        "notes": "Fixture ledger_state for export/009-signed-acts-manifest-only; pack listed members into deterministic ZIP.",
    }
    write_bytes(OUT_EXPORT_009 / "input-ledger-state.cbor", dcbor(ledger_state))
    write_text(
        OUT_EXPORT_009 / "manifest.toml",
        f'''id          = "export/009-signed-acts-manifest-only"
op          = "export"
status      = "active"
description = """Single-event WOS-T4 export that carries a WOS `SignatureAffirmation` event and binds only the substrate-anchored `068-signed-acts-manifest.cbor` member through `trellis.export.signed-acts.manifest.v1`. The render-time `066-signed-acts.cbor` projection and its `trellis.export.signed-acts.v1` extension are absent — exercising the invariant that the 068 manifest is the load-bearing signed-acts proof and the 066 projection is optional reporting."""

[coverage]
tr_core = [
    "TR-CORE-006",
    "TR-CORE-062",
    "TR-CORE-064",
    "TR-CORE-065",
    "TR-CORE-067",
    "TR-CORE-110",
    "TR-CORE-134",
]
tr_op = [
    "TR-OP-072",
    "TR-OP-122",
]

[inputs]
ledger_state = "input-ledger-state.cbor"

[expected]
zip        = "expected-export.zip"
zip_sha256 = "{hashlib.sha256(zip_bytes).hexdigest()}"

[derivation]
document = "derivation.md"
''',
    )
    write_text(
        OUT_EXPORT_009 / "derivation.md",
        """# Derivation — `export/009-signed-acts-manifest-only`

This fixture realizes the substrate-only branch of the WOS/Formspec signed-acts
contract: the export carries the canonical WOS `SignatureAffirmation` event but
binds only the `068-signed-acts-manifest.cbor` member through
`trellis.export.signed-acts.manifest.v1`. The render-time
`066-signed-acts.cbor` projection and its `trellis.export.signed-acts.v1`
extension are intentionally absent.

The 068 manifest member is a canonical-CBOR array of
`[bstr(canonical_event_hash), tstr(event_type)]` pairs, sorted ascending by
`(hash, event_type)`, derived deterministically from the sealed
`wos.kernel.signature_affirmation` and `wos.kernel.signature_admission_failed`
events in scope (Task A1 / `signed-acts-manifest-v1`). The export-manifest
extension binds `manifest_digest = SHA-256(068 member bytes)` so any drift in
the manifest member is detectable without re-deriving from sealed events.

This shape is permitted: the 066 projection is an optional reporting surface
and exporters MAY omit it. The signed source event chain plus the 068 manifest
remain authoritative.
""",
    )


def write_signed_acts_manifest_tamper_verify_vector() -> None:
    """Tamper the 068 manifest member after manifest signing.

    The 068 member byte is mutated so the SHA-256 digest no longer matches the
    `trellis.export.signed-acts.manifest.v1.manifest_digest` extension binding.
    The verifier MUST emit blocking `signed_acts_manifest_extension_digest_mismatch`
    (Task A1 §6.7 — substrate-shape failure).
    """
    root_dir, members, data, _manifest_payload = export_members_from_dir(OUT_EXPORT_006)
    original = data[SIGNED_ACTS_MANIFEST_MEMBER]
    if len(original) == 0:
        raise ValueError("068 manifest member is empty; cannot tamper")
    # Flip a single byte deep enough in the sealed-tuple list to never coincide
    # with structural CBOR framing — guarantees the SHA-256 changes while the
    # CBOR remains structurally parseable.
    mutated = bytearray(original)
    mutated[-1] ^= 0x01
    tampered_bytes = bytes(mutated)
    data_tampered = dict(data)
    data_tampered[SIGNED_ACTS_MANIFEST_MEMBER] = tampered_bytes

    OUT_VERIFY_021.mkdir(parents=True, exist_ok=True)
    write_zip(
        OUT_VERIFY_021 / "input-export.zip",
        root_dir=root_dir,
        members=members,
        data=data_tampered,
    )
    write_text(
        OUT_VERIFY_021 / "manifest.toml",
        '''id          = "verify/021-signed-acts-manifest-tamper"
op          = "verify"
status      = "active"
description = """Negative verify vector for the substrate-anchored 068 signed-acts manifest. Starts from `export/006-signature-affirmations-inline` and mutates one byte of `068-signed-acts-manifest.cbor` after manifest signing so the SHA-256 digest no longer matches the `trellis.export.signed-acts.manifest.v1.manifest_digest` binding while the signed export manifest stays unchanged."""

[coverage]
tr_core = ["TR-CORE-067"]
tr_op = ["TR-OP-122"]

[inputs]
export_zip = "input-export.zip"

[expected.report]
structure_verified   = true
integrity_verified   = false
readability_verified = true
first_failure_kind   = "signed_acts_manifest_extension_digest_mismatch"

[derivation]
document = "derivation.md"
''',
    )
    write_text(
        OUT_VERIFY_021 / "derivation.md",
        """# Derivation — `verify/021-signed-acts-manifest-tamper`

This fixture starts from `export/006-signature-affirmations-inline`, mutates
the final byte of `068-signed-acts-manifest.cbor`, and leaves the signed
`000-manifest.cbor` unchanged. The substrate-anchored signed-acts manifest is
the load-bearing proof of which signed-act source events landed, bound to the
manifest extension `trellis.export.signed-acts.manifest.v1.manifest_digest`.

The WOS validator must localize the failure to
`signed_acts_manifest_extension_digest_mismatch` (substrate-shape failure;
blocking) and the relying-party verdict MUST become invalid. Render drift on
the 066 projection alone never blocks; substrate drift on the 068 manifest
always does.
""",
    )


def write_066_render_drift_only_verify_vector() -> None:
    """066 mutated + manifest re-signed; 068 untouched; verifier issues advisory only.

    Distinct fixture surface from verify/019 (which mutates a signer field):
    here a `bound` field is mutated to demonstrate the same invariant — render
    drift on any 066 projection field is advisory because the load-bearing
    substrate-anchored 068 manifest still byte-matches its derivation. This
    regression-tests "render drift alone never blocks verdict."
    """
    root_dir, members, data, manifest_payload = export_members_from_dir(OUT_EXPORT_006)
    catalog = cbor2.loads(data[SIGNED_ACTS_MEMBER])
    tampered_catalog = copy.deepcopy(catalog)
    tampered_catalog["acts"][0]["bound"]["document_id"] = "doc-drifted"
    catalog_bytes = dcbor(tampered_catalog)
    data_verify = dict(data)
    data_verify[SIGNED_ACTS_MEMBER] = catalog_bytes

    seed, pubkey = load_seed_and_pubkey(KEY_ISSUER_001)
    kid = derive_kid(SUITE_ID_PHASE_1, pubkey)
    manifest_payload_verify = copy.deepcopy(manifest_payload)
    manifest_payload_verify["extensions"][SIGNED_ACTS_EXTENSION_KEY][
        "catalog_digest"
    ] = sha256(catalog_bytes)
    data_verify["000-manifest.cbor"] = cose_sign1(
        seed, kid, dcbor(manifest_payload_verify), ARTIFACT_TYPE_MANIFEST
    )

    OUT_VERIFY_022.mkdir(parents=True, exist_ok=True)
    write_zip(
        OUT_VERIFY_022 / "input-export.zip",
        root_dir=root_dir,
        members=members,
        data=data_verify,
    )
    write_text(
        OUT_VERIFY_022 / "manifest.toml",
        '''id          = "verify/022-066-render-drift-tampered-only"
op          = "verify"
status      = "active"
description = """Advisory verify vector pinning the "render drift alone never blocks verdict" invariant. Starts from `export/006-signature-affirmations-inline`, mutates a `bound` field in `066-signed-acts.cbor`, recomputes its `trellis.export.signed-acts.v1` digest, and re-signs the export manifest. The substrate-anchored `068-signed-acts-manifest.cbor` is untouched and still equals its deterministic derivation, so the verifier emits advisory `signed_acts_render_drift` and the relying-party verdict stays valid."""

[coverage]
tr_core = ["TR-CORE-067"]
tr_op = ["TR-OP-122"]

[inputs]
export_zip = "input-export.zip"

[expected.report]
structure_verified   = true
integrity_verified   = true
readability_verified = true

[derivation]
document = "derivation.md"
''',
    )
    write_text(
        OUT_VERIFY_022 / "derivation.md",
        """# Derivation — `verify/022-066-render-drift-tampered-only`

This fixture starts from `export/006-signature-affirmations-inline`, mutates
`acts[0].bound.document_id` in `066-signed-acts.cbor`, recomputes the
`catalog_digest` under `trellis.export.signed-acts.v1`, and re-signs
`000-manifest.cbor`. The ZIP remains structurally valid, every manifest digest
matches archive contents, and `068-signed-acts-manifest.cbor` is left
untouched — so it still byte-equals the deterministic
`signed-acts-manifest-v1` derivation over the sealed events.

The verifier reports advisory `signed_acts_render_drift` (066 projection bytes
disagree with the canonical derivation) but the relying-party verdict stays
valid because the load-bearing substrate-anchored 068 manifest is intact.
Distinct from `verify/019-export-006-signed-acts-render-drift`, which mutates a
signer field; this fixture mutates a bound-subject field. Together they pin the
"render drift on any 066 surface is advisory only" invariant.
""",
    )


def main() -> None:
    build_export_006()
    build_export_007()
    build_export_008()
    build_export_009()
    write_verify_vector()
    write_signed_acts_verify_vector()
    write_signed_acts_unsupported_rule_verify_vector()
    write_signed_acts_manifest_tamper_verify_vector()
    write_066_render_drift_only_verify_vector()
    write_tamper_vector()
    write_signed_acts_tamper_vector()
    write_policy_closure_tamper_vector()


if __name__ == "__main__":
    main()
