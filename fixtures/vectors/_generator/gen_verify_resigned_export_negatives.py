"""Generate negative verify vectors by re-signing the last event of a service-assembled export.

Sources (committed, read-only):
- export/015-certificate-v2-distinct-responses — ADR 0016 v2 certificate.
- export/019-assembled-native-external-attachment — Core §9.4.1 external profile.

Each case mutates the source export's LAST event payload, recomputes its
`author_event_hash` (Core §9.5), re-signs it with the fixture issuer key, and
rebuilds every member that binds that event, so the verifier reaches the
obligation under test instead of stopping at a stale digest:

- `010-events.cbor` and the manifest `events_digest` (Core §18.3).
- The Merkle leaf and root (Core §11.3), the head checkpoint (re-signed,
  Core §11.2), `020-inclusion-proofs.cbor` and `025-consistency-proofs.cbor`
  (Core §11.4, RFC 6962 §2.1), and their manifest digests.
- `061-attachments.cbor` rows whose `binding_event_hash` named the old event,
  and the attachments extension digest over it (Core §18.3, ADR 0072).
- The seal-fence extension's `events_digest`, `head_checkpoint_digest` and
  `export_attempt_id` (Core §18.3e).
- The `098-README.md` head lines, the archive root directory short hash
  (Core §18.1 naming), and the re-signed manifest.

One case instead replaces a `060-payloads` body in the ZIP and re-signs nothing.

Self-check: before any case is written, the identity mutation must reproduce
each source export's ZIP byte for byte, so the rebuild is known to agree with
the producer on every untouched byte.

Authoring aid only. This script is NOT normative; each vector's
derivation.md cites the spec prose that fixes its expected outcome.

Determinism: two runs produce byte-identical outputs.
"""

from __future__ import annotations

import copy
import hashlib
import json
import sys
import zipfile
from collections.abc import Callable
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cbor2  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from _lib.byte_utils import (  # noqa: E402
    CBOR_TAG_COSE_SIGN1,
    dcbor,
    deterministic_zipinfo,
    domain_separated_sha256,
)

ROOT = Path(__file__).resolve().parent.parent  # fixtures/vectors/
KEY_FILE = ROOT / "_keys" / "issuer-001.cose_key"

# Core §9.8 domain tags.
TAG_AUTHOR_EVENT = "trellis-author-event-v1"
TAG_EVENT = "trellis-event-v1"
TAG_CHECKPOINT = "trellis-checkpoint-v1"
TAG_MERKLE_LEAF = "trellis-merkle-leaf-v1"
TAG_MERKLE_INTERIOR = "trellis-merkle-interior-v1"
TAG_EXPORT_ATTEMPT = "trellis-export-attempt-v1"

SEAL_FENCE = "trellis.export.seal-fence.v1"
ATTACHMENTS = "trellis.export.attachments.v1"
CERTIFICATE_V1 = "trellis.certificate-of-completion.v1"
CERTIFICATE_V2 = "trellis.certificate-of-completion.v2"
PROFILE_MARKER = "trellis.payload-protection-profile.v1"
ATTACHMENT_BINDING = "trellis.evidence-attachment-binding.v1"


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def load_seed() -> bytes:
    seed = cbor2.loads(KEY_FILE.read_bytes())[-4]
    assert isinstance(seed, bytes) and len(seed) == 32, "issuer-001 seed (COSE_Key label -4)"
    return seed


def cose_sign1(protected: bytes, payload: bytes) -> bytes:
    """RFC 9052 §4.4 Sig_structure under the original protected header (Core §7.4)."""
    sig_structure = dcbor(["Signature1", protected, b"", payload])
    signature = Ed25519PrivateKey.from_private_bytes(load_seed()).sign(sig_structure)
    return dcbor(cbor2.CBORTag(CBOR_TAG_COSE_SIGN1, [protected, {}, payload, signature]))


def author_event_hash(payload: dict) -> bytes:
    """Core §9.5: every EventPayload field except `author_event_hash` itself."""
    preimage = {key: value for key, value in payload.items() if key != "author_event_hash"}
    return domain_separated_sha256(TAG_AUTHOR_EVENT, dcbor(preimage))


def canonical_event_hash(scope: bytes, payload: dict) -> bytes:
    """Core §9.2."""
    return domain_separated_sha256(
        TAG_EVENT, dcbor({"version": 1, "ledger_scope": scope, "event_payload": payload})
    )


def checkpoint_digest(scope: bytes, checkpoint_payload: dict) -> bytes:
    """Core §9.6."""
    return domain_separated_sha256(
        TAG_CHECKPOINT,
        dcbor({"version": 1, "scope": scope, "checkpoint_payload": checkpoint_payload}),
    )


def leaf_hash(event_hash: bytes) -> bytes:
    """Core §11.3 leaf."""
    return domain_separated_sha256(TAG_MERKLE_LEAF, event_hash)


def interior_hash(left: bytes, right: bytes) -> bytes:
    """Core §11.3 interior: one component, `left_hash || right_hash`."""
    return domain_separated_sha256(TAG_MERKLE_INTERIOR, left + right)


def split_point(size: int) -> int:
    """Largest power of two strictly below `size` (RFC 6962 §2.1)."""
    k = 1
    while k * 2 < size:
        k *= 2
    return k


def merkle_root(leaves: list[bytes]) -> bytes:
    if len(leaves) == 1:
        return leaves[0]
    k = split_point(len(leaves))
    return interior_hash(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


def audit_path(index: int, leaves: list[bytes]) -> list[bytes]:
    """RFC 6962 §2.1.1 PATH, innermost sibling first."""
    if len(leaves) == 1:
        return []
    k = split_point(len(leaves))
    if index < k:
        return audit_path(index, leaves[:k]) + [merkle_root(leaves[k:])]
    return audit_path(index - k, leaves[k:]) + [merkle_root(leaves[:k])]


def consistency_path(m: int, leaves: list[bytes], complete: bool = True) -> list[bytes]:
    """RFC 6962 §2.1.2 SUBPROOF(m, D[n], b)."""
    n = len(leaves)
    if m == n:
        return [] if complete else [merkle_root(leaves)]
    k = split_point(n)
    if m <= k:
        return consistency_path(m, leaves[:k], complete) + [merkle_root(leaves[k:])]
    return consistency_path(m - k, leaves[k:], False) + [merkle_root(leaves[:k])]


def export_attempt_id(seal: dict, high_water_event_hash: bytes) -> str:
    """Core §18.3e ExportAttemptPreimage."""
    preimage = {
        "bundle_scope": seal["bundle_scope"],
        "seal_version": seal["seal_version"],
        "high_water_sequence": seal["high_water_sequence"],
        "high_water_event_hash": high_water_event_hash,
    }
    return "sha256:" + domain_separated_sha256(TAG_EXPORT_ATTEMPT, dcbor(preimage)).hex()


def root_dir_for(scope: bytes, tree_size: int, tree_head_hash: bytes) -> str:
    """Core §18.1 archive naming: `trellis-export-<scope>-<tree_size>-<short_head_hash>`."""
    return f"trellis-export-{scope.decode('ascii')}-{tree_size}-{tree_head_hash.hex()[:8]}"


class Export:
    """A committed export vector's members, in its archive order."""

    def __init__(self, name: str) -> None:
        self.dir = ROOT / "export" / name
        ledger_state = cbor2.loads((self.dir / "input-ledger-state.cbor").read_bytes())
        self.root_dir: str = ledger_state["root_dir"]
        self.members: list[str] = list(ledger_state["members"])
        self.data: dict[str, bytes] = {m: (self.dir / m).read_bytes() for m in self.members}
        self.zip: bytes = (self.dir / "expected-export.zip").read_bytes()

    def body_member(self) -> str:
        bodies = [m for m in self.members if m.startswith("060-payloads/")]
        assert len(bodies) == 1, bodies
        return bodies[0]


def write_zip(root_dir: str, members: list[str], data: dict[str, bytes]) -> bytes:
    """Core §18.1 deterministic STORED archive in the source member order."""
    import io

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        for member in members:
            arcname = f"{root_dir}/{member}"
            assert arcname.isascii(), arcname
            zf.writestr(deterministic_zipinfo(arcname), data[member])
        for info in zf.filelist:
            info.external_attr = 0
    return buffer.getvalue()


def rebuild(source: Export, mutate: Callable[[dict], None]) -> bytes:
    """Mutate the last event's payload and rebuild every member that binds it."""
    data = dict(source.data)
    manifest_tag = cbor2.loads(data["000-manifest.cbor"])
    manifest = cbor2.loads(manifest_tag.value[2])
    scope = manifest["scope"]

    events = cbor2.loads(data["010-events.cbor"])
    payloads = [cbor2.loads(event.value[2]) for event in events]
    old_last_hash = canonical_event_hash(scope, payloads[-1])

    last = copy.deepcopy(payloads[-1])
    mutate(last)
    last["author_event_hash"] = author_event_hash(last)
    payloads[-1] = last
    signed_last = cose_sign1(events[-1].value[0], dcbor(last))
    # A CBOR array header for len(events) < 24 is 0x80 | len.
    assert len(events) < 24
    data["010-events.cbor"] = (
        bytes([0x80 | len(events)]) + b"".join(dcbor(e) for e in events[:-1]) + signed_last
    )

    event_hashes = [canonical_event_hash(scope, p) for p in payloads]
    leaves = [leaf_hash(h) for h in event_hashes]
    size = len(leaves)

    checkpoints = cbor2.loads(data["040-checkpoints.cbor"])
    head = cbor2.loads(checkpoints[-1].value[2])
    assert head["tree_size"] == size and all(
        cbor2.loads(c.value[2])["tree_size"] < size for c in checkpoints[:-1]
    ), "only the head checkpoint commits to the last event"
    head["tree_head_hash"] = merkle_root(leaves)
    signed_head = cose_sign1(checkpoints[-1].value[0], dcbor(head))
    assert len(checkpoints) < 24
    data["040-checkpoints.cbor"] = (
        bytes([0x80 | len(checkpoints)])
        + b"".join(dcbor(c) for c in checkpoints[:-1])
        + signed_head
    )

    inclusion = cbor2.loads(data["020-inclusion-proofs.cbor"])
    for index, proof in inclusion.items():
        assert proof["tree_size"] == size
        proof["leaf_hash"] = leaves[index]
        proof["audit_path"] = audit_path(index, leaves)
    data["020-inclusion-proofs.cbor"] = dcbor(inclusion)

    consistency = cbor2.loads(data["025-consistency-proofs.cbor"])
    for proof in consistency:
        assert proof["to_tree_size"] == size
        proof["proof_path"] = consistency_path(proof["from_tree_size"], leaves)
    data["025-consistency-proofs.cbor"] = dcbor(consistency)

    new_last_hash = event_hashes[-1]
    extensions = manifest.get("extensions") or {}
    if "061-attachments.cbor" in data:
        rows = cbor2.loads(data["061-attachments.cbor"])
        for row in rows:
            if row["binding_event_hash"] == old_last_hash:
                row["binding_event_hash"] = new_last_hash
        data["061-attachments.cbor"] = dcbor(rows)
        extensions[ATTACHMENTS]["attachment_manifest_digest"] = sha256(data["061-attachments.cbor"])

    head_digest = checkpoint_digest(scope, head)
    old_head = cbor2.loads(cbor2.loads(source.data["040-checkpoints.cbor"])[-1].value[2])
    manifest["events_digest"] = sha256(data["010-events.cbor"])
    manifest["checkpoints_digest"] = sha256(data["040-checkpoints.cbor"])
    manifest["inclusion_proofs_digest"] = sha256(data["020-inclusion-proofs.cbor"])
    manifest["consistency_proofs_digest"] = sha256(data["025-consistency-proofs.cbor"])
    old_head_digest = manifest["head_checkpoint_digest"]
    manifest["head_checkpoint_digest"] = head_digest
    if SEAL_FENCE in extensions:
        seal = extensions[SEAL_FENCE]
        seal["events_digest"] = manifest["events_digest"]
        seal["head_checkpoint_digest"] = head_digest
        seal["export_attempt_id"] = export_attempt_id(seal, new_last_hash)

    readme = data["098-README.md"].decode("utf-8")
    for old, new in (
        (old_head["tree_head_hash"].hex(), head["tree_head_hash"].hex()),
        (old_head_digest.hex(), head_digest.hex()),
    ):
        assert old in readme
        readme = readme.replace(old, new)
    data["098-README.md"] = readme.encode("utf-8")

    data["000-manifest.cbor"] = cose_sign1(manifest_tag.value[0], dcbor(manifest))

    # Nothing outside the rebuilt members may still name the old last event.
    rebuilt = {"000-manifest.cbor", "010-events.cbor", "020-inclusion-proofs.cbor",
               "040-checkpoints.cbor", "061-attachments.cbor"}
    if new_last_hash != old_last_hash:
        for member in source.members:
            if member not in rebuilt:
                assert old_last_hash not in data[member], f"{member} still binds the old event"

    assert root_dir_for(scope, size, old_head["tree_head_hash"]) == source.root_dir
    return write_zip(root_dir_for(scope, size, head["tree_head_hash"]), source.members, data)


def swap_body(source: Export) -> bytes:
    """Flip one bit of the retained body; nothing signed changes."""
    data = dict(source.data)
    body = source.body_member()
    data[body] = data[body][:-1] + bytes([data[body][-1] ^ 0x01])
    return write_zip(source.root_dir, source.members, data)


# --- Mutations -------------------------------------------------------------


def certificate(payload: dict) -> dict:
    return payload["extensions"][CERTIFICATE_V2]


def rows(payload: dict) -> list[dict]:
    return certificate(payload)["chain_summary"]["signer_display"]


def swap_response_refs(payload: dict) -> None:
    first, second = rows(payload)
    first["response_ref"], second["response_ref"] = second["response_ref"], first["response_ref"]


def one_wrong_response_ref(payload: dict) -> None:
    rows(payload)[1]["response_ref"] = b"\xee" * 32


def unresolved_signing_event(payload: dict) -> None:
    certificate(payload)["signing_events"][1] = sha256(b"no chain-present event has this hash")


def duplicate_signing_events(payload: dict) -> None:
    events = certificate(payload)["signing_events"]
    events[1] = events[0]


def ambiguous_v1_and_v2(payload: dict) -> None:
    payload["extensions"][CERTIFICATE_V1] = copy.deepcopy(certificate(payload))


def null_row_response_ref(payload: dict) -> None:
    rows(payload)[1]["response_ref"] = None


def aggregate_response_ref(payload: dict) -> None:
    summary = certificate(payload)["chain_summary"]
    summary["response_ref"] = summary["signer_display"][0]["response_ref"]


def unknown_profile_marker(payload: dict) -> None:
    payload["extensions"][PROFILE_MARKER] = "trellis.external-attachment-unknown.v1"


def inline_payload_under_marker(body: bytes) -> Callable[[dict], None]:
    def mutate(payload: dict) -> None:
        payload["payload_ref"] = {"ref_type": "inline", "ciphertext": body, "nonce": b"\x00" * 12}

    return mutate


def missing_attachment_binding(payload: dict) -> None:
    del payload["extensions"][ATTACHMENT_BINDING]


def empty_key_bag(payload: dict) -> None:
    payload["key_bag"] = {"entries": []}


# --- Cases -----------------------------------------------------------------

FATAL = {"structure_verified": False, "integrity_verified": False, "readability_verified": False}

V2_COVERAGE = {"tr_core": ["TR-CORE-183"]}
NATIVE_COVERAGE = {"tr_core": ["TR-CORE-182"]}


def cases(v2: Export, native: Export) -> list[dict]:
    body = native.data[native.body_member()]
    return [
        {
            "name": "046-export-015-certificate-v2-swapped-response-refs",
            "source": v2,
            "mutate": swap_response_refs,
            "coverage": V2_COVERAGE,
            "description": "ADR 0016 swapped bindings: the v2 certificate's two `signer_display` rows exchange `response_ref` digests, so each row names the other signing event's Response. Localizable failure `response_ref_mismatch` (Core §19 step 6c).",
            "report": {
                "structure_verified": True,
                "integrity_verified": False,
                "readability_verified": True,
                "first_failure_kind": "response_ref_mismatch",
            },
            "derivation": "Core §19 step 6c (v2): for every indexed signing event the resolved digest MUST match that row's `response_ref`; a wrong digest fails `response_ref_mismatch`. After the swap, row 0 carries row 1's digest and row 1 carries row 0's, so both rows are wrong. Both digests still exist in the certificate, which is why the swap shows that a verifier binds by index, not by set membership.",
        },
        {
            "name": "047-export-015-certificate-v2-one-wrong-response-ref",
            "source": v2,
            "mutate": one_wrong_response_ref,
            "coverage": V2_COVERAGE,
            "description": "ADR 0016 partly wrong bindings: row 0 of the v2 certificate is unchanged and correct; row 1's `response_ref` is replaced by a well-formed digest no Response has. Localizable failure `response_ref_mismatch` (Core §19 step 6c).",
            "report": {
                "structure_verified": True,
                "integrity_verified": False,
                "readability_verified": True,
                "first_failure_kind": "response_ref_mismatch",
            },
            "derivation": "Core §19 step 6c (v2): a wrong digest fails `response_ref_mismatch`, and \"a matching row cannot compensate for another row's failure.\" Row 0 still matches its signing event; row 1's digest is 32 bytes of `ee`.",
        },
        {
            "name": "048-export-015-certificate-v2-unresolved-signing-event",
            "source": v2,
            "mutate": unresolved_signing_event,
            "coverage": V2_COVERAGE,
            "description": "ADR 0016 absent proof: the v2 certificate's `signing_events[1]` names a digest no chain-present event has, so no response proof exists for row 1. Localizable failure `signing_event_unresolved` (Core §19 step 6c step 5).",
            "report": {
                "structure_verified": True,
                "integrity_verified": False,
                "readability_verified": True,
                "first_failure_kind": "signing_event_unresolved",
            },
            "derivation": "Core §19 step 6c step 5: every `signing_events[i]` MUST resolve to a chain-present signing event with readable evidence; \"any unresolvable row (missing event, unreadable payload, or for v2 a missing or empty principal or absent proof) fails `signing_event_unresolved`\". `signing_events[1]` is SHA-256 of a fixed text no event hashes to. The two hashes stay distinct, so v2 decode still admits the certificate.",
        },
        {
            "name": "049-export-015-certificate-v2-duplicate-signing-events",
            "source": v2,
            "mutate": duplicate_signing_events,
            "coverage": V2_COVERAGE,
            "description": "ADR 0016 duplicates: the v2 certificate lists the same signing event hash twice. V2 decode MUST reject duplicate signing-event hashes, so the export is rejected: fatal.",
            "report": FATAL,
            "derivation": "Core §19 step 6c: \"V2 MUST reject missing/null row digests, duplicate signing-event hashes, aggregate response_ref, or ambiguous v1/v2 dispatch\" (ADR 0016: \"Signing-event hashes MUST be unique\").",
        },
        {
            "name": "050-export-015-certificate-v2-ambiguous-v1-and-v2",
            "source": v2,
            "mutate": ambiguous_v1_and_v2,
            "coverage": V2_COVERAGE,
            "description": "ADR 0016 ambiguous dispatch: the v2 certificate event also carries a `trellis.certificate-of-completion.v1` extension. V2 decode MUST reject ambiguous v1/v2 dispatch, so the export is rejected: fatal.",
            "report": FATAL,
            "derivation": "Core §19 step 6c: V2 MUST reject \"ambiguous v1/v2 dispatch\" (ADR 0016: \"any ambiguous combination of v1 and v2 certificate extensions\"). The v1 extension is a copy of the v2 body.",
        },
        {
            "name": "051-export-015-certificate-v2-null-row-response-ref",
            "source": v2,
            "mutate": null_row_response_ref,
            "coverage": V2_COVERAGE,
            "description": "ADR 0016 null row digest: row 1 of the v2 certificate carries `response_ref = null`. V2 decode MUST reject missing or null row digests, so the export is rejected: fatal.",
            "report": FATAL,
            "derivation": "Core §19 step 6c: V2 MUST reject \"missing/null row digests\" (ADR 0016: \"V2 decode MUST reject ... a missing or null row digest\").",
        },
        {
            "name": "052-export-015-certificate-v2-aggregate-response-ref",
            "source": v2,
            "mutate": aggregate_response_ref,
            "coverage": V2_COVERAGE,
            "description": "ADR 0016 aggregate digest: the v2 certificate's `chain_summary` also carries the v1 aggregate `response_ref`. V2 decode MUST reject it, so the export is rejected: fatal.",
            "report": FATAL,
            "derivation": "Core §19 step 6c: V2 uses \"a required per-row `signer_display[i].response_ref` instead of aggregate `response_ref`\" and MUST reject \"aggregate response_ref\". The aggregate equals row 0's digest.",
        },
        {
            "name": "053-export-019-native-external-unknown-profile",
            "source": native,
            "mutate": unknown_profile_marker,
            "coverage": NATIVE_COVERAGE,
            "description": "Core §9.4.1: the attachment event's `trellis.payload-protection-profile.v1` marker names an unknown profile. An unknown value MUST be rejected, so the export is rejected: fatal.",
            "report": FATAL,
            "derivation": "Core §9.4.1: \"An unknown value MUST be rejected\" and \"Core §19 extension processing MUST reject unknown Core profile markers\". The marker is `trellis.external-attachment-unknown.v1`.",
        },
        {
            "name": "054-export-019-native-external-inline-payload",
            "source": native,
            "mutate": inline_payload_under_marker(body),
            "coverage": NATIVE_COVERAGE,
            "description": "Core §9.4.1: the attachment event keeps the external profile marker but carries its ciphertext inline. Inline carriage under the external marker MUST be rejected, so the export is rejected: fatal.",
            "report": FATAL,
            "derivation": "Core §9.4.1: the marker's host event MUST carry `PayloadExternal`, and \"Core §19 extension processing MUST reject ... inline carriage under this external marker\". `payload_ref` becomes `PayloadInline` over the same ciphertext, so `content_hash` still matches it.",
        },
        {
            "name": "055-export-019-native-external-missing-binding",
            "source": native,
            "mutate": missing_attachment_binding,
            "coverage": NATIVE_COVERAGE,
            "description": "Core §9.4.1: the attachment event keeps the external profile marker but drops `trellis.evidence-attachment-binding.v1`. A missing attachment binding MUST be rejected, so the export is rejected: fatal.",
            "report": FATAL,
            "derivation": "Core §9.4.1: the marker's host event MUST carry `trellis.evidence-attachment-binding.v1`, and \"Core §19 extension processing MUST reject ... missing attachment bindings\". The `061` catalog row still names the rebuilt event.",
        },
        {
            "name": "056-export-019-native-external-empty-key-bag",
            "source": native,
            "mutate": empty_key_bag,
            "coverage": NATIVE_COVERAGE,
            "description": "Core §9.4.1: the attachment event keeps the external profile marker but its key bag has no entries. The marker requires a nonempty suite-1 key bag, so the export is rejected: fatal.",
            "report": FATAL,
            "derivation": "Core §9.4.1: the marker's host event MUST carry \"a nonempty suite-1 `KeyBag`\" with one wrap per selected recipient, and extension processing MUST reject malformed wraps.",
        },
        {
            "name": "057-export-019-native-external-body-tampered",
            "source": native,
            "body_swap": True,
            "coverage": NATIVE_COVERAGE,
            "description": "Core §9.4.1 / §19 step 4.g: one bit of the retained `060-payloads` ciphertext body is flipped; nothing signed changes. The body no longer hashes to the event's `content_hash`: localizable failure `content_hash_mismatch` at the attachment event.",
            "report": {
                "structure_verified": True,
                "integrity_verified": False,
                "readability_verified": False,
                "first_failure_kind": "content_hash_mismatch",
                "failing_event_id": None,  # filled from the source event below
            },
            "derivation": "Core §19 step 4.g: for `PayloadExternal` with `060-payloads/<content_hash>.bin` present, SHA-256 of the file bytes under §9.3 MUST equal `content_hash`. Core §9.4.1: `CONTENT_DOMAIN` hashes exactly the ciphertext-plus-tag body, and outer `content_hash`, reference `content_hash` and binding `payload_content_hash` MUST agree. The flipped body breaks that equality for the one event, which Core §19.1 reports as `content_hash_mismatch` located at the event. Readability stays false: the profile never claims the original readable (Core §9.4.1).",
        },
    ]


def manifest_toml(case: dict) -> str:
    coverage = "".join(
        f"{key} = {json.dumps(value)}\n" for key, value in case["coverage"].items()
    )
    report = "".join(
        f"{key:<20} = {json.dumps(value)}\n" for key, value in case["report"].items()
    )
    return (
        f'id          = "verify/{case["name"]}"\n'
        'op          = "verify"\n'
        'status      = "active"\n'
        f'description = """{case["description"]}"""\n'
        "\n[coverage]\n"
        f"{coverage}"
        "\n[inputs]\n"
        'export_zip = "input-export.zip"\n'
        "\n[expected.report]\n"
        f"{report}"
        "\n[derivation]\n"
        'document = "derivation.md"\n'
    )


DECODE_REJECTED = (
    "The certificate or profile rule rejects the event's payload, and an event that does not "
    "decode rejects the export: structure, integrity and readability are all false. The spec "
    "does not fix which check reports the rejection first. Both the seal-fence high-water "
    "decode (Core §18.3e) and event decoding (Core §19 step 4.c) read this last event, so the "
    "failure kind is not pinned."
)


def derivation_md(case: dict) -> str:
    source = case["source"].dir.name
    if case.get("body_swap"):
        how = (
            f"Starts from `export/{source}/expected-export.zip` and flips the last bit of the "
            "single `060-payloads` body. No other member changes and nothing is re-signed."
        )
    else:
        how = (
            f"Starts from `export/{source}/expected-export.zip` and mutates the payload of its "
            "last event as described below. The event's `author_event_hash` (Core §9.5) is "
            "recomputed and the event re-signed with the public fixture key `issuer-001`. Every "
            "member that binds the event is rebuilt: the events array, the Merkle root and the "
            "re-signed head checkpoint (Core §11.2–§11.3), the inclusion and consistency proofs "
            "(Core §11.4), any `061` row's `binding_event_hash`, the seal-fence fields including "
            "`export_attempt_id` (Core §18.3e), the README head lines, the archive root name, "
            "and the re-signed manifest with its digests. The verifier therefore reaches the "
            "obligation under test rather than a stale digest."
        )
    return (
        f"# Derivation — `verify/{case['name']}`\n\n"
        f"{how}\n\n"
        f"{case['derivation']}\n\n"
        + (f"{DECODE_REJECTED}\n\n" if case["report"] is FATAL else "")
        + "The expected outcome is fixed by the spec text above and confirmed against the "
        "maintained Rust verifier (`trellis-conformance`). Bytes were produced by "
        "`_generator/gen_verify_resigned_export_negatives.py`, an authoring aid; this "
        "document, not the generator, is the reproduction authority.\n"
    )


def self_check(source: Export) -> None:
    rebuilt = rebuild(source, lambda payload: None)
    assert rebuilt == source.zip, f"identity rebuild of {source.dir.name} drifted from its ZIP"


def main() -> None:
    v2 = Export("015-certificate-v2-distinct-responses")
    native = Export("019-assembled-native-external-attachment")
    for source in (v2, native):
        self_check(source)

    native_events = cbor2.loads(native.data["010-events.cbor"])
    native_scope = cbor2.loads(cbor2.loads(native.data["000-manifest.cbor"]).value[2])["scope"]
    native_event_hash = canonical_event_hash(
        native_scope, cbor2.loads(native_events[-1].value[2])
    ).hex()

    for case in cases(v2, native):
        if case.get("body_swap"):
            case["report"]["failing_event_id"] = native_event_hash
            zip_bytes = swap_body(case["source"])
        else:
            zip_bytes = rebuild(case["source"], case["mutate"])
        out = ROOT / "verify" / case["name"]
        out.mkdir(parents=True, exist_ok=True)
        (out / "input-export.zip").write_bytes(zip_bytes)
        (out / "manifest.toml").write_text(manifest_toml(case))
        (out / "derivation.md").write_text(derivation_md(case))


if __name__ == "__main__":
    main()
