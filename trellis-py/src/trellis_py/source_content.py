"""WOS Source-content catalog readers (062 signature / 063 intake members).

Python counterpart of the catalog parsers in `trellis-verify-wos`
(`records.rs`, `protected_response.rs`, `source_signed_task.rs`,
`source_proof_package.rs`, `source_original.rs`). These readers check closed
public shapes and exact native joins only. They never open protected content
and grant no Source signature authority; final Source readers own that.

Every reader raises :class:`trellis_py.verify.VerifyError` on a malformed
catalog. A map key repeated at any depth refuses the whole catalog, as Rust's
`integrity_cbor::decode_cbor_value` does (canonical CBOR R4).
"""

from __future__ import annotations

import unicodedata
from typing import Any, Optional

from trellis_py import native_provenance
from trellis_py import verify as core
from trellis_py._cbor_canonical import encode_canonical_cbor_value
from trellis_py._cbor_strict import (
    CborDuplicateKeyError,
    CborReferenceTagError,
    CborStrictError,
    reject_duplicate_canonical_map_keys,
)

MAX_CATALOG_BYTES = 1024 * 1024
MAX_ROWS = 256

_MAX_RESPONSE_BYTES = 1_048_576
_MAX_PACKAGE_BYTES = 8 * 1024 * 1024
_MAX_METADATA_BYTES = 64 * 1024
_KEY_LEN = (1, 64)  # bstr .size (1..64): idempotency key and context key bound

_LOCATOR_FIELDS = (
    "version", "native_event_hash", "response_ref", "response_id", "response_hash",
    "original_byte_length", "content_hash", "context_key", "record_hash",
    "source_binding_hash", "publication_hash", "public_policy_hash",
    "recipient_policy_hash", "nonce", "key_bag",
)
_PACKAGE_FIELDS = (
    "version", "family", "task_completed_event_hash", "package_sha256",
    "witness_sha256", "original_byte_length", "content_hash", "context_key",
    "record_hash", "source_binding_hash", "current_publication_hash",
    "original_publication_hash", "public_policy_hash", "recipient_policy_hash",
    "nonce", "key_bag",
)
_TASK_FIELDS = (
    "kind", "version", "family", "canonical_event_hash", "task_created_event_hash",
    "process_id", "task_id", "task_ref", "task_created_record_id",
    "task_completed_record_id", "actor_ref", "artifact_id", "formspec_response_ref",
    "response_id", "signature_id", "signed_payload_digest",
    "signed_payload_digest_algorithm", "task_proof", "protected_response",
)
_PROOF_FIELDS = (
    "version", "admission", "witness_sha256", "protected_package",
    "native_snapshot_hash", "provider_selection_hash", "family_selection_hash",
    "original_selection_hash", "committed_task_submit_key", "native_outcome_digest",
    "http_receipt_digest",
)
_TASK_KIND = "sourceSignedCompletedTask"
_FAMILIES = ("native-v1", "mixed-v2", "native-local-v3")


# --- typed field access -------------------------------------------------------


def _fail(message: str) -> core.VerifyError:
    return core.VerifyError(message)


def _text(m: dict, key: str) -> str:
    v = m.get(key)
    if not isinstance(v, str):
        raise _fail(f"`{key}` is not text")
    return v


def _uint(m: dict, key: str) -> int:
    v = m.get(key)
    if type(v) is not int or v < 0:
        raise _fail(f"`{key}` is not an unsigned integer")
    return v


def _bytes(m: dict, key: str, size: Optional[int] = None) -> bytes:
    v = m.get(key)
    if not isinstance(v, bytes) or (size is not None and len(v) != size):
        raise _fail(f"`{key}` is not {'bytes' if size is None else f'{size} bytes'}")
    return v


def _closed(m: Any, allowed: tuple[str, ...], *, complete: bool, label: str) -> dict:
    """The map must be text-keyed and within `allowed` (and equal to it when `complete`)."""
    if not isinstance(m, dict):
        raise _fail(f"{label} must be a map")
    if any(not isinstance(k, str) or k not in allowed for k in m):
        raise _fail(f"{label} has an unknown field")
    if complete and len(m) != len(allowed):
        raise _fail(f"{label} is missing a field")
    return m


def _blank(s: str) -> bool:
    return not s.strip(core.RUST_WHITE_SPACE)


def _bytes_len(s: str) -> int:
    return len(s.encode())


def _text_ok(s: str) -> bool:
    return (
        not _blank(s)
        and _bytes_len(s) <= 4096
        and not any(unicodedata.category(c) == "Cc" for c in s)
    )


def _canonical_len(value: Any) -> int:
    return len(encode_canonical_cbor_value(value))


def _decode(data: bytes, root_message: str = "catalog root is not an array") -> Any:
    try:
        reject_duplicate_canonical_map_keys(data)
    except CborReferenceTagError as exc:
        # Rust leaves a root reference tag as a tag, so the root is simply not an array.
        raise _fail(root_message if exc.offset == 0 else f"catalog is not unambiguous CBOR: {exc}") from exc
    except CborDuplicateKeyError as exc:
        # Rust's integrity_cbor::decode_cbor_value words the same refusal this way.
        raise _fail(f"duplicate canonical CBOR map key `{exc.canonical_key_hex}`") from exc
    except CborStrictError as exc:
        raise _fail(f"catalog is not unambiguous CBOR: {exc}") from exc
    return core._decode_value(data)


def _key_bag(value: Any) -> dict:
    if not isinstance(value, dict):
        raise _fail("protected key bag must be a map")
    return value


# --- protected Response locator ----------------------------------------------


def parse_protected_response(value: Any) -> dict[str, Any]:
    """Closed catalog reference to one retained protected Response occurrence."""
    m = _closed(value, _LOCATOR_FIELDS, complete=True, label="protected Response locator")
    if _uint(m, "version") != 1:
        raise _fail("protected Response locator version is unsupported")
    out: dict[str, Any] = {
        "response_ref": _text(m, "response_ref"),
        "response_id": _text(m, "response_id"),
        "response_hash": _text(m, "response_hash"),
        "original_byte_length": _uint(m, "original_byte_length"),
        "context_key": _bytes(m, "context_key"),
        "nonce": _bytes(m, "nonce", 12),
        "key_bag": _key_bag(m["key_bag"]),
    }
    core._parse_sha256_prefix_text(out["response_hash"])
    for name in (
        "native_event_hash", "content_hash", "record_hash", "source_binding_hash",
        "publication_hash", "public_policy_hash", "recipient_policy_hash",
    ):
        out[name] = _bytes(m, name, 32)
    if (
        _blank(out["response_id"]) or _bytes_len(out["response_id"]) > 1024
        or _blank(out["response_ref"]) or _bytes_len(out["response_ref"]) > 1024
        or not 0 < out["original_byte_length"] <= _MAX_RESPONSE_BYTES
        or not _KEY_LEN[0] <= len(out["context_key"]) <= _KEY_LEN[1]
        or _canonical_len(out["key_bag"]) > _MAX_METADATA_BYTES
    ):
        raise _fail("protected Response identity or bound is invalid")
    return out


# --- protected Source proof package ------------------------------------------


def _proof_package_key_bag(value: Any) -> None:
    bag = _closed(value, ("entries",), complete=True, label="proof-package key bag")
    entries = bag["entries"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= 64:
        raise _fail("proof-package wrap count")
    recipients: set[bytes] = set()
    for entry in entries:
        wrap = _closed(
            entry, ("recipient", "suite", "ephemeral_pubkey", "wrapped_dek"),
            complete=True, label="proof-package wrap",
        )
        recipient = _bytes(wrap, "recipient")
        if (
            not recipient or len(recipient) > 256 or recipient in recipients
            or _uint(wrap, "suite") != 1
            or len(_bytes(wrap, "ephemeral_pubkey")) != 32
            or len(_bytes(wrap, "wrapped_dek")) != 48
        ):
            raise _fail("proof-package wrap invalid")
        recipients.add(recipient)
    if _canonical_len(value) > _MAX_METADATA_BYTES:
        raise _fail("proof-package key bag bound")


def parse_proof_package(value: Any) -> dict[str, Any]:
    m = _closed(value, _PACKAGE_FIELDS, complete=True, label="proof-package locator")
    if _uint(m, "version") != 1:
        raise _fail("proof-package version unsupported")
    out: dict[str, Any] = {
        "family": _text(m, "family"),
        "original_byte_length": _uint(m, "original_byte_length"),
        "context_key": _bytes(m, "context_key"),
        "nonce": _bytes(m, "nonce", 12),
        "key_bag": m["key_bag"],
    }
    for name in (
        "task_completed_event_hash", "package_sha256", "witness_sha256", "content_hash",
        "record_hash", "source_binding_hash", "current_publication_hash",
        "original_publication_hash", "public_policy_hash", "recipient_policy_hash",
    ):
        out[name] = _bytes(m, name, 32)
    if (
        out["family"] != "mixed-v2"
        or not 0 < out["original_byte_length"] <= _MAX_PACKAGE_BYTES
        or not _KEY_LEN[0] <= len(out["context_key"]) <= _KEY_LEN[1]
    ):
        raise _fail("proof-package family or content bound unsupported")
    _proof_package_key_bag(out["key_bag"])
    return out


def parse_original_context_proof(value: Any) -> dict[str, Any]:
    m = _closed(
        value, ("task_completed_event_hash", "package_record_hash", "context_instance"),
        complete=True, label="original context proof",
    )
    instance = _text(m, "context_instance")
    if _blank(instance) or _bytes_len(instance) > 1024 or any(
        unicodedata.category(c) == "Cc" for c in instance
    ):
        raise _fail("original context instance invalid")
    return {
        "task_completed_event_hash": _bytes(m, "task_completed_event_hash", 32),
        "package_record_hash": _bytes(m, "package_record_hash", 32),
        "context_instance": instance,
    }


# --- Source-signed completed task rows (062) ----------------------------------


def parse_source_task(value: Any) -> dict[str, Any]:
    """One closed `sourceSignedCompletedTask` row, validated like Rust `from_value`."""
    m = _closed(value, _TASK_FIELDS, complete=False, label="Source row")
    if _text(m, "kind") != _TASK_KIND or _uint(m, "version") != 1:
        raise _fail("unsupported Source row")
    proof = _closed(m.get("task_proof"), _PROOF_FIELDS, complete=False, label="task proof")
    if _uint(proof, "version") != 1 or _text(proof, "admission") != "owningWosProviderAdmitted":
        raise _fail("unsupported task admission")
    family = _text(m, "family")
    if family not in _FAMILIES:
        raise _fail("unsupported Source family")
    task: dict[str, Any] = {"family": family}
    for name in ("canonical_event_hash", "task_created_event_hash"):
        task[name] = _bytes(m, name, 32)
    texts = (
        "process_id", "task_id", "task_ref", "task_created_record_id",
        "task_completed_record_id", "actor_ref", "artifact_id", "formspec_response_ref",
        "response_id", "signature_id", "signed_payload_digest",
        "signed_payload_digest_algorithm",
    )
    for name in texts:
        task[name] = _text(m, name)
    task["task_proof"] = {
        "protected_package": (
            parse_proof_package(proof["protected_package"]) if "protected_package" in proof else None
        ),
        "original_selection_hash": (
            _bytes(proof, "original_selection_hash", 32)
            if "original_selection_hash" in proof else None
        ),
        "committed_task_submit_key": _text(proof, "committed_task_submit_key"),
        **{
            name: _bytes(proof, name, 32)
            for name in (
                "witness_sha256", "native_snapshot_hash", "provider_selection_hash",
                "family_selection_hash", "native_outcome_digest", "http_receipt_digest",
            )
        },
    }
    locator = m.get("protected_response")
    if _canonical_len(locator) > _MAX_METADATA_BYTES:
        raise _fail("protected locator exceeds bound")
    task["protected"] = parse_protected_response(locator)
    _validate_source_task(task)
    return task


def _validate_source_task(task: dict[str, Any]) -> None:
    proof = task["task_proof"]
    protected = task["protected"]
    if (
        not all(_text_ok(task[n]) for n in (
            "process_id", "task_id", "task_ref", "task_created_record_id",
            "task_completed_record_id", "actor_ref", "artifact_id",
            "formspec_response_ref", "response_id", "signature_id",
            "signed_payload_digest",
        ))
        or not _text_ok(proof["committed_task_submit_key"])
        or task["signed_payload_digest_algorithm"] != "sha-256"
    ):
        raise _fail("invalid Source task fields")
    has_original = proof["original_selection_hash"] is not None
    if (task["family"] == "mixed-v2" and not has_original) or (
        task["family"] == "native-local-v3" and has_original
    ):
        raise _fail("Source family proof selection mismatch")
    if (
        protected["native_event_hash"] != task["canonical_event_hash"]
        or protected["response_ref"] != task["formspec_response_ref"]
        or protected["response_id"] != task["response_id"]
    ):
        raise _fail("Source task protected binding mismatch")
    package = proof["protected_package"]
    if package is not None and (
        package["family"] != task["family"]
        or package["task_completed_event_hash"] != task["canonical_event_hash"]
        or package["witness_sha256"] != proof["witness_sha256"]
        or package["source_binding_hash"] != protected["source_binding_hash"]
        or package["current_publication_hash"] != protected["publication_hash"]
        or package["public_policy_hash"] != protected["public_policy_hash"]
        or package["recipient_policy_hash"] != protected["recipient_policy_hash"]
    ):
        raise _fail("Source proof package task association differs")


def read_signature_catalog(data: bytes) -> tuple[list[dict], list[dict]]:
    """Splits the 062 catalog into legacy formal rows and Source task rows.

    Rows carrying `kind` are Source task rows; every other row is a legacy
    formal signature row, parsed by the strict legacy reader.
    """
    if len(data) > MAX_CATALOG_BYTES:
        raise _fail("catalog exceeds bound")
    rows = _decode(data, "catalog must be array")
    if not isinstance(rows, list):
        raise _fail("catalog must be array")
    if len(rows) > MAX_ROWS:
        raise _fail("catalog row limit")
    legacy: list[dict] = []
    tasks: list[dict] = []
    for row in rows:
        if not isinstance(row, dict):
            raise _fail("signature catalog entry is not a map")
        if "kind" in row:
            tasks.append(parse_source_task(row))
        else:
            legacy.append(_legacy_signature_row(row))
    return legacy, tasks


def _optional_text(entry: dict, key: str) -> Optional[str]:
    v = entry.get(key)
    if v is not None and not isinstance(v, str):
        raise _fail(f"`{key}` must be text or null")
    return v


def _legacy_signature_row(entry: dict) -> dict[str, Any]:
    try:
        encode_canonical_cbor_value(entry)  # legacy rows must be canonically encodable (no NaN, -0.0)
    except Exception as exc:  # noqa: BLE001
        raise _fail("invalid legacy row") from exc
    ib = entry.get("identity_binding")
    cr = entry.get("consent_reference")
    if not isinstance(ib, dict) or not isinstance(cr, dict):
        raise _fail("identity_binding or consent_reference is not a map")
    text_keys = (
        "signer_id", "role_id", "role", "document_id", "document_hash",
        "document_hash_algorithm", "signed_at", "signature_provider", "ceremony_id",
        "signing_act_id", "presentation_hash",
    )
    protected = entry.get("protected_response")
    return {
        "canonical_event_hash": _bytes(entry, "canonical_event_hash", 32),
        **{k: _text(entry, k) for k in text_keys},
        "identity_binding": ib,
        "consent_reference": cr,
        **{
            k: _optional_text(entry, k)
            for k in (
                "source_signature_system", "source_signature_id", "signed_payload_digest",
                "signed_payload_digest_algorithm", "signing_intent", "profile_ref",
                "profile_key", "witnessed_signature_ref",
            )
        },
        # The catalog names the Response only as `formspec_response_ref`; the row key
        # keeps the record parser's name so both sides compare field for field.
        "source_response_ref": _text(entry, "formspec_response_ref"),
        "protected_response": None if protected is None else parse_protected_response(protected),
    }


# --- intake rows (063) ---------------------------------------------------------


def read_intake_catalog(data: bytes) -> list[dict[str, Any]]:
    """Intake rows; each carries exactly one of inline `response_bytes` or a protected locator."""
    rows = _decode(data, "intake handoff catalog root is not an array")
    if not isinstance(rows, list):
        raise _fail("intake handoff catalog root is not an array")
    out: list[dict[str, Any]] = []
    for entry in rows:
        if not isinstance(entry, dict):
            raise _fail("intake handoff catalog entry is not a map")
        if entry.get("handoff") is None:
            raise _fail("missing `handoff`")
        handoff = core._parse_intake_handoff_details(entry["handoff"])
        inline = entry.get("response_bytes")
        protected = entry.get("protected_response")
        if (inline is None) == (protected is None):
            raise _fail("intake catalog requires exactly one Response content form")
        out.append({
            "intake_event_hash": _bytes(entry, "intake_event_hash", 32),
            "case_created_event_hash": core._map_lookup_optional_fixed_bytes(
                entry, "case_created_event_hash", 32
            ),
            "handoff": handoff,
            "response_bytes": _bytes(entry, "response_bytes") if inline is not None else None,
            "protected_response": (
                parse_protected_response(protected) if protected is not None else None
            ),
            "original_context_proof": (
                parse_original_context_proof(entry["original_context_proof"])
                if "original_context_proof" in entry else None
            ),
        })
    return out


def protected_originals(data: bytes, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Protected original rows of an already-parsed 063 catalog (Rust `protected_intake_responses_from_catalog`)."""
    if len(data) > MAX_CATALOG_BYTES:
        raise _fail("intake catalog byte limit")
    if len(entries) > MAX_ROWS:
        raise _fail("intake catalog count limit")
    seen: set[bytes] = set()
    originals = []
    for entry in entries:
        if entry["intake_event_hash"] in seen:
            raise _fail("duplicate original intake")
        seen.add(entry["intake_event_hash"])
        if entry["protected_response"] is not None:
            originals.append(entry)
        elif entry["original_context_proof"] is not None:
            raise _fail("original context proof requires protected original")
    return originals


def original_context_error(original: dict[str, Any], tasks: list[dict[str, Any]]) -> Optional[str]:
    """Why the original's MIXED context join to exactly one task package fails, if it does."""
    join = original["original_context_proof"]
    matches = [t for t in tasks if t["canonical_event_hash"] == join["task_completed_event_hash"]]
    if not matches:
        return "original context task absent"
    if len(matches) > 1:
        return "original context task ambiguous"
    package = matches[0]["task_proof"]["protected_package"]
    if package is None:
        return "original context package absent"
    locator = original["protected_response"]
    if (
        package["record_hash"] != join["package_record_hash"]
        or package["task_completed_event_hash"] != join["task_completed_event_hash"]
        or package["original_publication_hash"] != locator["publication_hash"]
        or package["recipient_policy_hash"] != locator["recipient_policy_hash"]
    ):
        return "original context package association differs"
    return None


# --- exact native task join ----------------------------------------------------


_MISSING = object()


def _pointer(value: Any, *path: str) -> Any:
    for step in path:
        if not isinstance(value, dict) or step not in value:
            return _MISSING
        value = value[step]
    return value


NativeTaskIndex = Optional[dict[str, list[tuple[int, "core.EventDetails", dict]]]]


def native_task_index(
    ordered_events: list[core.EventDetails], payload_blobs: dict[bytes, bytes]
) -> NativeTaskIndex:
    """Native task records grouped by task id, decoded once per export.

    None when any readable native record is outside the accepted shape: no task
    can then be joined exactly (Rust refuses every join the same way).
    """
    index: dict[str, list[tuple[int, core.EventDetails, dict]]] = {}
    for position, details in enumerate(ordered_events):
        if details.event_type != native_provenance.EVENT_TYPE:
            continue
        payload = core._readable_payload_bytes(details, payload_blobs)
        if payload is None:
            continue
        try:
            record = native_provenance.parse_native_record(payload)
        except core.VerifyError:
            return None
        task_id = _pointer(record, "data", "taskId")
        if isinstance(task_id, str):
            index.setdefault(task_id, []).append((position, details, record))
    return index


def native_join_error(task: dict[str, Any], index: NativeTaskIndex) -> Optional[str]:
    """Why the task's created and completed records do not join the ledger exactly, if they do not."""
    if index is None:
        return "invalid native task record"
    created = completed = None
    creations = completions = 0
    for position, details, record in index.get(task["task_id"], ()):
        if record["recordKind"] == "taskCreated":
            creations += 1
            if (
                details.canonical_event_hash == task["task_created_event_hash"]
                and record["id"] == task["task_created_record_id"]
            ):
                created = (position, record)
        elif record["recordKind"] == "taskCompleted":
            completions += 1
            if (
                details.canonical_event_hash == task["canonical_event_hash"]
                and record["id"] == task["task_completed_record_id"]
            ):
                completed = (position, record)
    if created is None:
        return "Source task creation unresolved"
    if completed is None:
        return "Source task completion unresolved"
    (ci, c), (di, d) = created, completed
    if (
        creations != 1 or completions != 1 or ci >= di
        or _pointer(c, "data", "details", "taskRef") != task["task_ref"]
        or d.get("actorId") != task["actor_ref"]
        or _pointer(d, "data", "details", "artifactId") != task["artifact_id"]
    ):
        return "Source native task join mismatch"
    assigned = _pointer(c, "data", "details", "assignedActor")
    if assigned is not _MISSING and assigned != task["actor_ref"]:
        return "Source assigned actor mismatch"
    return None
