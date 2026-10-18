"""Structural admission of the explicit native external attachment profile (Core §9.4.1).

Mirrors Rust `trellis_cddl::external_attachment`. Parsing authenticates
nothing: a caller verifies the event signature and chain first. Admission
grants no recipient authority, so a generic verifier never reads the original.
TR-CORE-182.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

import cbor2

from trellis_py._cbor_canonical import CanonicalCborError, encode_canonical_cbor_value
from trellis_py._cbor_strict import CborStrictError, reject_duplicate_canonical_map_keys

PROFILE_EXTENSION = "trellis.payload-protection-profile.v1"
EXTERNAL_ATTACHMENT_PROFILE = "trellis.external-attachment-suite1.v1"
ATTACHMENT_BINDING_EXTENSION = "trellis.evidence-attachment-binding.v1"

_HEADER_FIELDS = frozenset(
    {
        "event_type",
        "authored_at",
        "retention_tier",
        "classification",
        "outcome_commitment",
        "subject_ref_commitment",
        "tag_commitment",
        "witness_ref",
        "extensions",
    }
)
_REFERENCE_FIELDS = frozenset({"ref_type", "content_hash", "availability", "retrieval_hint"})
_BINDING_FIELDS = frozenset(
    {
        "attachment_id",
        "slot_path",
        "media_type",
        "byte_length",
        "attachment_sha256",
        "payload_content_hash",
        "filename",
        "prior_binding_hash",
    }
)
_WRAP_FIELDS = frozenset({"recipient", "suite", "ephemeral_pubkey", "wrapped_dek"})
_MEDIA_TOKEN_EXTRA = frozenset(b"!#$%&'*+-.^_`|~")
_LOWER_HEX = frozenset("0123456789abcdef")


class ExternalAttachmentProfileError(ValueError):
    """The event selects the profile but its fields are not admissible."""


@dataclass(frozen=True)
class ExternalAttachmentWrap:
    """One structurally checked suite-1 recipient wrap, not cryptographically verified."""

    recipient: bytes
    ephemeral_pubkey: bytes
    wrapped_dek: bytes


@dataclass(frozen=True)
class ExternalAttachment:
    """Signed decoding inputs; a recipient uses them only after signature verification."""

    original_sha256: bytes
    original_byte_length: int
    idempotency_key: bytes
    content_hash: bytes
    key_bag_entries: tuple[ExternalAttachmentWrap, ...]


def parse_external_attachment_profile(data: bytes) -> Optional[ExternalAttachment]:
    """Parse an event payload that may select the profile.

    Returns None for an unmarked event, which keeps its existing reading.
    A present marker must name this exact profile. The payload must be
    canonical CBOR with no duplicate map keys at any depth.

    Raises ExternalAttachmentProfileError for malformed CBOR or incomplete,
    unknown or inconsistent profile fields.
    """
    try:
        reject_duplicate_canonical_map_keys(data)
        value = cbor2.loads(data)
        canonical = encode_canonical_cbor_value(value) == bytes(data)
    except (CborStrictError, cbor2.CBORDecodeError, CanonicalCborError) as exc:
        raise ExternalAttachmentProfileError(f"invalid external attachment CBOR: {exc}") from exc
    if not canonical:
        raise ExternalAttachmentProfileError("noncanonical external attachment CBOR")
    event = _map(value)
    extensions = event.get("extensions")
    if extensions is None:
        return None
    extensions = _map(extensions)
    if PROFILE_EXTENSION not in extensions:
        return None
    if _text(extensions[PROFILE_EXTENSION]) != EXTERNAL_ATTACHMENT_PROFILE:
        raise ExternalAttachmentProfileError("unknown external attachment protection profile")
    _native_header(event)
    content_hash = _fixed(_field(event, "content_hash"), 32)
    idempotency_key = _bytes(_field(event, "idempotency_key"))
    if not 1 <= len(idempotency_key) <= 64:
        raise ExternalAttachmentProfileError("idempotency key length invalid")

    reference = _closed(_field(event, "payload_ref"), _REFERENCE_FIELDS)
    if (
        _text(reference["ref_type"]) != "external"
        or _fixed(reference["content_hash"], 32) != content_hash
        or _uint(reference["availability"]) != 0
        or reference["retrieval_hint"] is not None
    ):
        raise ExternalAttachmentProfileError(
            "profile requires matching external InExport payload reference"
        )

    binding = _closed(_field(extensions, ATTACHMENT_BINDING_EXTENSION), _BINDING_FIELDS)
    _identity(binding["attachment_id"])
    _pointer(binding["slot_path"])
    _media_type(binding["media_type"])
    original_byte_length = _uint(binding["byte_length"])
    if original_byte_length == 0:
        raise ExternalAttachmentProfileError("empty original attachment")
    original_sha256 = _sha(binding["attachment_sha256"])
    if _sha(binding["payload_content_hash"]) != content_hash:
        raise ExternalAttachmentProfileError("binding ciphertext hash mismatch")
    if binding["filename"] is not None and not isinstance(binding["filename"], str):
        raise ExternalAttachmentProfileError("invalid filename")
    if binding["prior_binding_hash"] is not None:
        _sha(binding["prior_binding_hash"])

    bag = _closed(_field(event, "key_bag"), frozenset({"entries"}))
    entries = bag["entries"]
    if not isinstance(entries, list):
        raise ExternalAttachmentProfileError("key bag entries must be an array")
    if not entries:
        raise ExternalAttachmentProfileError("profile requires recipient wraps")
    recipients: set[bytes] = set()
    ephemerals: set[bytes] = set()
    wraps = []
    for value in entries:
        entry = _closed(value, _WRAP_FIELDS)
        recipient = _bytes(entry["recipient"])
        ephemeral_pubkey = _fixed(entry["ephemeral_pubkey"], 32)
        if (
            not recipient
            or _uint(entry["suite"]) != 1
            or recipient in recipients
            or ephemeral_pubkey in ephemerals
        ):
            raise ExternalAttachmentProfileError("invalid or duplicate suite 1 recipient wrap")
        recipients.add(recipient)
        ephemerals.add(ephemeral_pubkey)
        wraps.append(
            ExternalAttachmentWrap(
                recipient=recipient,
                ephemeral_pubkey=ephemeral_pubkey,
                wrapped_dek=_fixed(entry["wrapped_dek"], 48),
            )
        )
    return ExternalAttachment(
        original_sha256=original_sha256,
        original_byte_length=original_byte_length,
        idempotency_key=idempotency_key,
        content_hash=content_hash,
        key_bag_entries=tuple(wraps),
    )


def _native_header(event: dict) -> None:
    if _uint(_field(event, "version")) != 1 or not _bytes(_field(event, "ledger_scope")):
        raise ExternalAttachmentProfileError("invalid native event version or scope")
    _uint(_field(event, "sequence"))
    _nullable_digest(_field(event, "prev_hash"))
    header = _closed(_field(event, "header"), _HEADER_FIELDS)
    for key in ("event_type", "classification"):
        identity = _bytes(header[key])
        try:
            identity.decode("utf-8")
        except UnicodeDecodeError:
            identity = b""
        if not identity:
            raise ExternalAttachmentProfileError(
                "native header identity must be nonempty UTF-8 bytes"
            )
    authored_at = header["authored_at"]
    if not isinstance(authored_at, list) or len(authored_at) != 2:
        raise ExternalAttachmentProfileError("invalid authored_at timestamp")
    _uint(authored_at[0])
    if _uint(authored_at[1]) >= 1_000_000_000:
        raise ExternalAttachmentProfileError("invalid authored_at nanoseconds")
    if _uint(header["retention_tier"]) > 3:
        raise ExternalAttachmentProfileError("invalid retention tier")
    for key in ("outcome_commitment", "subject_ref_commitment", "tag_commitment"):
        _nullable_digest(header[key])
    if header["witness_ref"] is not None and not isinstance(header["witness_ref"], bytes):
        raise ExternalAttachmentProfileError("invalid witness reference")
    if header["extensions"] is not None and any(
        not isinstance(key, str) for key in _map(header["extensions"])
    ):
        raise ExternalAttachmentProfileError("header extension keys must be text")


def _map(value: Any) -> dict:
    if not isinstance(value, dict):
        raise ExternalAttachmentProfileError("expected map")
    return value


def _field(fields: dict, key: str) -> Any:
    if key not in fields:
        raise ExternalAttachmentProfileError(f"missing {key}")
    return fields[key]


def _closed(value: Any, keys: frozenset[str]) -> dict:
    fields = _map(value)
    if set(fields) != keys:
        raise ExternalAttachmentProfileError("unexpected or missing profile field")
    return fields


def _text(value: Any) -> str:
    if not isinstance(value, str):
        raise ExternalAttachmentProfileError("expected text")
    return value


def _bytes(value: Any) -> bytes:
    if not isinstance(value, bytes):
        raise ExternalAttachmentProfileError("expected byte string")
    return value


def _fixed(value: Any, length: int) -> bytes:
    raw = _bytes(value)
    if len(raw) != length:
        raise ExternalAttachmentProfileError("wrong byte string length")
    return raw


def _uint(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2**64:
        raise ExternalAttachmentProfileError("expected unsigned integer")
    return value


def _nullable_digest(value: Any) -> None:
    if value is not None:
        _fixed(value, 32)


def _sha(value: Any) -> bytes:
    text = _text(value)
    if not text.startswith("sha256:"):
        raise ExternalAttachmentProfileError("invalid SHA-256 text")
    digest = text[len("sha256:") :]
    if len(digest) != 64 or not set(digest) <= _LOWER_HEX:
        raise ExternalAttachmentProfileError("invalid lowercase SHA-256 text")
    return bytes.fromhex(digest)


def _identity(value: Any) -> str:
    text = _text(value)
    if not text or text.strip() != text or any(_is_control(c) for c in text):
        raise ExternalAttachmentProfileError("invalid attachment identity")
    return text


def _is_control(char: str) -> bool:
    # Rust `char::is_control`: the Unicode Cc category, C0 and C1 controls.
    code = ord(char)
    return code < 0x20 or 0x7F <= code < 0xA0


def _pointer(value: Any) -> None:
    text = _identity(value)
    if not text.startswith("/"):
        raise ExternalAttachmentProfileError("slot_path must be a JSON pointer")
    index = 0
    while index < len(text):
        if text[index] == "~":
            if index + 1 >= len(text) or text[index + 1] not in "01":
                raise ExternalAttachmentProfileError("invalid JSON pointer escape")
            index += 1
        index += 1


def _media_type(value: Any) -> None:
    text = _text(value)
    primary, slash, secondary = text.partition("/")

    def token(part: str) -> bool:
        return bool(part) and all(
            ord(c) < 128 and (c.isalnum() or ord(c) in _MEDIA_TOKEN_EXTRA) for c in part
        )

    # Rust `split_once('/')`: the subtype keeps any later slash and then fails the token check.
    if not slash or not token(primary) or not token(secondary):
        raise ExternalAttachmentProfileError("invalid media type")
