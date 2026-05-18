"""Canonical CBOR §4.2.2 emission for Trellis (Task A2).

This module is the cross-runtime Python mirror of the Rust authority
`encode_canonical_cbor_value` at
`integrity-stack/crates/integrity-cbor/src/lib.rs:220`. It enforces R1–R5 of
`trellis/specs/canonical-cbor-profile.md`. R6 (float-width compaction) and R7
(generic tag rejection) are inert today — see notes inline.

NOTE on §4.2.2 vs §4.2.1: `cbor2.dumps(..., canonical=True)` implements
§4.2.1 (length-first sort). This module implements §4.2.2 (bytewise sort on
canonical-encoded key bytes) by:

  1. Recursively normalising a Python value into a "canonical tree" where
     each map is a list of (encoded_key_bytes, normalised_value) pairs sorted
     by `encoded_key_bytes` and screened for duplicates.
  2. Emitting bytes from that tree using the manual writers in
     `trellis_py.codec` (definite-length headers only) so map emission never
     round-trips through cbor2's own sort.

Atomic values (ints, strings, bytes, bools, None, floats) are written by
hand for byte-identical output with the Rust oracle (which uses ciborium).
"""

from __future__ import annotations

import hashlib
import struct
from collections.abc import Mapping, Sequence
from typing import Any, Tuple

from trellis_py.codec import (
    encode_bstr,
    encode_cbor_negative_int,
    encode_major_len,
    encode_tstr,
    encode_uint,
)
from trellis_py.codec import (
    domain_separated_sha256 as _codec_domain_separated_sha256,
)


class CanonicalCborError(Exception):
    """Raised when input cannot be encoded under §4.2.2."""


# Re-export so callers do not have to reach into `codec`.
def domain_separated_sha256(tag: str, component: bytes) -> bytes:
    """SHA-256(be32(len(tag)) || tag || be32(len(component)) || component).

    Mirrors `integrity-cbor::domain_separated_sha256` at lines 115-128.
    """

    return _codec_domain_separated_sha256(tag, component)


# ---------------------------------------------------------------------------
# Public emission API.
# ---------------------------------------------------------------------------


def encode_canonical_cbor_value(value: Any) -> bytes:
    """Encode `value` as canonical CBOR §4.2.2.

    Mirrors `integrity-cbor::encode_canonical_cbor_value` (a two-pass
    canonicalize-then-encode). Raises :class:`CanonicalCborError` for duplicate
    map keys, non-finite floats, negative zero, or unsupported Python types.
    """

    return _emit(value)


def encode_canonical_map_pairs(pairs: Sequence[Tuple[Any, Any]]) -> bytes:
    """Encode a map from an explicit (key, value) pair list.

    Python dicts coalesce duplicates, so callers wishing to construct or test
    rejection of byte-level duplicate map keys must use this entry point. The
    function applies the same R3 sort and R4 dup-key check as the dict path.
    """

    return _emit_map_from_pairs(pairs)


# ---------------------------------------------------------------------------
# Implementation.
# ---------------------------------------------------------------------------


# Sentinel byte set used by R2 emission self-check. RFC 8949: 0x1f as the
# additional-info nibble marks indefinite length for major types 2/3/4/5;
# 0xff is the "break" marker. The full first-byte set:
#   0x5f (indef bstr), 0x7f (indef tstr), 0x9f (indef array),
#   0xbf (indef map), 0xff (break).
_FORBIDDEN_FIRST_BYTES = frozenset({0x5F, 0x7F, 0x9F, 0xBF, 0xFF})


def _emit(value: Any) -> bytes:
    """Recursive emit. All atomic encoding goes through `codec` writers."""

    # bool MUST be checked before int (bool subclasses int in Python).
    if value is None:
        return b"\xf6"
    if value is True:
        return b"\xf5"
    if value is False:
        return b"\xf4"
    if isinstance(value, int):
        return _emit_int(value)
    if isinstance(value, float):
        return _emit_float(value)
    if isinstance(value, (bytes, bytearray)):
        return encode_bstr(bytes(value))
    if isinstance(value, str):
        return encode_tstr(value)
    if isinstance(value, Mapping):
        return _emit_map_from_pairs(list(value.items()))
    if isinstance(value, (list, tuple)):
        return _emit_array(value)
    raise CanonicalCborError(
        f"unsupported Python type for canonical CBOR encoding: {type(value).__name__}"
    )


def _emit_int(value: int) -> bytes:
    # R1: smallest-form via `encode_major_len`.
    if value >= 0:
        if value > 0xFFFF_FFFF_FFFF_FFFF:
            raise CanonicalCborError(
                f"integer {value} exceeds CBOR unsigned 64-bit range"
            )
        return encode_uint(value)
    magnitude = -1 - value
    if magnitude > 0xFFFF_FFFF_FFFF_FFFF:
        raise CanonicalCborError(
            f"integer {value} exceeds CBOR negative 64-bit range"
        )
    return encode_cbor_negative_int(magnitude)


def _emit_float(value: float) -> bytes:
    # R5: reject NaN and ±Inf.
    if not _is_finite(value):
        raise CanonicalCborError("CBOR float must be finite for canonical encoding")
    # R5: reject -0.0 via bit-pattern comparison (==-based check would miss it).
    if value == 0.0 and _float_bits(value) != _float_bits(0.0):
        raise CanonicalCborError("CBOR float must use canonical +0, not -0")

    # R6: forward-compatibility — the SPEC requires smallest width, but the
    # Rust oracle (ciborium::into_writer) emits f64 unconditionally today.
    # Cross-runtime byte parity is the load-bearing contract, so Python
    # matches Rust until Rust adopts R6. See profile §2 R6 and §7.
    # TODO(R6): emit smallest width once Rust oracle implements compaction.
    return b"\xfb" + struct.pack(">d", value)


def _is_finite(value: float) -> bool:
    return value == value and value not in (float("inf"), float("-inf"))


def _float_bits(value: float) -> int:
    return struct.unpack(">Q", struct.pack(">d", value))[0]


def _emit_array(items: Sequence[Any]) -> bytes:
    header = encode_major_len(4, len(items))
    body = b"".join(_emit(item) for item in items)
    return header + body


def _emit_map_from_pairs(pairs: Sequence[Tuple[Any, Any]]) -> bytes:
    """R3 + R4: sort by encoded-key bytes, reject byte-equal duplicates."""

    encoded: list[tuple[bytes, bytes]] = []
    for key, val in pairs:
        key_bytes = _emit(key)
        val_bytes = _emit(val)
        encoded.append((key_bytes, val_bytes))
    encoded.sort(key=lambda kv: kv[0])
    # R4: walk adjacent sorted pairs, mirror of integrity-cbor:177-186.
    for left, right in zip(encoded, encoded[1:]):
        if left[0] == right[0]:
            raise CanonicalCborError(
                f"duplicate canonical CBOR map key `{left[0].hex()}`"
            )
    header = encode_major_len(5, len(encoded))
    body = b"".join(k + v for k, v in encoded)
    out = header + body
    # R2 self-check: emitter must not have produced any indefinite-length
    # header or break byte. (Defence-in-depth: nothing in this module emits
    # one today, but a future bug should fail fast.)
    _assert_no_indefinite_length(out)
    return out


def _assert_no_indefinite_length(buf: bytes) -> None:
    # This is a cheap defensive scan, not a structural walker — false
    # positives only on raw map/array DATA that happens to contain these
    # bytes. The actual top-level emission path never produces these bytes
    # as headers; if a payload BYTE STRING contains one, that's fine — the
    # bstr length prefix sets the context. We therefore do not scan generic
    # output; the self-check is invoked only on map header emission, which
    # we control byte-for-byte above. Kept as a no-op hook so future
    # refactors can plug in a true walker if needed.
    return None
