"""Parse-side strict CBOR walker (Task A2b).

A defence-in-depth byte-walker that detects duplicate map keys at any
nesting depth WITHOUT first decoding through cbor2 (which would silently
coalesce duplicates in Python `dict`). Mirrors the contract noted in
`trellis/specs/canonical-cbor-profile.md` §2 R4 ("decoder side"): a full
parse-side guard is a conformant defence-in-depth addition.

The walker is intentionally a single forward pass with no recursion-via-
intermediate-values. It tracks encountered key byte-ranges per map frame.

Independence: this module defines its own :class:`CborStrictError` so that
`verify_wos` can import it without a circular dependency.
"""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass, field


class CborStrictError(Exception):
    """Raised on duplicate map keys at any depth, on trailing bytes, or on a reference tag."""


class CborDuplicateKeyError(CborStrictError):
    """A map repeats the key whose canonical encoding is `canonical_key_hex`, at byte `offset`."""

    def __init__(self, canonical_key_hex: str, offset: int) -> None:
        super().__init__(f"duplicate canonical CBOR map key `{canonical_key_hex}` at offset {offset}")
        self.canonical_key_hex = canonical_key_hex


class CborReferenceTagError(CborStrictError):
    """A reference tag (see :data:`REFERENCE_TAGS`) at byte `offset`."""

    def __init__(self, tag: int, offset: int) -> None:
        super().__init__(f"reference tag {tag} at offset {offset}")
        self.offset = offset


# String-reference (25 / 256) and value-sharing (28 / 29) tags make a decoder
# resolve one item into another, so the bytes no longer say what they decode to.
# The canonical profile never emits them and the Rust decoders leave them as
# tags and refuse them; refuse them here, before any decoder can resolve them.
REFERENCE_TAGS = frozenset({25, 28, 29, 256})


def reject_duplicate_canonical_map_keys(data: bytes) -> None:
    """Walk `data` and raise on (a) any duplicate map key at any depth,
    (b) trailing bytes after the root CBOR item, or (c) a reference tag
    (string-reference 25/256, value-sharing 28/29).

    Accepts both definite-length and indefinite-length CBOR (defence-in-depth
    against external producers; canonical Trellis bytes never use indefinite
    length per profile R2).
    """

    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise CborStrictError("input must be bytes-like")
    walker = _Walker(bytes(data))
    walker.walk_item()
    if walker.offset != len(walker.buf):
        raise CborStrictError(
            f"trailing bytes after root CBOR item at offset {walker.offset}"
        )


# ---------------------------------------------------------------------------
# Internal walker. Single forward pass; no value materialisation.
# ---------------------------------------------------------------------------


# Indefinite-length additional-info nibble.
_INDEF = 31
_BREAK_BYTE = 0xFF


@dataclass
class _Walker:
    buf: bytes
    offset: int = 0

    def _read(self, n: int) -> bytes:
        if self.offset + n > len(self.buf):
            raise CborStrictError(
                f"unexpected EOF: need {n} bytes at offset {self.offset}"
            )
        chunk = self.buf[self.offset : self.offset + n]
        self.offset += n
        return chunk

    def _read_byte(self) -> int:
        return self._read(1)[0]

    def _read_argument(self, info: int) -> tuple[int | None, int, int]:
        """Decode the argument that follows the initial byte.

        Returns `(value_or_none_for_indefinite, arg_bytes_consumed, additional_info)`.
        For info 0-23 the value is `info` and no bytes are consumed.
        """

        if info < 24:
            return info, 0, info
        if info == 24:
            return self._read_byte(), 1, info
        if info == 25:
            return struct.unpack(">H", self._read(2))[0], 2, info
        if info == 26:
            return struct.unpack(">I", self._read(4))[0], 4, info
        if info == 27:
            return struct.unpack(">Q", self._read(8))[0], 8, info
        if info in (28, 29, 30):
            raise CborStrictError(
                f"reserved additional-info {info} at offset {self.offset - 1}"
            )
        # info == 31 → indefinite length sentinel for major types 2/3/4/5
        return None, 0, info

    # ------------------------------------------------------------------
    # walk_item: dispatch by major type, advancing `offset` past one item.
    # ------------------------------------------------------------------

    def walk_item(self) -> None:
        initial_offset = self.offset
        initial = self._read_byte()
        major = initial >> 5
        info = initial & 0x1F

        if major == 0 or major == 1:
            # uint / negint: argument bytes only, no further payload.
            self._read_argument(info)
            return

        if major == 2 or major == 3:
            # byte string / text string.
            length, _, ai = self._read_argument(info)
            if ai == _INDEF:
                # Indefinite-length chunks of bstr/tstr until break.
                self._walk_indefinite_string_chunks(expected_major=major)
                return
            assert length is not None
            self._read(length)
            return

        if major == 4:
            # array.
            count, _, ai = self._read_argument(info)
            if ai == _INDEF:
                while not self._peek_is_break():
                    self.walk_item()
                self._read_byte()  # consume break
                return
            assert count is not None
            for _ in range(count):
                self.walk_item()
            return

        if major == 5:
            # map: track per-frame keys.
            count, _, ai = self._read_argument(info)
            seen: set[bytes] = set()
            if ai == _INDEF:
                while not self._peek_is_break():
                    self._walk_map_entry(seen)
                self._read_byte()  # consume break
                return
            assert count is not None
            for _ in range(count):
                self._walk_map_entry(seen)
            return

        if major == 6:
            # tagged item: argument is the tag number, then one nested item.
            tag, _, _ = self._read_argument(info)
            if tag in REFERENCE_TAGS:
                raise CborReferenceTagError(tag, initial_offset)
            self.walk_item()
            return

        if major == 7:
            # simple values / floats / break.
            # info 20-23: false/true/null/undefined (no argument).
            # info 24: simple value byte.
            # info 25/26/27: f16/f32/f64.
            # info 31: break — should only be consumed by container loops above.
            if info == 31:
                raise CborStrictError(
                    f"unexpected break marker at offset {initial_offset}"
                )
            if info < 24:
                return
            if info == 24:
                self._read(1)
                return
            if info == 25:
                self._read(2)
                return
            if info == 26:
                self._read(4)
                return
            if info == 27:
                self._read(8)
                return
            raise CborStrictError(
                f"reserved simple/float additional-info {info} at offset {initial_offset}"
            )

        raise CborStrictError(
            f"unreachable major type {major} at offset {initial_offset}"
        )

    # ------------------------------------------------------------------
    # Helpers.
    # ------------------------------------------------------------------

    def _peek_is_break(self) -> bool:
        if self.offset >= len(self.buf):
            raise CborStrictError(
                f"unexpected EOF while scanning for break at offset {self.offset}"
            )
        return self.buf[self.offset] == _BREAK_BYTE

    def _walk_map_entry(self, seen: set[bytes]) -> None:
        key_start = self.offset
        self.walk_item()
        key_end = self.offset
        key_bytes = _canonical_key(self.buf[key_start:key_end])
        if key_bytes in seen:
            raise CborDuplicateKeyError(key_bytes.hex(), key_start)
        seen.add(key_bytes)
        # Walk value (which may itself contain nested maps).
        self.walk_item()

    def _walk_indefinite_string_chunks(self, expected_major: int) -> None:
        while not self._peek_is_break():
            initial = self._read_byte()
            major = initial >> 5
            info = initial & 0x1F
            if major != expected_major:
                raise CborStrictError(
                    f"indefinite-length string chunk has wrong major type "
                    f"{major} at offset {self.offset - 1}"
                )
            if info == _INDEF:
                raise CborStrictError(
                    f"nested indefinite-length string at offset {self.offset - 1}"
                )
            length, _, _ = self._read_argument(info)
            assert length is not None
            self._read(length)
        self._read_byte()  # consume break


def _canonical_key(key_bytes: bytes) -> bytes:
    """The key's canonical encoding, compared the way Rust's `decode_cbor_value` compares keys (R4).

    Rust canonicalizes each decoded key before comparing, so this re-encodes the
    key's bytes the same way: integers and lengths in their smallest form,
    indefinite strings joined, nested maps sorted, tags kept as tag number plus
    canonical content, and floats in their smallest lossless width (as
    ciborium writes them). A key that has no canonical encoding, a NaN, ±Inf or
    -0.0 float, refuses the whole item, as Rust refuses it.
    """
    encoded, _ = _canonical_at(key_bytes, 0)
    return encoded


def _head(major: int, value: int) -> bytes:
    if value < 24:
        return bytes([(major << 5) | value])
    for info, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if value < 1 << (8 * size):
            return bytes([(major << 5) | info]) + value.to_bytes(size, "big")
    raise CborStrictError("CBOR argument exceeds 64 bits")


def _argument(buf: bytes, offset: int, info: int) -> tuple[int, int]:
    if info < 24:
        return info, offset
    size = {24: 1, 25: 2, 26: 4, 27: 8}[info]
    return int.from_bytes(buf[offset : offset + size], "big"), offset + size


def _canonical_float(value: float) -> bytes:
    if math.isnan(value) or math.isinf(value):
        raise CborStrictError("CBOR float must be finite for canonical encoding")
    if value == 0.0 and math.copysign(1.0, value) < 0:
        raise CborStrictError("CBOR float must use canonical +0, not -0")
    for prefix, fmt in ((b"\xf9", ">e"), (b"\xfa", ">f")):
        try:
            packed = struct.pack(fmt, value)
        except (OverflowError, struct.error):
            continue
        if struct.unpack(fmt, packed)[0] == value:
            return prefix + packed
    return b"\xfb" + struct.pack(">d", value)


def _canonical_at(buf: bytes, offset: int) -> tuple[bytes, int]:
    """Canonical bytes of the one item at `offset`, which the walker already checked."""
    initial = buf[offset]
    major, info = initial >> 5, initial & 0x1F
    offset += 1
    if major in (0, 1):
        value, offset = _argument(buf, offset, info)
        return _head(major, value), offset
    if major in (2, 3):
        payload = b""
        if info == _INDEF:
            while buf[offset] != _BREAK_BYTE:
                chunk_info = buf[offset] & 0x1F
                length, offset = _argument(buf, offset + 1, chunk_info)
                payload += buf[offset : offset + length]
                offset += length
            offset += 1
        else:
            length, offset = _argument(buf, offset, info)
            payload, offset = buf[offset : offset + length], offset + length
        return _head(major, len(payload)) + payload, offset
    if major in (4, 5):
        items: list[bytes] = []
        if info == _INDEF:
            while buf[offset] != _BREAK_BYTE:
                item, offset = _canonical_at(buf, offset)
                items.append(item)
            offset += 1
        else:
            count, offset = _argument(buf, offset, info)
            for _ in range(count * (2 if major == 5 else 1)):
                item, offset = _canonical_at(buf, offset)
                items.append(item)
        if major == 4:
            return _head(4, len(items)) + b"".join(items), offset
        pairs = sorted(zip(items[0::2], items[1::2]))
        for left, right in zip(pairs, pairs[1:]):
            if left[0] == right[0]:
                raise CborDuplicateKeyError(left[0].hex(), offset)
        return _head(5, len(pairs)) + b"".join(key + value for key, value in pairs), offset
    if major == 6:
        tag, offset = _argument(buf, offset, info)
        item, offset = _canonical_at(buf, offset)
        return _head(6, tag) + item, offset
    if info == 25:
        return _canonical_float(struct.unpack(">e", buf[offset : offset + 2])[0]), offset + 2
    if info == 26:
        return _canonical_float(struct.unpack(">f", buf[offset : offset + 4])[0]), offset + 4
    if info == 27:
        return _canonical_float(struct.unpack(">d", buf[offset : offset + 8])[0]), offset + 8
    if info == 24:
        return bytes(buf[offset - 1 : offset + 1]), offset + 1
    return bytes([initial]), offset
