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

import struct
from dataclasses import dataclass, field


class CborStrictError(Exception):
    """Raised on duplicate map keys at any depth, or on trailing bytes."""


def reject_duplicate_canonical_map_keys(data: bytes) -> None:
    """Walk `data` and raise on (a) any duplicate map key at any depth or
    (b) trailing bytes after the root CBOR item.

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
            self._read_argument(info)
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
        key_bytes = self.buf[key_start:key_end]
        if key_bytes in seen:
            raise CborStrictError(
                f"duplicate canonical CBOR map key `{key_bytes.hex()}` "
                f"at offset {key_start}"
            )
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
