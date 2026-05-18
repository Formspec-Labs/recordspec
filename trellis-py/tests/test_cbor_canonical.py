"""Conformance tests for §4.2.2 canonical CBOR encoder (Task A2).

Vectors V1–V14 are pinned in `trellis/specs/canonical-cbor-profile.md §5` against
the Rust oracle at
`integrity-stack/crates/integrity-cbor/src/lib.rs::encode_canonical_cbor_value`.
"""

from __future__ import annotations

import hashlib
import struct
from collections import OrderedDict

import pytest

from trellis_py._cbor_canonical import (
    CanonicalCborError,
    domain_separated_sha256,
    encode_canonical_cbor_value,
)


def _h(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str.replace(" ", ""))


# ---------------------------------------------------------------------------
# R1 — Integer smallest-form (V1–V6).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected_hex", "label"),
    [
        (0, "00", "V1 unsigned 0"),
        (23, "17", "V2 unsigned 23"),
        (24, "18 18", "V3 unsigned 24"),
        (256, "19 01 00", "V4 unsigned 256"),
        (-1, "20", "V5 negative -1"),
        (-25, "38 18", "V6 negative -25"),
        (65_536, "1a 00 01 00 00", "R1 4-byte boundary"),
        (4_294_967_296, "1b 00 00 00 01 00 00 00 00", "R1 8-byte boundary"),
        (255, "18 ff", "R1 1-byte max"),
        (-256, "38 ff", "R1 negative 1-byte max"),
    ],
)
def test_integer_smallest_form(value: int, expected_hex: str, label: str) -> None:
    assert encode_canonical_cbor_value(value) == _h(expected_hex), label


# ---------------------------------------------------------------------------
# R2 + R3 — empty containers, single text-key map.
# ---------------------------------------------------------------------------


def test_v7_empty_map() -> None:
    assert encode_canonical_cbor_value({}) == _h("a0")


def test_v8_empty_array() -> None:
    assert encode_canonical_cbor_value([]) == _h("80")


def test_v9_single_text_key_map() -> None:
    assert encode_canonical_cbor_value({"a": 1}) == _h("a1 61 61 01")


# ---------------------------------------------------------------------------
# R3 — bytewise sort on encoded key bytes (§4.2.2, not §4.2.1).
# ---------------------------------------------------------------------------


def test_v10_mixed_int_and_text_key_sort_bytewise() -> None:
    # Integer 0 encodes as 0x00 (major 0). Empty text "" encodes as 0x60.
    # Bytewise: 0x00 < 0x60, so int key sorts first.
    # Use OrderedDict in REVERSE-of-canonical order to prove sort, not insertion order, drives output.
    src = OrderedDict()
    src[""] = 2
    src[0] = 1
    assert encode_canonical_cbor_value(src) == _h("a2 00 01 60 02")


def test_v14_nested_map_inner_keys_sorted() -> None:
    src = {"outer": OrderedDict([("z", 1), ("a", 2)])}
    assert encode_canonical_cbor_value(src) == _h(
        "a1 65 6f 75 74 65 72 a2 61 61 02 61 7a 01"
    )


def test_section_6_example_1_text_keys_bytewise_not_length_first() -> None:
    # From profile §6 Example 1: {"b": 2, "aa": 1} sorts to ("aa", "b") under §4.2.2
    # because 0x61 (first byte of "b"'s 61 62) < 0x62 wait... key "b" encodes 0x61 0x62,
    # key "aa" encodes 0x62 0x61 0x61. Bytewise compare: 0x61 < 0x62, so "b" sorts first.
    # NOTE: profile §6 Example 1 actually claims "aa" sorts first.
    # Re-reading the profile: key "b" is len 1, prefix byte 0x61 (text len 1).
    #                          key "aa" is len 2, prefix byte 0x62 (text len 2).
    # bytewise: 0x61 < 0x62 → "b" sorts first under §4.2.2 too.
    # Profile §6 Example 1 has a contradiction. Use the actual bytewise outcome.
    src = OrderedDict([("b", 2), ("aa", 1)])
    out = encode_canonical_cbor_value(src)
    # Confirm §4.2.2 bytewise: "b" (61 62) < "aa" (62 61 61)
    assert out == _h("a2 61 62 02 62 61 61 01")


def test_byte_string_keys_sort_before_text_string_keys() -> None:
    # bstr empty encodes 0x40 (major 2). tstr empty encodes 0x60 (major 3).
    # Bytewise: 0x40 < 0x60.
    src = OrderedDict()
    src[""] = "text"
    src[b""] = "bytes"
    out = encode_canonical_cbor_value(src)
    assert out == _h("a2 40 65 62 79 74 65 73 60 64 74 65 78 74")


def test_empty_byte_string_and_empty_text_string_keys() -> None:
    src = OrderedDict([(b"", 1), ("", 2)])
    out = encode_canonical_cbor_value(src)
    # 0x40 < 0x60, so bstr first
    assert out == _h("a2 40 01 60 02")


# ---------------------------------------------------------------------------
# R4 — Duplicate key rejection.
# ---------------------------------------------------------------------------


def test_v11_duplicate_key_rejected_via_pairs_arg() -> None:
    from trellis_py._cbor_canonical import encode_canonical_map_pairs

    with pytest.raises(CanonicalCborError, match="duplicate canonical CBOR map key"):
        encode_canonical_map_pairs([("a", 1), ("a", 2)])


# ---------------------------------------------------------------------------
# R5 — Non-finite floats and -0.0 rejected.
# ---------------------------------------------------------------------------


def test_v12_nan_rejected() -> None:
    with pytest.raises(CanonicalCborError, match="finite"):
        encode_canonical_cbor_value(float("nan"))


def test_positive_infinity_rejected() -> None:
    with pytest.raises(CanonicalCborError, match="finite"):
        encode_canonical_cbor_value(float("inf"))


def test_negative_infinity_rejected() -> None:
    with pytest.raises(CanonicalCborError, match="finite"):
        encode_canonical_cbor_value(float("-inf"))


def test_v13_negative_zero_rejected() -> None:
    with pytest.raises(CanonicalCborError, match=r"\+0"):
        encode_canonical_cbor_value(-0.0)


def test_positive_zero_accepted() -> None:
    # Positive zero is allowed. Per R6 the spec asks smallest width; the
    # Rust oracle today emits 8-byte. Document and accept either today; the
    # bytes MUST match the Rust oracle for cross-runtime parity.
    out = encode_canonical_cbor_value(0.0)
    # Rust ciborium emits f64 as fb 00 00 00 00 00 00 00 00.
    assert out == _h("fb 00 00 00 00 00 00 00 00")


# ---------------------------------------------------------------------------
# Other primitives.
# ---------------------------------------------------------------------------


def test_text_string_encoding() -> None:
    assert encode_canonical_cbor_value("hello") == _h("65 68 65 6c 6c 6f")


def test_byte_string_encoding() -> None:
    assert encode_canonical_cbor_value(b"\x01\x02\x03") == _h("43 01 02 03")


def test_null_encoding() -> None:
    assert encode_canonical_cbor_value(None) == _h("f6")


def test_true_encoding() -> None:
    assert encode_canonical_cbor_value(True) == _h("f5")


def test_false_encoding() -> None:
    assert encode_canonical_cbor_value(False) == _h("f4")


def test_array_with_mixed_elements() -> None:
    assert encode_canonical_cbor_value([1, "a", b"\x01"]) == _h("83 01 61 61 41 01")


# ---------------------------------------------------------------------------
# R2 — emitter never produces indefinite-length headers (self-check).
# ---------------------------------------------------------------------------


def test_no_indefinite_length_headers_in_output() -> None:
    # Build a nested value that would tempt indefinite encoding in some libs.
    src = {"a": [1, 2, 3], "b": {"c": b"\x00"}}
    out = encode_canonical_cbor_value(src)
    forbidden = {0x5F, 0x7F, 0x9F, 0xBF, 0xFF}
    for byte in out:
        assert byte not in forbidden, (
            f"indefinite-length / break marker 0x{byte:02x} in canonical output"
        )


# ---------------------------------------------------------------------------
# domain_separated_sha256 — bit-exact mirror of integrity-cbor:115-128.
# ---------------------------------------------------------------------------


def test_domain_separated_sha256_matches_rust_formula() -> None:
    tag = "trellis-export-attempt-v1"
    component = b"hello"
    expected = hashlib.sha256(
        struct.pack(">I", len(tag))
        + tag.encode("utf-8")
        + struct.pack(">I", len(component))
        + component
    ).digest()
    assert domain_separated_sha256(tag, component) == expected
    assert len(domain_separated_sha256(tag, component)) == 32


def test_domain_separated_sha256_distinct_for_different_tags() -> None:
    a = domain_separated_sha256("tag-one", b"x")
    b = domain_separated_sha256("tag-two", b"x")
    assert a != b
