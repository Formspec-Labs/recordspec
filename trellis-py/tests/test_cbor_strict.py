"""Parse-side duplicate-key rejection (Task A2b).

A byte-walker that rejects duplicate canonical map keys at any nesting depth
WITHOUT first decoding (Python dicts would coalesce duplicates).
"""

from __future__ import annotations

import pytest

from trellis_py._cbor_strict import (
    CborStrictError,
    reject_duplicate_canonical_map_keys,
)


def _h(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str.replace(" ", ""))


# ---------------------------------------------------------------------------
# Valid input — must NOT raise.
# ---------------------------------------------------------------------------


def test_valid_canonical_passes() -> None:
    # {"a": "X"} — single entry, definite length.
    # a1 (map(1))   61 61 ("a")   61 58 ("X")
    reject_duplicate_canonical_map_keys(_h("a1 61 61 61 58"))


def test_empty_map_passes() -> None:
    reject_duplicate_canonical_map_keys(_h("a0"))


def test_empty_array_passes() -> None:
    reject_duplicate_canonical_map_keys(_h("80"))


def test_canonical_two_distinct_keys_passes() -> None:
    # {"a": 1, "b": 2} canonical → a2 61 61 01 61 62 02
    reject_duplicate_canonical_map_keys(_h("a2 61 61 01 61 62 02"))


def test_nested_distinct_keys_passes() -> None:
    # {"outer": {"a": 1}} → a1 65 6f 75 74 65 72 a1 61 61 01
    reject_duplicate_canonical_map_keys(_h("a1 65 6f 75 74 65 72 a1 61 61 01"))


def test_byte_string_value_with_nested_map_passes() -> None:
    # {"k": h'01 02 03'} → a1 61 6b 43 01 02 03
    reject_duplicate_canonical_map_keys(_h("a1 61 6b 43 01 02 03"))


def test_array_of_maps_passes() -> None:
    # [{"a": 1}, {"a": 2}] — duplicate "a" across SIBLING maps is fine; only same-map dups are rejected.
    # 82 a1 61 61 01 a1 61 61 02
    reject_duplicate_canonical_map_keys(_h("82 a1 61 61 01 a1 61 61 02"))


# ---------------------------------------------------------------------------
# Duplicate key rejection — root, nested, indefinite.
# ---------------------------------------------------------------------------


def test_root_duplicate_text_key_explicitly_rejected() -> None:
    # {"a": 1, "a": 2}  manual definite-length map(2): a2 61 61 01 61 61 02
    data = _h("a2 61 61 01 61 61 02")
    with pytest.raises(CborStrictError, match="duplicate"):
        reject_duplicate_canonical_map_keys(data)


def test_root_duplicate_integer_key_explicitly_rejected() -> None:
    # {0: 1, 0: 2} → a2 00 01 00 02
    data = _h("a2 00 01 00 02")
    with pytest.raises(CborStrictError, match="duplicate"):
        reject_duplicate_canonical_map_keys(data)


def test_nested_duplicate_key_explicitly_rejected() -> None:
    # {"outer": {"a": 1, "a": 2}}
    # a1 65 6f 75 74 65 72 a2 61 61 01 61 61 02
    data = _h("a1 65 6f 75 74 65 72 a2 61 61 01 61 61 02")
    with pytest.raises(CborStrictError, match="duplicate"):
        reject_duplicate_canonical_map_keys(data)


def test_duplicate_inside_array_element_rejected() -> None:
    # [{"a": 1, "a": 2}]  → 81 a2 61 61 01 61 61 02
    data = _h("81 a2 61 61 01 61 61 02")
    with pytest.raises(CborStrictError, match="duplicate"):
        reject_duplicate_canonical_map_keys(data)


def test_indefinite_length_map_duplicate_rejected() -> None:
    # bf 61 61 18 58 61 61 18 59 ff   = {_ "a": 88, "a": 89 _}
    data = _h("bf 61 61 18 58 61 61 18 59 ff")
    with pytest.raises(CborStrictError, match="duplicate"):
        reject_duplicate_canonical_map_keys(data)


def test_indefinite_length_map_distinct_keys_passes() -> None:
    # bf 61 61 01 61 62 02 ff   = {_ "a": 1, "b": 2 _}
    reject_duplicate_canonical_map_keys(_h("bf 61 61 01 61 62 02 ff"))


# ---------------------------------------------------------------------------
# Trailing bytes after root item.
# ---------------------------------------------------------------------------


def test_trailing_bytes_after_root_item_rejected() -> None:
    # 01 (uint 1) followed by spurious 02
    with pytest.raises(CborStrictError, match="trailing"):
        reject_duplicate_canonical_map_keys(_h("01 02"))


def test_trailing_bytes_after_map_rejected() -> None:
    # {"a": 1} followed by spurious 00
    with pytest.raises(CborStrictError, match="trailing"):
        reject_duplicate_canonical_map_keys(_h("a1 61 61 01 00"))


# ---------------------------------------------------------------------------
# Indefinite-length text/byte/array containers walk correctly.
# ---------------------------------------------------------------------------


def test_indefinite_length_array_with_inner_dup_map_rejected() -> None:
    # 9f a2 61 61 01 61 61 02 ff
    data = _h("9f a2 61 61 01 61 61 02 ff")
    with pytest.raises(CborStrictError, match="duplicate"):
        reject_duplicate_canonical_map_keys(data)


def test_indefinite_length_text_chunks_skip_correctly() -> None:
    # 7f 61 61 61 62 ff   indefinite text "ab" inside a singleton map value
    # Wrap in {"k": <indef-text>} → a1 61 6b 7f 61 61 61 62 ff
    data = _h("a1 61 6b 7f 61 61 61 62 ff")
    reject_duplicate_canonical_map_keys(data)


def test_tag_wrapped_map_walks_into_inner_map() -> None:
    # tag(18, {"a": 1, "a": 2}) = d2 a2 61 61 01 61 61 02
    data = _h("d2 a2 61 61 01 61 61 02")
    with pytest.raises(CborStrictError, match="duplicate"):
        reject_duplicate_canonical_map_keys(data)
