"""dCBOR helpers and Trellis domain-separated SHA-256 (Core §5, §9)."""

from __future__ import annotations

import hashlib
import struct


def encode_major_len(major: int, value: int) -> bytes:
    header = major << 5
    if value <= 23:
        return bytes([header | value])
    if value <= 0xFF:
        return bytes([header | 24, value])
    if value <= 0xFFFF:
        return bytes([header | 25]) + struct.pack(">H", value)
    if value <= 0xFFFF_FFFF:
        return bytes([header | 26]) + struct.pack(">I", value)
    return bytes([header | 27]) + struct.pack(">Q", value)


def encode_bstr(data: bytes) -> bytes:
    return encode_major_len(2, len(data)) + data


def encode_tstr(text: str) -> bytes:
    b = text.encode("utf-8")
    return encode_major_len(3, len(b)) + b


def encode_uint(value: int) -> bytes:
    return encode_major_len(0, value)


def encode_cbor_negative_int(n: int) -> bytes:
    """Encode CBOR negative integer -1 - n (major type 1)."""
    return encode_major_len(1, n)


COSE_SUITE_ID_LABEL_MAGNITUDE = 65_536


def encode_cose_suite_id_label() -> bytes:
    return encode_major_len(1, COSE_SUITE_ID_LABEL_MAGNITUDE)


def domain_separated_preimage(tag: str, component: bytes) -> bytes:
    """be32(len(tag)) || tag || be32(len(component)) || component."""
    return (
        struct.pack(">I", len(tag))
        + tag.encode("utf-8")
        + struct.pack(">I", len(component))
        + component
    )


def domain_separated_sha256(tag: str, component: bytes) -> bytes:
    return hashlib.sha256(domain_separated_preimage(tag, component)).digest()


def sig_structure_bytes(protected_header: bytes, payload: bytes) -> bytes:
    parts = bytearray()
    parts.append(0x84)
    parts.extend(encode_tstr("Signature1"))
    parts.extend(encode_bstr(protected_header))
    parts.append(0x40)
    parts.extend(encode_bstr(payload))
    return bytes(parts)
