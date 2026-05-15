"""Deterministic export ZIP (Core §18; aligns with `integrity-bundle` / `trellis-export-writer`)."""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass


ZIP_VERSION_NEEDED = 20
ZIP_VERSION_MADE_BY = 20
ZIP_GENERAL_PURPOSE_BITS = 0
ZIP_COMPRESSION_STORED = 0
ZIP_FIXED_TIME = 0
ZIP_FIXED_DATE = (1 << 5) | 1
ZIP_LOCAL_FILE_HEADER_SIGNATURE = 0x04034B50
ZIP_CENTRAL_DIRECTORY_SIGNATURE = 0x02014B50
ZIP_END_OF_CENTRAL_DIRECTORY_SIGNATURE = 0x06054B50


@dataclass(frozen=True)
class ExportEntry:
    path: str
    bytes: bytes


class ExportError(Exception):
    pass


def _crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def _push_u16(buf: bytearray, v: int) -> None:
    buf.extend(struct.pack("<H", v))


def _push_u32(buf: bytearray, v: int) -> None:
    buf.extend(struct.pack("<I", v))


def export_to_zip_bytes(entries: list[ExportEntry]) -> bytes:
    items = sorted(entries, key=lambda e: e.path)
    for a, b in zip(items, items[1:]):
        if a.path == b.path:
            raise ExportError(f"duplicate export path `{a.path}`")
    local_sections: list[bytes] = []
    central_sections: list[bytes] = []
    offset = 0
    for entry in items:
        if not entry.path.isascii():
            raise ExportError(f"export path `{entry.path}` is not ASCII")
        path_b = entry.path.encode("ascii")
        if len(entry.bytes) > 0xFFFF_FFFF:
            raise ExportError(f"entry `{entry.path}` exceeds ZIP32 size bounds")
        crc = _crc32(entry.bytes)
        csize = len(entry.bytes)
        if csize > 0xFFFF_FFFF:
            raise ExportError("compressed size overflow")
        path_len = len(path_b)
        if path_len > 0xFFFF:
            raise ExportError("path too long")
        local_offset = offset
        local = bytearray()
        _push_u32(local, ZIP_LOCAL_FILE_HEADER_SIGNATURE)
        _push_u16(local, ZIP_VERSION_NEEDED)
        _push_u16(local, ZIP_GENERAL_PURPOSE_BITS)
        _push_u16(local, ZIP_COMPRESSION_STORED)
        _push_u16(local, ZIP_FIXED_TIME)
        _push_u16(local, ZIP_FIXED_DATE)
        _push_u32(local, crc)
        _push_u32(local, csize)
        _push_u32(local, csize)
        _push_u16(local, path_len)
        _push_u16(local, 0)
        local.extend(path_b)
        local.extend(entry.bytes)
        central = bytearray()
        _push_u32(central, ZIP_CENTRAL_DIRECTORY_SIGNATURE)
        _push_u16(central, ZIP_VERSION_MADE_BY)
        _push_u16(central, ZIP_VERSION_NEEDED)
        _push_u16(central, ZIP_GENERAL_PURPOSE_BITS)
        _push_u16(central, ZIP_COMPRESSION_STORED)
        _push_u16(central, ZIP_FIXED_TIME)
        _push_u16(central, ZIP_FIXED_DATE)
        _push_u32(central, crc)
        _push_u32(central, csize)
        _push_u32(central, csize)
        _push_u16(central, path_len)
        _push_u16(central, 0)
        _push_u16(central, 0)
        _push_u16(central, 0)
        _push_u16(central, 0)
        _push_u32(central, 0)
        _push_u32(central, local_offset)
        central.extend(path_b)
        offset += len(local)
        local_sections.append(bytes(local))
        central_sections.append(bytes(central))
    central_directory_offset = offset
    central_directory_size = sum(len(s) for s in central_sections)
    entry_count = len(items)
    if entry_count > 0xFFFF:
        raise ExportError("archive exceeds ZIP32 entry-count bounds")
    archive = bytearray()
    for s in local_sections:
        archive.extend(s)
    for s in central_sections:
        archive.extend(s)
    _push_u32(archive, ZIP_END_OF_CENTRAL_DIRECTORY_SIGNATURE)
    _push_u16(archive, 0)
    _push_u16(archive, 0)
    _push_u16(archive, entry_count)
    _push_u16(archive, entry_count)
    _push_u32(archive, central_directory_size)
    _push_u32(archive, central_directory_offset)
    _push_u16(archive, 0)
    return bytes(archive)
