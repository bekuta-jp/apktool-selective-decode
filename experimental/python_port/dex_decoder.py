#!/usr/bin/env python3
"""Lightweight DEX decoder for metadata-oriented analysis."""

from __future__ import annotations

from dataclasses import dataclass
import struct
from typing import Dict, List, Tuple


class DexDecodeError(Exception):
    pass


@dataclass
class DexHeader:
    magic: str
    checksum: int
    signature: str
    file_size: int
    header_size: int
    endian_tag: int
    string_ids_size: int
    string_ids_off: int
    type_ids_size: int
    type_ids_off: int
    method_ids_size: int
    method_ids_off: int
    class_defs_size: int
    class_defs_off: int


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _read_uleb128(data: bytes, offset: int) -> Tuple[int, int]:
    value = 0
    shift = 0
    pos = offset
    for _ in range(5):
        b = data[pos]
        pos += 1
        value |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return value, pos
        shift += 7
    raise DexDecodeError("Invalid uleb128 sequence")


def _read_mutf8_string(data: bytes, offset: int) -> str:
    _, pos = _read_uleb128(data, offset)
    end = data.find(b"\x00", pos)
    if end < 0:
        raise DexDecodeError("Unterminated string_data_item")
    raw = data[pos:end]
    return raw.decode("utf-8", errors="replace")


def _parse_header(data: bytes) -> DexHeader:
    if len(data) < 112:
        raise DexDecodeError("File too small for DEX header")

    magic = data[0:8]
    if not magic.startswith(b"dex\n"):
        raise DexDecodeError("Not a DEX file")

    checksum = _u32(data, 8)
    signature = data[12:32].hex()
    file_size = _u32(data, 32)
    header_size = _u32(data, 36)
    endian_tag = _u32(data, 40)

    string_ids_size = _u32(data, 56)
    string_ids_off = _u32(data, 60)
    type_ids_size = _u32(data, 64)
    type_ids_off = _u32(data, 68)
    method_ids_size = _u32(data, 88)
    method_ids_off = _u32(data, 92)
    class_defs_size = _u32(data, 96)
    class_defs_off = _u32(data, 100)

    return DexHeader(
        magic=magic.decode("ascii", errors="replace").rstrip("\x00"),
        checksum=checksum,
        signature=signature,
        file_size=file_size,
        header_size=header_size,
        endian_tag=endian_tag,
        string_ids_size=string_ids_size,
        string_ids_off=string_ids_off,
        type_ids_size=type_ids_size,
        type_ids_off=type_ids_off,
        method_ids_size=method_ids_size,
        method_ids_off=method_ids_off,
        class_defs_size=class_defs_size,
        class_defs_off=class_defs_off,
    )


def decode_dex(data: bytes, preview_limit: int = 32) -> Dict[str, object]:
    header = _parse_header(data)

    strings: List[str] = []
    for i in range(header.string_ids_size):
        item_off = header.string_ids_off + i * 4
        if item_off + 4 > len(data):
            raise DexDecodeError("Out of range string_id")
        str_off = _u32(data, item_off)
        if str_off >= len(data):
            raise DexDecodeError("Out of range string_data")
        strings.append(_read_mutf8_string(data, str_off))

    type_descriptors: List[str] = []
    for i in range(header.type_ids_size):
        item_off = header.type_ids_off + i * 4
        if item_off + 4 > len(data):
            raise DexDecodeError("Out of range type_id")
        descriptor_idx = _u32(data, item_off)
        if descriptor_idx >= len(strings):
            type_descriptors.append("<invalid>")
        else:
            type_descriptors.append(strings[descriptor_idx])

    classes: List[str] = []
    for i in range(header.class_defs_size):
        item_off = header.class_defs_off + i * 32
        if item_off + 32 > len(data):
            raise DexDecodeError("Out of range class_def")
        class_idx = _u32(data, item_off)
        if class_idx >= len(type_descriptors):
            classes.append("<invalid>")
        else:
            classes.append(type_descriptors[class_idx])

    methods: List[Dict[str, object]] = []
    for i in range(min(header.method_ids_size, preview_limit)):
        item_off = header.method_ids_off + i * 8
        if item_off + 8 > len(data):
            break
        class_idx = _u16(data, item_off)
        proto_idx = _u16(data, item_off + 2)
        name_idx = _u32(data, item_off + 4)

        class_name = type_descriptors[class_idx] if class_idx < len(type_descriptors) else "<invalid>"
        method_name = strings[name_idx] if name_idx < len(strings) else "<invalid>"

        methods.append(
            {
                "index": i,
                "class": class_name,
                "name": method_name,
                "proto_index": proto_idx,
            }
        )

    return {
        "header": {
            "magic": header.magic,
            "checksum": header.checksum,
            "signature": header.signature,
            "file_size": header.file_size,
            "header_size": header.header_size,
            "endian_tag": header.endian_tag,
            "string_ids_size": header.string_ids_size,
            "type_ids_size": header.type_ids_size,
            "method_ids_size": header.method_ids_size,
            "class_defs_size": header.class_defs_size,
        },
        "preview": {
            "strings": strings[:preview_limit],
            "type_descriptors": type_descriptors[:preview_limit],
            "classes": classes[:preview_limit],
            "methods": methods,
        },
        "counts": {
            "strings": len(strings),
            "types": len(type_descriptors),
            "classes": len(classes),
            "methods": header.method_ids_size,
        },
    }
