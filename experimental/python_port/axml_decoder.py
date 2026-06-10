#!/usr/bin/env python3
"""Minimal Android binary XML (AXML) decoder for manifest-oriented use cases."""

from __future__ import annotations

from dataclasses import dataclass
import html
import struct
from typing import Callable, List, Optional, Sequence, Tuple


RES_XML_TYPE = 0x0003
RES_STRING_POOL_TYPE = 0x0001
RES_XML_RESOURCE_MAP_TYPE = 0x0180
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_CDATA_TYPE = 0x0104

TYPE_NULL = 0x00
TYPE_REFERENCE = 0x01
TYPE_ATTRIBUTE = 0x02
TYPE_STRING = 0x03
TYPE_FLOAT = 0x04
TYPE_DIMENSION = 0x05
TYPE_FRACTION = 0x06
TYPE_DYNAMIC_REFERENCE = 0x07
TYPE_DYNAMIC_ATTRIBUTE = 0x08
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12
TYPE_FIRST_COLOR_INT = 0x1C
TYPE_LAST_COLOR_INT = 0x1F

UTF8_FLAG = 0x00000100
NO_INDEX = 0xFFFFFFFF

ResourceResolver = Callable[[int], Optional[str]]
AttributeValueResolver = Callable[[int, int, int], Optional[str]]


class AxmlDecodeError(Exception):
    pass


@dataclass
class StartEvent:
    depth: int
    tag: str
    attrs: Sequence[Tuple[str, str]]
    namespaces: Sequence[Tuple[str, str]]


@dataclass
class EndEvent:
    depth: int
    tag: str


@dataclass
class TextEvent:
    depth: int
    text: str


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _i32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<i", data, offset)[0]


def _read_length8(data: bytes, offset: int) -> Tuple[int, int]:
    first = data[offset]
    if first & 0x80:
        return ((first & 0x7F) << 8) | data[offset + 1], offset + 2
    return first, offset + 1


def _read_length16(data: bytes, offset: int) -> Tuple[int, int]:
    first = _u16(data, offset)
    if first & 0x8000:
        second = _u16(data, offset + 2)
        return ((first & 0x7FFF) << 16) | second, offset + 4
    return first, offset + 2


class StringPool:
    def __init__(self, strings: Sequence[str]) -> None:
        self._strings = list(strings)

    def get(self, idx: int) -> str:
        if idx == NO_INDEX or idx < 0:
            return ""
        if idx >= len(self._strings):
            return ""
        return self._strings[idx]


def _parse_string_pool(data: bytes, chunk_off: int, header_size: int, chunk_size: int) -> StringPool:
    if header_size < 28:
        raise AxmlDecodeError("Invalid string pool header size")

    string_count, style_count, flags, strings_start, styles_start = struct.unpack_from(
        "<IIIII", data, chunk_off + 8
    )

    _ = style_count
    _ = styles_start

    offsets_off = chunk_off + header_size
    strings: List[str] = []

    for i in range(string_count):
        rel_off = _u32(data, offsets_off + i * 4)
        str_off = chunk_off + strings_start + rel_off
        if str_off >= chunk_off + chunk_size:
            strings.append("")
            continue

        if flags & UTF8_FLAG:
            _, p = _read_length8(data, str_off)
            byte_len, p = _read_length8(data, p)
            raw = data[p : p + byte_len]
            strings.append(raw.decode("utf-8", errors="replace"))
        else:
            char_len, p = _read_length16(data, str_off)
            byte_len = char_len * 2
            raw = data[p : p + byte_len]
            strings.append(raw.decode("utf-16le", errors="replace"))

    return StringPool(strings)


def _format_typed_value(
    value_type: int,
    value_data: int,
    pool: StringPool,
    resource_resolver: Optional[ResourceResolver],
) -> str:
    if value_type == TYPE_NULL:
        return ""
    if value_type in {TYPE_REFERENCE, TYPE_DYNAMIC_REFERENCE}:
        if resource_resolver is not None:
            resolved = resource_resolver(value_data)
            if resolved:
                return resolved
        return "@0x%08x" % value_data
    if value_type in {TYPE_ATTRIBUTE, TYPE_DYNAMIC_ATTRIBUTE}:
        return "?0x%08x" % value_data
    if value_type == TYPE_STRING:
        return pool.get(value_data)
    if value_type == TYPE_FLOAT:
        value = struct.unpack("<f", struct.pack("<I", value_data))[0]
        for precision in range(1, 10):
            candidate = format(value, f".{precision}g")
            if struct.pack("<f", float(candidate)) == struct.pack("<f", value):
                return candidate
        return format(value, ".9g")
    if value_type == TYPE_DIMENSION:
        return "0x%08x" % value_data
    if value_type == TYPE_FRACTION:
        return "0x%08x" % value_data
    if value_type == TYPE_INT_DEC:
        return str(_i32(struct.pack("<I", value_data), 0))
    if value_type == TYPE_INT_HEX:
        return "0x%x" % value_data
    if value_type == TYPE_INT_BOOLEAN:
        return "true" if value_data != 0 else "false"
    if TYPE_FIRST_COLOR_INT <= value_type <= TYPE_LAST_COLOR_INT:
        return "#%08x" % value_data
    return "0x%08x" % value_data


def _lookup_prefix(uri: str, ns_stack: Sequence[Tuple[str, str]]) -> str:
    for prefix, ns_uri in reversed(ns_stack):
        if ns_uri == uri:
            return prefix
    return ""


def decode_axml(
    xml_bytes: bytes,
    resource_resolver: Optional[ResourceResolver] = None,
    attribute_value_resolver: Optional[AttributeValueResolver] = None,
    apktool_compatible: bool = False,
) -> str:
    if len(xml_bytes) < 8:
        raise AxmlDecodeError("Input too small")

    root_type, root_header_size, root_size = struct.unpack_from("<HHI", xml_bytes, 0)
    if root_type != RES_XML_TYPE:
        raise AxmlDecodeError("Not an AXML document")
    if root_header_size < 8 or root_size > len(xml_bytes):
        raise AxmlDecodeError("Invalid root header")

    off = root_header_size
    pool: Optional[StringPool] = None
    resource_map: List[int] = []
    ns_stack: List[Tuple[str, str]] = []

    events: List[object] = []
    depth = 0

    while off + 8 <= root_size:
        chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", xml_bytes, off)
        if chunk_size < 8 or off + chunk_size > root_size:
            raise AxmlDecodeError("Corrupt chunk header")

        if chunk_type == RES_STRING_POOL_TYPE:
            pool = _parse_string_pool(xml_bytes, off, header_size, chunk_size)
        elif chunk_type == RES_XML_RESOURCE_MAP_TYPE:
            resource_map.clear()
            p = off + header_size
            while p + 4 <= off + chunk_size:
                resource_map.append(_u32(xml_bytes, p))
                p += 4
        elif chunk_type in {
            RES_XML_START_NAMESPACE_TYPE,
            RES_XML_END_NAMESPACE_TYPE,
            RES_XML_START_ELEMENT_TYPE,
            RES_XML_END_ELEMENT_TYPE,
            RES_XML_CDATA_TYPE,
        }:
            if pool is None:
                raise AxmlDecodeError("String pool must appear before node chunks")

            ext_off = off + header_size

            if chunk_type == RES_XML_START_NAMESPACE_TYPE:
                prefix_idx = _u32(xml_bytes, ext_off)
                uri_idx = _u32(xml_bytes, ext_off + 4)
                ns_stack.append((pool.get(prefix_idx), pool.get(uri_idx)))

            elif chunk_type == RES_XML_END_NAMESPACE_TYPE:
                prefix_idx = _u32(xml_bytes, ext_off)
                uri_idx = _u32(xml_bytes, ext_off + 4)
                prefix = pool.get(prefix_idx)
                uri = pool.get(uri_idx)
                for i in range(len(ns_stack) - 1, -1, -1):
                    if ns_stack[i] == (prefix, uri):
                        del ns_stack[i]
                        break

            elif chunk_type == RES_XML_START_ELEMENT_TYPE:
                ns_idx, name_idx = struct.unpack_from("<II", xml_bytes, ext_off)
                attr_start, attr_size, attr_count = struct.unpack_from("<HHH", xml_bytes, ext_off + 8)

                tag_name = pool.get(name_idx)
                if ns_idx != NO_INDEX:
                    uri = pool.get(ns_idx)
                    prefix = _lookup_prefix(uri, ns_stack)
                    if prefix:
                        tag_name = f"{prefix}:{tag_name}"

                attrs: List[Tuple[str, str]] = []
                attr_off = ext_off + attr_start
                for i in range(attr_count):
                    entry_off = attr_off + i * attr_size
                    a_ns, a_name, a_raw = struct.unpack_from("<III", xml_bytes, entry_off)
                    _, _, value_type, value_data = struct.unpack_from("<HBBI", xml_bytes, entry_off + 12)

                    attr_name = pool.get(a_name)
                    if a_ns != NO_INDEX:
                        uri = pool.get(a_ns)
                        prefix = _lookup_prefix(uri, ns_stack)
                        if prefix:
                            attr_name = f"{prefix}:{attr_name}"

                    if a_raw != NO_INDEX:
                        attr_value = pool.get(a_raw)
                    else:
                        attr_resource_id = resource_map[a_name] if a_name < len(resource_map) else 0
                        attr_value = None
                        if attribute_value_resolver is not None and attr_resource_id:
                            attr_value = attribute_value_resolver(
                                attr_resource_id, value_type, value_data
                            )
                        if attr_value is None:
                            attr_value = _format_typed_value(
                                value_type, value_data, pool, resource_resolver
                            )

                    if not attr_name and a_name < len(resource_map):
                        attr_name = "res_0x%08x" % resource_map[a_name]

                    if (
                        apktool_compatible
                        and tag_name == "manifest"
                        and attr_name.rsplit(":", 1)[-1] in {"versionCode", "versionName"}
                    ):
                        continue
                    attrs.append((attr_name, attr_value))

                events.append(StartEvent(depth=depth, tag=tag_name, attrs=attrs, namespaces=list(ns_stack)))
                depth += 1

            elif chunk_type == RES_XML_END_ELEMENT_TYPE:
                depth = max(0, depth - 1)
                ns_idx, name_idx = struct.unpack_from("<II", xml_bytes, ext_off)
                tag_name = pool.get(name_idx)
                if ns_idx != NO_INDEX:
                    uri = pool.get(ns_idx)
                    prefix = _lookup_prefix(uri, ns_stack)
                    if prefix:
                        tag_name = f"{prefix}:{tag_name}"
                events.append(EndEvent(depth=depth, tag=tag_name))

            elif chunk_type == RES_XML_CDATA_TYPE:
                text_idx = _u32(xml_bytes, ext_off)
                text = pool.get(text_idx)
                if text:
                    events.append(TextEvent(depth=depth, text=text))

        off += chunk_size

    if apktool_compatible:
        filtered: List[object] = []
        skipped_depth: Optional[int] = None
        for event in events:
            if skipped_depth is not None:
                if isinstance(event, EndEvent) and event.depth == skipped_depth:
                    skipped_depth = None
                continue
            if isinstance(event, StartEvent) and event.tag == "uses-sdk":
                skipped_depth = event.depth
                continue
            filtered.append(event)
        events = filtered

    lines = ['<?xml version="1.0" encoding="utf-8"?>']
    root_ns_written = False
    event_index = 0

    while event_index < len(events):
        event = events[event_index]
        if isinstance(event, StartEvent):
            indent = "    " * event.depth
            parts = [f"{indent}<{event.tag}"]

            if not root_ns_written:
                seen = set()
                for prefix, uri in event.namespaces:
                    if not uri or uri in seen:
                        continue
                    seen.add(uri)
                    if prefix:
                        parts.append(f' xmlns:{prefix}="{html.escape(uri, quote=True)}"')
                    else:
                        parts.append(f' xmlns="{html.escape(uri, quote=True)}"')
                root_ns_written = True

            attrs = event.attrs
            if apktool_compatible:
                attrs = sorted(attrs, key=lambda item: item[0].rsplit(":", 1)[-1])

            for name, value in attrs:
                if not name:
                    continue
                escaped = html.escape(value.replace("\\", "\\\\"), quote=True)
                parts.append(f' {name}="{escaped}"')

            is_empty = (
                apktool_compatible
                and event_index + 1 < len(events)
                and isinstance(events[event_index + 1], EndEvent)
                and events[event_index + 1].depth == event.depth
                and events[event_index + 1].tag == event.tag
            )
            parts.append("/>" if is_empty else ">")
            lines.append("".join(parts))
            if is_empty:
                event_index += 1

        elif isinstance(event, EndEvent):
            indent = "    " * event.depth
            lines.append(f"{indent}</{event.tag}>")

        elif isinstance(event, TextEvent):
            indent = "    " * event.depth
            lines.append(f"{indent}{html.escape(event.text)}")

        event_index += 1

    return "\n".join(lines) + "\n"
