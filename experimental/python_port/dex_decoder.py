#!/usr/bin/env python3
"""Lightweight DEX decoder for manifest/dex extraction experiments."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
import struct
from typing import Dict, Iterable, List, Optional, Tuple


NO_INDEX = 0xFFFFFFFF


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
    proto_ids_size: int
    proto_ids_off: int
    field_ids_size: int
    field_ids_off: int
    method_ids_size: int
    method_ids_off: int
    class_defs_size: int
    class_defs_off: int


@dataclass
class FieldId:
    class_desc: str
    type_desc: str
    name: str


@dataclass
class MethodId:
    class_desc: str
    name: str
    proto_desc: str


@dataclass
class ClassDef:
    descriptor: str
    access_flags: int
    superclass: Optional[str]
    interfaces: List[str]
    source_file: Optional[str]
    class_data_off: int


@dataclass
class EncodedField:
    field_idx: int
    access_flags: int
    kind: str


@dataclass
class EncodedMethod:
    method_idx: int
    access_flags: int
    code_off: int
    kind: str


@dataclass
class ParsedClassData:
    static_fields: List[EncodedField]
    instance_fields: List[EncodedField]
    direct_methods: List[EncodedMethod]
    virtual_methods: List[EncodedMethod]


@dataclass
class CodeItemHeader:
    registers_size: int
    ins_size: int
    outs_size: int
    tries_size: int
    debug_info_off: int
    insns_size: int


@dataclass
class ParsedDex:
    header: DexHeader
    strings: List[str]
    type_descriptors: List[str]
    proto_descriptors: List[str]
    field_ids: List[FieldId]
    method_ids: List[MethodId]
    class_defs: List[ClassDef]


def _u16(data: bytes, offset: int) -> int:
    _check_range(data, offset, 2, "u16")
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    _check_range(data, offset, 4, "u32")
    return struct.unpack_from("<I", data, offset)[0]


def _check_range(data: bytes, offset: int, size: int, label: str) -> None:
    if offset < 0 or offset + size > len(data):
        raise DexDecodeError(f"Out of range {label}")


def _read_uleb128(data: bytes, offset: int) -> Tuple[int, int]:
    value = 0
    shift = 0
    pos = offset
    for _ in range(5):
        _check_range(data, pos, 1, "uleb128")
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

    return DexHeader(
        magic=magic.decode("ascii", errors="replace").rstrip("\x00"),
        checksum=_u32(data, 8),
        signature=data[12:32].hex(),
        file_size=_u32(data, 32),
        header_size=_u32(data, 36),
        endian_tag=_u32(data, 40),
        string_ids_size=_u32(data, 56),
        string_ids_off=_u32(data, 60),
        type_ids_size=_u32(data, 64),
        type_ids_off=_u32(data, 68),
        proto_ids_size=_u32(data, 72),
        proto_ids_off=_u32(data, 76),
        field_ids_size=_u32(data, 80),
        field_ids_off=_u32(data, 84),
        method_ids_size=_u32(data, 88),
        method_ids_off=_u32(data, 92),
        class_defs_size=_u32(data, 96),
        class_defs_off=_u32(data, 100),
    )


def _idx(values: List[str], index: int, fallback: str = "<invalid>") -> str:
    return values[index] if 0 <= index < len(values) else fallback


def _parse_strings(data: bytes, header: DexHeader) -> List[str]:
    strings: List[str] = []
    for i in range(header.string_ids_size):
        item_off = header.string_ids_off + i * 4
        str_off = _u32(data, item_off)
        if str_off >= len(data):
            raise DexDecodeError("Out of range string_data")
        strings.append(_read_mutf8_string(data, str_off))
    return strings


def _parse_type_descriptors(data: bytes, header: DexHeader, strings: List[str]) -> List[str]:
    descriptors: List[str] = []
    for i in range(header.type_ids_size):
        item_off = header.type_ids_off + i * 4
        descriptor_idx = _u32(data, item_off)
        descriptors.append(_idx(strings, descriptor_idx))
    return descriptors


def _parse_proto_descriptors(data: bytes, header: DexHeader, type_descriptors: List[str]) -> List[str]:
    descriptors: List[str] = []
    for i in range(header.proto_ids_size):
        item_off = header.proto_ids_off + i * 12
        return_type_idx = _u32(data, item_off + 4)
        parameters_off = _u32(data, item_off + 8)

        ret = _idx(type_descriptors, return_type_idx)
        params: List[str] = []
        if parameters_off != 0:
            size = _u32(data, parameters_off)
            list_off = parameters_off + 4
            for j in range(size):
                type_idx = _u16(data, list_off + j * 2)
                params.append(_idx(type_descriptors, type_idx))

        descriptors.append(f"({''.join(params)}){ret}")
    return descriptors


def _parse_field_ids(
    data: bytes, header: DexHeader, strings: List[str], type_descriptors: List[str]
) -> List[FieldId]:
    fields: List[FieldId] = []
    for i in range(header.field_ids_size):
        item_off = header.field_ids_off + i * 8
        class_idx = _u16(data, item_off)
        type_idx = _u16(data, item_off + 2)
        name_idx = _u32(data, item_off + 4)
        fields.append(
            FieldId(
                class_desc=_idx(type_descriptors, class_idx),
                type_desc=_idx(type_descriptors, type_idx),
                name=_idx(strings, name_idx),
            )
        )
    return fields


def _parse_method_ids(
    data: bytes,
    header: DexHeader,
    strings: List[str],
    type_descriptors: List[str],
    proto_descriptors: List[str],
) -> List[MethodId]:
    methods: List[MethodId] = []
    for i in range(header.method_ids_size):
        item_off = header.method_ids_off + i * 8
        class_idx = _u16(data, item_off)
        proto_idx = _u16(data, item_off + 2)
        name_idx = _u32(data, item_off + 4)
        methods.append(
            MethodId(
                class_desc=_idx(type_descriptors, class_idx),
                name=_idx(strings, name_idx),
                proto_desc=_idx(proto_descriptors, proto_idx, "(?)<invalid>"),
            )
        )
    return methods


def _parse_type_list(data: bytes, offset: int, type_descriptors: List[str]) -> List[str]:
    if offset == 0:
        return []
    size = _u32(data, offset)
    items_off = offset + 4
    return [_idx(type_descriptors, _u16(data, items_off + i * 2)) for i in range(size)]


def _parse_class_defs(
    data: bytes, header: DexHeader, strings: List[str], type_descriptors: List[str]
) -> List[ClassDef]:
    classes: List[ClassDef] = []
    for i in range(header.class_defs_size):
        item_off = header.class_defs_off + i * 32
        class_idx = _u32(data, item_off)
        access_flags = _u32(data, item_off + 4)
        superclass_idx = _u32(data, item_off + 8)
        interfaces_off = _u32(data, item_off + 12)
        source_file_idx = _u32(data, item_off + 16)
        class_data_off = _u32(data, item_off + 24)

        classes.append(
            ClassDef(
                descriptor=_idx(type_descriptors, class_idx),
                access_flags=access_flags,
                superclass=None if superclass_idx == NO_INDEX else _idx(type_descriptors, superclass_idx),
                interfaces=_parse_type_list(data, interfaces_off, type_descriptors),
                source_file=None if source_file_idx == NO_INDEX else _idx(strings, source_file_idx),
                class_data_off=class_data_off,
            )
        )
    return classes


def _parse_dex(data: bytes) -> ParsedDex:
    header = _parse_header(data)
    strings = _parse_strings(data, header)
    type_descriptors = _parse_type_descriptors(data, header, strings)
    proto_descriptors = _parse_proto_descriptors(data, header, type_descriptors)
    field_ids = _parse_field_ids(data, header, strings, type_descriptors)
    method_ids = _parse_method_ids(data, header, strings, type_descriptors, proto_descriptors)
    class_defs = _parse_class_defs(data, header, strings, type_descriptors)

    return ParsedDex(
        header=header,
        strings=strings,
        type_descriptors=type_descriptors,
        proto_descriptors=proto_descriptors,
        field_ids=field_ids,
        method_ids=method_ids,
        class_defs=class_defs,
    )


def _parse_class_data(data: bytes, class_data_off: int) -> ParsedClassData:
    if class_data_off == 0:
        return ParsedClassData([], [], [], [])

    pos = class_data_off
    static_fields_size, pos = _read_uleb128(data, pos)
    instance_fields_size, pos = _read_uleb128(data, pos)
    direct_methods_size, pos = _read_uleb128(data, pos)
    virtual_methods_size, pos = _read_uleb128(data, pos)

    def read_fields(size: int, kind: str) -> List[EncodedField]:
        nonlocal pos
        fields: List[EncodedField] = []
        field_idx = 0
        for _ in range(size):
            field_idx_diff, pos = _read_uleb128(data, pos)
            access_flags, pos = _read_uleb128(data, pos)
            field_idx += field_idx_diff
            fields.append(EncodedField(field_idx, access_flags, kind))
        return fields

    def read_methods(size: int, kind: str) -> List[EncodedMethod]:
        nonlocal pos
        methods: List[EncodedMethod] = []
        method_idx = 0
        for _ in range(size):
            method_idx_diff, pos = _read_uleb128(data, pos)
            access_flags, pos = _read_uleb128(data, pos)
            code_off, pos = _read_uleb128(data, pos)
            method_idx += method_idx_diff
            methods.append(EncodedMethod(method_idx, access_flags, code_off, kind))
        return methods

    return ParsedClassData(
        static_fields=read_fields(static_fields_size, "static"),
        instance_fields=read_fields(instance_fields_size, "instance"),
        direct_methods=read_methods(direct_methods_size, "direct"),
        virtual_methods=read_methods(virtual_methods_size, "virtual"),
    )


def _parse_code_item_header(data: bytes, code_off: int) -> Optional[CodeItemHeader]:
    if code_off == 0:
        return None
    _check_range(data, code_off, 16, "code_item")
    return CodeItemHeader(
        registers_size=_u16(data, code_off),
        ins_size=_u16(data, code_off + 2),
        outs_size=_u16(data, code_off + 4),
        tries_size=_u16(data, code_off + 6),
        debug_info_off=_u32(data, code_off + 8),
        insns_size=_u32(data, code_off + 12),
    )


def _hash_lines(lines: Iterable[str]) -> str:
    h = hashlib.sha256()
    for line in sorted(set(lines)):
        h.update(line.encode("utf-8", errors="replace"))
        h.update(b"\n")
    return h.hexdigest()


def _method_signature(method: MethodId) -> str:
    return f"{method.class_desc}->{method.name}{method.proto_desc}"


def _defined_method_signatures(parsed: ParsedDex, data: bytes) -> List[str]:
    signatures: List[str] = []
    for class_def in parsed.class_defs:
        class_data = _parse_class_data(data, class_def.class_data_off)
        for encoded in class_data.direct_methods + class_data.virtual_methods:
            if encoded.method_idx < len(parsed.method_ids):
                signatures.append(_method_signature(parsed.method_ids[encoded.method_idx]))
    return signatures


def decode_dex(
    data: bytes, preview_limit: int = 32, include_method_signatures: bool = False
) -> Dict[str, object]:
    parsed = _parse_dex(data)
    classes = [class_def.descriptor for class_def in parsed.class_defs]
    defined_methods = _defined_method_signatures(parsed, data)
    method_id_signatures = [_method_signature(method) for method in parsed.method_ids]

    methods_preview = [
        {
            "index": i,
            "class": method.class_desc,
            "name": method.name,
            "descriptor": method.proto_desc,
            "signature": _method_signature(method),
        }
        for i, method in enumerate(parsed.method_ids[:preview_limit])
    ]

    class_previews: List[Dict[str, object]] = []
    for class_def in parsed.class_defs[:preview_limit]:
        class_data = _parse_class_data(data, class_def.class_data_off)
        class_previews.append(
            {
                "class": class_def.descriptor,
                "super": class_def.superclass,
                "interfaces": class_def.interfaces,
                "source_file": class_def.source_file,
                "static_fields": len(class_data.static_fields),
                "instance_fields": len(class_data.instance_fields),
                "direct_methods": len(class_data.direct_methods),
                "virtual_methods": len(class_data.virtual_methods),
            }
        )

    signatures_block: Dict[str, object] = {
        "class_count": len(set(classes)),
        "class_hash": _hash_lines(classes),
        "method_signature_count": len(defined_methods),
        "method_signature_hash": _hash_lines(defined_methods),
        "method_id_signature_count": len(method_id_signatures),
        "method_id_signature_hash": _hash_lines(method_id_signatures),
    }
    if include_method_signatures:
        signatures_block["class_descriptors"] = sorted(set(classes))
        signatures_block["method_signatures"] = sorted(set(defined_methods))
        signatures_block["method_id_signatures"] = sorted(set(method_id_signatures))

    header = parsed.header
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
            "proto_ids_size": header.proto_ids_size,
            "field_ids_size": header.field_ids_size,
            "method_ids_size": header.method_ids_size,
            "class_defs_size": header.class_defs_size,
        },
        "preview": {
            "strings": parsed.strings[:preview_limit],
            "type_descriptors": parsed.type_descriptors[:preview_limit],
            "classes": class_previews,
            "methods": methods_preview,
        },
        "counts": {
            "strings": len(parsed.strings),
            "types": len(parsed.type_descriptors),
            "fields": len(parsed.field_ids),
            "method_ids": len(parsed.method_ids),
            "classes": len(parsed.class_defs),
            "defined_methods": len(defined_methods),
        },
        "signatures": signatures_block,
    }


def _access_flags(flags: int, target: str) -> str:
    selected = [
        (0x0001, "public"),
        (0x0002, "private"),
        (0x0004, "protected"),
        (0x0008, "static"),
        (0x0010, "final"),
    ]
    if target == "class":
        selected += [
            (0x0200, "interface"),
            (0x0400, "abstract"),
            (0x1000, "synthetic"),
            (0x2000, "annotation"),
            (0x4000, "enum"),
        ]
    elif target == "field":
        selected += [
            (0x0040, "volatile"),
            (0x0080, "transient"),
            (0x1000, "synthetic"),
            (0x4000, "enum"),
        ]
    elif target == "method":
        selected += [
            (0x0020, "synchronized"),
            (0x0040, "bridge"),
            (0x0080, "varargs"),
            (0x0100, "native"),
            (0x0400, "abstract"),
            (0x0800, "strictfp"),
            (0x1000, "synthetic"),
            (0x10000, "constructor"),
            (0x20000, "declared-synchronized"),
        ]

    values = [name for bit, name in selected if flags & bit]
    return " ".join(values)


def _descriptor_to_smali_path(descriptor: str) -> str:
    if descriptor.startswith("L") and descriptor.endswith(";"):
        return descriptor[1:-1] + ".smali"
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", descriptor).strip("_") or "invalid"
    return f"invalid/{safe}.smali"


def _unique_smali_path(
    path: str,
    existing: Dict[str, str],
    casefold_paths: Optional[set[str]] = None,
) -> str:
    used = (
        casefold_paths
        if casefold_paths is not None
        else {existing_path.casefold() for existing_path in existing}
    )
    if path.casefold() not in used:
        return path
    stem = path[:-6] if path.endswith(".smali") else path
    duplicate_index = 1
    while f"{stem}.{duplicate_index}.smali".casefold() in used:
        duplicate_index += 1
    return f"{stem}.{duplicate_index}.smali"


def _quote_smali_string(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r")
    return f'"{escaped}"'


def _format_directive(prefix: str, access: str, rest: str) -> str:
    if access:
        return f"{prefix} {access} {rest}"
    return f"{prefix} {rest}"


def _method_key(method: MethodId) -> str:
    return f"{method.class_desc}->{method.name}{method.proto_desc}"


def _field_key(field: FieldId) -> str:
    return f"{field.class_desc}->{field.name}:{field.type_desc}"


def _smali_for_class(
    parsed: ParsedDex,
    data: bytes,
    class_def: ClassDef,
    method_bodies: Optional[Dict[str, object]] = None,
    field_initializers: Optional[Dict[str, str]] = None,
    class_annotations: Optional[Dict[str, List[str]]] = None,
    field_annotations: Optional[Dict[str, List[str]]] = None,
    method_annotations: Optional[Dict[str, List[str]]] = None,
) -> str:
    class_data = _parse_class_data(data, class_def.class_data_off)
    lines: List[str] = []

    lines.append(_format_directive(".class", _access_flags(class_def.access_flags, "class"), class_def.descriptor))
    if class_def.superclass is not None:
        lines.append(f".super {class_def.superclass}")
    if class_def.source_file is not None:
        lines.append(f".source {_quote_smali_string(class_def.source_file)}")
    lines.append("")

    for interface in class_def.interfaces:
        if interface == class_def.interfaces[0]:
            lines.append("# interfaces")
        lines.append(f".implements {interface}")
    if class_def.interfaces:
        lines.append("")

    annotations = (
        class_annotations.get(class_def.descriptor)
        if class_annotations
        else None
    )
    if annotations:
        lines.append("")
        lines.append("# annotations")
        lines.extend(annotations)
        lines.append("")
        lines.append("")

    def append_fields(section: str, encoded_fields: List[EncodedField]) -> None:
        if not encoded_fields:
            return
        lines.append("")
        lines.append(f"# {section} fields")
        for encoded in encoded_fields:
            if encoded.field_idx >= len(parsed.field_ids):
                continue
            field = parsed.field_ids[encoded.field_idx]
            access = _access_flags(encoded.access_flags, "field")
            rest = f"{field.name}:{field.type_desc}"
            initializer = field_initializers.get(_field_key(field)) if field_initializers else None
            if initializer is not None:
                rest += f" = {initializer}"
            lines.append(_format_directive(".field", access, rest))
            annotations = (
                field_annotations.get(_field_key(field))
                if field_annotations
                else None
            )
            if annotations:
                lines.extend(annotations)
                lines.append(".end field")
            lines.append("")

    append_fields("static", class_data.static_fields)
    append_fields("instance", class_data.instance_fields)
    if class_data.static_fields or class_data.instance_fields:
        lines.append("")

    def append_methods(section: str, encoded_methods: List[EncodedMethod]) -> None:
        if not encoded_methods:
            return
        lines.append(f"# {section} methods")
        for encoded in encoded_methods:
            if encoded.method_idx >= len(parsed.method_ids):
                continue
            method = parsed.method_ids[encoded.method_idx]
            access = _access_flags(encoded.access_flags, "method")
            lines.append(_format_directive(".method", access, f"{method.name}{method.proto_desc}"))

            method_body = method_bodies.get(_method_key(method)) if method_bodies else None
            code_header = _parse_code_item_header(data, encoded.code_off)
            if method_body is not None:
                lines.append(f"    .locals {method_body.locals_count}")
                lines.extend(method_body.parameter_lines)
                annotations = (
                    method_annotations.get(_method_key(method))
                    if method_annotations
                    else None
                )
                if annotations:
                    lines.extend(annotations)
                if method_body.lines:
                    lines.append("")
                    lines.extend(method_body.lines)
            elif code_header is not None:
                lines.append(f"    .registers {code_header.registers_size}")
                annotations = (
                    method_annotations.get(_method_key(method))
                    if method_annotations
                    else None
                )
                if annotations:
                    lines.extend(annotations)
                lines.append("")
                lines.append(f"    # code_off = 0x{encoded.code_off:x}")
                lines.append(f"    # insns_size = {code_header.insns_size}")
                lines.append("    # instruction disassembly is not available")
            else:
                annotations = (
                    method_annotations.get(_method_key(method))
                    if method_annotations
                    else None
                )
                if annotations:
                    lines.extend(annotations)
                if not (encoded.access_flags & (0x0100 | 0x0400)):
                    lines.append("")
                    lines.append("    # no code_item available")

            lines.append(".end method")
            lines.append("")

    append_methods("direct", class_data.direct_methods)
    if class_data.direct_methods and class_data.virtual_methods:
        lines.append("")
    append_methods("virtual", class_data.virtual_methods)

    return "\n".join(lines).rstrip() + "\n"


def generate_smali_files(data: bytes, disassemble: bool = False) -> Dict[str, str]:
    """Generate smali files, optionally including Androguard-decoded instructions."""
    parsed = _parse_dex(data)
    method_bodies: Optional[Dict[str, object]] = None
    field_initializers: Optional[Dict[str, str]] = None
    class_annotations: Optional[Dict[str, List[str]]] = None
    field_annotations: Optional[Dict[str, List[str]]] = None
    method_annotations: Optional[Dict[str, List[str]]] = None
    if disassemble:
        from androguard_disassembler import disassemble_dex

        disassembly = disassemble_dex(data)
        method_bodies = disassembly.methods
        field_initializers = disassembly.field_initializers
        class_annotations = disassembly.class_annotations
        field_annotations = disassembly.field_annotations
        method_annotations = disassembly.method_annotations

    files: Dict[str, str] = {}
    casefold_paths: set[str] = set()
    for class_def in parsed.class_defs:
        path = _unique_smali_path(
            _descriptor_to_smali_path(class_def.descriptor),
            files,
            casefold_paths,
        )
        files[path] = _smali_for_class(
            parsed,
            data,
            class_def,
            method_bodies,
            field_initializers,
            class_annotations,
            field_annotations,
            method_annotations,
        )
        casefold_paths.add(path.casefold())
    return files
