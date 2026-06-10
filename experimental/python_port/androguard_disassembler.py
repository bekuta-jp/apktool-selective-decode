#!/usr/bin/env python3
"""Convert Androguard DEX instructions into a smali-oriented method body."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Dict, Optional


REGISTER_RE = re.compile(r"\bv(\d+)\b")
FIELD_RE = re.compile(r"(L[^;]+;->[^\s,(]+)\s+(\[*(?:[ZBSCIJFDV]|L[^;]+;))")
METHOD_RE = re.compile(r"(L[^;]+;->[^\s(]+\()([^)]*)(\)\S+)")
OFFSET_RE = re.compile(r"[+-][0-9a-fA-F]+h")


@dataclass
class MethodBody:
    locals_count: int
    lines: list[str]


@dataclass
class DexDisassembly:
    methods: Dict[str, MethodBody]
    field_initializers: Dict[str, str]


def _method_key(class_name: str, method_name: str, descriptor: str) -> str:
    return f"{class_name}->{method_name}{descriptor.replace(' ', '')}"


def _register_name(register: int, parameter_start: int) -> str:
    if register >= parameter_start:
        return f"p{register - parameter_start}"
    return f"v{register}"


def _replace_registers(value: str, parameter_start: int) -> str:
    return REGISTER_RE.sub(
        lambda match: _register_name(int(match.group(1)), parameter_start),
        value,
    )


def _reference_operand(instruction: object) -> Optional[str]:
    for operand in reversed(instruction.get_operands()):
        if len(operand) >= 3 and isinstance(operand[-1], str):
            return operand[-1]
    return None


def _format_reference(reference: str) -> str:
    reference = FIELD_RE.sub(r"\1:\2", reference)
    return METHOD_RE.sub(lambda match: match.group(1) + match.group(2).replace(" ", "") + match.group(3), reference)


def _label_kind(name: str) -> str:
    if name.startswith("if-"):
        return "cond"
    if name.startswith("goto"):
        return "goto"
    if name == "fill-array-data":
        return "array"
    if name == "packed-switch":
        return "pswitch_data"
    if name == "sparse-switch":
        return "sswitch_data"
    return "label"


def _array_literal(value: int, width: int) -> str:
    suffix = {1: "t", 2: "s", 4: "", 8: "L"}.get(width, "")
    return f"0x{value:x}{suffix}"


def _quote_string(value: str) -> str:
    parts: list[str] = []
    for char in value:
        codepoint = ord(char)
        if char == "\\":
            parts.append("\\\\")
        elif char == '"':
            parts.append('\\"')
        elif char == "\n":
            parts.append("\\n")
        elif char == "\r":
            parts.append("\\r")
        elif char == "\t":
            parts.append("\\t")
        elif 0x20 <= codepoint <= 0x7E:
            parts.append(char)
        elif codepoint <= 0xFFFF:
            parts.append(f"\\u{codepoint:04x}")
        else:
            codepoint -= 0x10000
            parts.append(f"\\u{0xD800 + (codepoint >> 10):04x}")
            parts.append(f"\\u{0xDC00 + (codepoint & 0x3FF):04x}")
    return '"' + "".join(parts) + '"'


def _field_initializer(field: object) -> Optional[str]:
    encoded = field.get_init_value()
    if encoded is None:
        return None

    value_type = encoded.get_value_type()
    value = encoded.get_value()
    if value_type == 0x17:
        return _quote_string(str(value))
    if value_type == 0x1F:
        return "true" if value else None
    if value_type == 0x1E:
        return None
    if value_type in {0x00, 0x02, 0x03, 0x04}:
        return None if int(value) == 0 else f"0x{int(value) & 0xffffffff:x}"
    if value_type == 0x06:
        return None if int(value) == 0 else f"0x{int(value) & 0xffffffffffffffff:x}L"
    if value_type == 0x10:
        return None if float(value) == 0.0 else f"{float(value)!r}f"
    if value_type == 0x11:
        return None if float(value) == 0.0 else repr(float(value))
    return None


def _read_uleb128(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    for _ in range(5):
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte & 0x80 == 0:
            return value, offset
        shift += 7
    raise ValueError("Invalid uleb128")


def _read_sleb128(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    byte = 0
    for _ in range(5):
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if byte & 0x80 == 0:
            break
    if shift < 32 and byte & 0x40:
        value |= -(1 << shift)
    return value, offset


def _debug_directives(data: bytes, offset: int) -> Dict[int, list[str]]:
    if offset == 0:
        return {}

    try:
        line, cursor = _read_uleb128(data, offset)
        parameter_count, cursor = _read_uleb128(data, cursor)
        for _ in range(parameter_count):
            _, cursor = _read_uleb128(data, cursor)

        address = 0
        directives: Dict[int, list[str]] = {}
        while cursor < len(data):
            opcode = data[cursor]
            cursor += 1
            if opcode == 0:
                break
            if opcode == 1:
                advance, cursor = _read_uleb128(data, cursor)
                address += advance
            elif opcode == 2:
                advance, cursor = _read_sleb128(data, cursor)
                line += advance
            elif opcode == 3:
                for _ in range(3):
                    _, cursor = _read_uleb128(data, cursor)
            elif opcode == 4:
                for _ in range(4):
                    _, cursor = _read_uleb128(data, cursor)
            elif opcode in {5, 6}:
                _, cursor = _read_uleb128(data, cursor)
            elif opcode == 7:
                directives.setdefault(address * 2, []).append(".prologue")
            elif opcode == 8:
                directives.setdefault(address * 2, []).append(".epilogue")
            elif opcode == 9:
                _, cursor = _read_uleb128(data, cursor)
            else:
                adjusted = opcode - 0x0A
                address += adjusted // 15
                line += -4 + adjusted % 15
                directives.setdefault(address * 2, []).append(f".line {line}")
        return directives
    except (IndexError, ValueError):
        return {}


def _render_array_payload(instruction: object) -> list[str]:
    width = instruction.element_width
    data = instruction.get_data()
    lines = [f"    .array-data {width}"]
    for offset in range(0, len(data), width):
        raw = data[offset : offset + width]
        if len(raw) != width:
            break
        lines.append(f"        {_array_literal(int.from_bytes(raw, 'little'), width)}")
    lines.append("    .end array-data")
    return lines


def _render_switch_payload(
    instruction: object,
    owner_offset: int,
    sparse: bool,
) -> tuple[list[str], Dict[int, str]]:
    target_labels: Dict[int, str] = {}
    prefix = "sswitch" if sparse else "pswitch"
    targets = instruction.get_targets()
    keys = instruction.get_keys()

    for target in targets:
        target_offset = owner_offset + target * 2
        target_labels[target_offset] = f":{prefix}_{target_offset:x}"

    if sparse:
        lines = ["    .sparse-switch"]
        for key, target in zip(keys, targets):
            target_offset = owner_offset + target * 2
            lines.append(f"        0x{key:x} -> {target_labels[target_offset]}")
        lines.append("    .end sparse-switch")
    else:
        first_key = keys[0] if keys else 0
        lines = [f"    .packed-switch 0x{first_key:x}"]
        for target in targets:
            target_offset = owner_offset + target * 2
            lines.append(f"        {target_labels[target_offset]}")
        lines.append("    .end packed-switch")
    return lines, target_labels


def _format_normal_instruction(
    offset: int,
    instruction: object,
    parameter_start: int,
    target_label: Optional[str],
) -> str:
    name = instruction.get_name()
    output = instruction.get_output(offset)
    operands = instruction.get_operands()

    if name.startswith("invoke-") or name.startswith("filled-new-array"):
        registers = [
            _register_name(int(operand[1]), parameter_start)
            for operand in operands
            if int(operand[0]) == 0
        ]
        if name.endswith("/range") and registers:
            register_text = (
                registers[0]
                if len(registers) == 1
                else f"{registers[0]} .. {registers[-1]}"
            )
        else:
            register_text = ", ".join(registers)
        reference = _reference_operand(instruction)
        output = f"{{{register_text}}}"
        if reference:
            output += f", {_format_reference(reference)}"
    elif name in {"const-string", "const-string/jumbo"}:
        registers = [operand for operand in operands if int(operand[0]) == 0]
        reference = _reference_operand(instruction)
        if registers and reference is not None:
            output = (
                f"{_register_name(int(registers[0][1]), parameter_start)}, "
                f"{_quote_string(reference)}"
            )
    else:
        output = _replace_registers(output, parameter_start)
        output = _format_reference(output)
        literals = [operand for operand in operands if int(operand[0]) == 1]
        if literals:
            literal = int(literals[-1][1])
            formatted = f"-0x{-literal:x}" if literal < 0 else f"0x{literal:x}"
            output = re.sub(r"(?<=,\s)[-+]?(?:0x[0-9a-fA-F]+|\d+)(?=\s*$)", formatted, output)

    if target_label:
        output = OFFSET_RE.sub(target_label, output)
    return f"    {name}" + (f" {output}" if output else "")


def disassemble_dex(data: bytes) -> DexDisassembly:
    from loguru import logger

    logger.remove()
    from androguard.core.dex import DEX, Operand

    dex = DEX(data)
    result: Dict[str, MethodBody] = {}
    field_initializers: Dict[str, str] = {}

    for class_def in dex.get_classes():
        for field in class_def.get_fields():
            initializer = _field_initializer(field)
            if initializer is not None:
                field_initializers[
                    f"{field.get_class_name()}->{field.get_name()}:{field.get_descriptor()}"
                ] = initializer

    for method in dex.get_encoded_methods():
        code = method.get_code()
        if code is None:
            continue

        instructions = list(method.get_instructions_idx())
        labels: Dict[int, str] = {}
        payload_owners: Dict[int, tuple[int, str]] = {}

        for offset, instruction in instructions:
            name = instruction.get_name()
            for operand in instruction.get_operands():
                if operand[0] != Operand.OFFSET:
                    continue
                target_offset = offset + int(operand[1]) * 2
                kind = _label_kind(name)
                labels[target_offset] = f":{kind}_{target_offset:x}"
                if kind in {"pswitch_data", "sswitch_data"}:
                    payload_owners[target_offset] = (offset, kind)

        for offset, instruction in instructions:
            owner = payload_owners.get(offset)
            if owner is None:
                continue
            owner_offset, kind = owner
            _, target_labels = _render_switch_payload(
                instruction, owner_offset, sparse=kind == "sswitch_data"
            )
            labels.update(target_labels)

        parameter_start = code.get_registers_size() - code.get_ins_size()
        debug_directives = _debug_directives(data, code.get_debug_info_off())
        lines: list[str] = []
        for offset, instruction in instructions:
            for directive in debug_directives.get(offset, []):
                lines.append(f"    {directive}")

            if offset in labels:
                lines.append(f"    {labels[offset]}")

            name = instruction.get_name()
            if name == "fill-array-data-payload":
                lines.extend(_render_array_payload(instruction))
                lines.append("")
                continue
            if name in {"packed-switch-payload", "sparse-switch-payload"}:
                owner_offset, kind = payload_owners.get(offset, (offset, "pswitch_data"))
                payload_lines, _ = _render_switch_payload(
                    instruction, owner_offset, sparse=kind == "sswitch_data"
                )
                lines.extend(payload_lines)
                lines.append("")
                continue

            target_label = None
            for operand in instruction.get_operands():
                if operand[0] == Operand.OFFSET:
                    target_offset = offset + int(operand[1]) * 2
                    target_label = labels[target_offset]
                    break
            lines.append(
                _format_normal_instruction(
                    offset, instruction, parameter_start, target_label
                )
            )
            lines.append("")

        while lines and not lines[-1]:
            lines.pop()

        result[
            _method_key(
                method.get_class_name(),
                method.get_name(),
                method.get_descriptor(),
            )
        ] = MethodBody(
            locals_count=code.get_registers_size() - code.get_ins_size(),
            lines=lines,
        )

    return DexDisassembly(
        methods=result,
        field_initializers=field_initializers,
    )
