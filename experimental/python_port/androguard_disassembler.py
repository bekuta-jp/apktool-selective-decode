#!/usr/bin/env python3
"""Convert Androguard DEX instructions into a smali-oriented method body."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
import math
import re
import struct
from typing import Callable, Dict, Optional


REGISTER_RE = re.compile(r"(?<![A-Za-z0-9_/$>])v(\d+)(?=$|[\s,}])")
FIELD_RE = re.compile(r"(L[^;]+;->[^\s,(]+)\s+(\[*(?:[ZBSCIJFDV]|L[^;]+;))")
METHOD_RE = re.compile(r"(L[^;]+;->[^\s(]+\()([^)]*)(\)\S+)")
OFFSET_RE = re.compile(r"[+-][0-9a-fA-F]+h")


@dataclass
class MethodBody:
    locals_count: int
    parameter_lines: list[str]
    lines: list[str]


@dataclass
class DexDisassembly:
    methods: Dict[str, MethodBody]
    field_initializers: Dict[str, str]
    class_annotations: Dict[str, list[str]]
    field_annotations: Dict[str, list[str]]
    method_annotations: Dict[str, list[str]]
    parameter_annotations: Dict[str, list[str]]


@dataclass
class TryDirectives:
    starts: Dict[int, list[str]]
    ends: Dict[int, list[str]]
    handler_labels: Dict[int, list[str]]


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
    suffix = {1: "t", 2: "s"}.get(width, "")
    if width == 8 and not (-0x80000000 <= value <= 0x7FFFFFFF):
        suffix = "L"
    return _hex_literal(value, suffix)


def _hex_literal(value: int, suffix: str = "") -> str:
    if value < 0:
        return f"-0x{-value:x}{suffix}"
    return f"0x{value:x}{suffix}"


def _quote_string(value: str) -> str:
    parts: list[str] = []
    for char in value:
        codepoint = ord(char)
        if char == "\\":
            parts.append("\\\\")
        elif char == '"':
            parts.append('\\"')
        elif char == "'":
            parts.append("\\'")
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


def _decode_mutf8_code_units(data: bytes) -> str:
    code_units: list[str] = []
    offset = 0
    while offset < len(data):
        first = data[offset]
        offset += 1
        if first < 0x80:
            code_units.append(chr(first))
            continue
        if first & 0xE0 == 0xC0 and offset < len(data):
            second = data[offset]
            offset += 1
            code_units.append(chr(((first & 0x1F) << 6) | (second & 0x3F)))
            continue
        if first & 0xF0 == 0xE0 and offset + 1 < len(data):
            second = data[offset]
            third = data[offset + 1]
            offset += 2
            code_units.append(
                chr(
                    ((first & 0x0F) << 12)
                    | ((second & 0x3F) << 6)
                    | (third & 0x3F)
                )
            )
            continue
        raise UnicodeDecodeError(
            "mutf-8",
            data,
            offset - 1,
            offset,
            "invalid MUTF-8 sequence",
        )
    return "".join(code_units)


def _quote_char(value: int) -> str:
    char = chr(value)
    escapes = {
        "\\": "\\\\",
        "'": "\\'",
        '"': '\\"',
        "\n": "\\n",
        "\r": "\\r",
        "\t": "\\t",
    }
    if char in escapes:
        rendered = escapes[char]
    elif 0x20 <= value <= 0x7E:
        rendered = char
    else:
        rendered = f"\\u{value:04x}"
    return f"'{rendered}'"


def _java_decimal(value: float, *, float32: bool) -> str:
    if math.isnan(value):
        return "NaN"
    if math.isinf(value):
        return "-Infinity" if value < 0 else "Infinity"

    if float32:
        packed = struct.pack("<f", value)
        bits = struct.unpack("<I", packed)[0]
        if bits == 0x00000001:
            return "1.4E-45"
        if bits == 0x80000001:
            return "-1.4E-45"
        candidate = repr(value)
        for precision in range(1, 10):
            current = format(value, f".{precision}g")
            try:
                current_packed = struct.pack("<f", float(current))
            except OverflowError:
                continue
            if current_packed == packed:
                candidate = current
                break
    else:
        bits = struct.unpack("<Q", struct.pack("<d", value))[0]
        if bits == 0x0000000000000001:
            return "4.9E-324"
        if bits == 0x8000000000000001:
            return "-4.9E-324"
        candidate = repr(value)

    absolute = abs(value)
    if value != 0.0 and (absolute < 1e-3 or absolute >= 1e7):
        coefficient, exponent = format(Decimal(candidate).normalize(), "E").split("E")
        if "." not in coefficient:
            coefficient += ".0"
        return f"{coefficient}E{int(exponent)}"

    rendered = format(Decimal(candidate), "f")
    if "." not in rendered:
        rendered += ".0"
    return rendered


def _scientific_text(value: int | float) -> str:
    if isinstance(value, int):
        negative = value < 0
        digits = str(abs(value))
        if value == 0:
            return "0E0"
        exponent = len(digits) - 1
        fraction = digits[1:].rstrip("0")
        coefficient = digits[0] + (f".{fraction}" if fraction else "")
        return ("-" if negative else "") + coefficient + f"E{exponent}"

    if math.isnan(value):
        return "NaN"
    if math.isinf(value):
        return "-I" if value < 0 else "I"
    if value == 0.0:
        return "0E0"
    coefficient, exponent = format(Decimal(repr(value)).normalize(), "E").split("E")
    return f"{coefficient}E{int(exponent)}"


def _strip_likely_imprecision(value: str) -> str:
    decimal_point = value.find(".")
    exponent = value.find("E")
    for pattern in ("000", "999"):
        index = value.find(pattern)
        if index > decimal_point and index < exponent:
            return value[:index] + value[exponent:]
    return value


def _is_likely_float(value: int) -> bool:
    unsigned = value & 0xFFFFFFFF
    named = {
        0x7FC00000,
        0x7F7FFFFF,
        struct.unpack("<I", struct.pack("<f", math.pi))[0],
        struct.unpack("<I", struct.pack("<f", math.e))[0],
    }
    if unsigned in named:
        return True
    if value in {0x7FFFFFFF, -0x80000000}:
        return False

    package_id = unsigned >> 24
    resource_type = unsigned >> 16 & 0xFF
    resource_id = unsigned & 0xFFFF
    if package_id in {0x7F, 1} and resource_type < 0x1F and resource_id < 0xFFF:
        return False

    float_value = struct.unpack("<f", struct.pack("<I", unsigned))[0]
    if math.isnan(float_value):
        return False
    as_int = _scientific_text(value)
    as_float = _strip_likely_imprecision(_scientific_text(float_value))
    return len(as_float) < len(as_int)


def _is_likely_double(value: int) -> bool:
    unsigned = value & 0xFFFFFFFFFFFFFFFF
    named = {
        0x7FF8000000000000,
        0x7FEFFFFFFFFFFFFF,
        struct.unpack("<Q", struct.pack("<d", math.pi))[0],
        struct.unpack("<Q", struct.pack("<d", math.e))[0],
    }
    if unsigned in named:
        return True
    if value in {0x7FFFFFFFFFFFFFFF, -0x8000000000000000}:
        return False

    double_value = struct.unpack("<d", struct.pack("<Q", unsigned))[0]
    if math.isnan(double_value):
        return False
    as_long = _scientific_text(value)
    as_double = _strip_likely_imprecision(_scientific_text(double_value))
    return len(as_double) < len(as_long)


def _literal_comment(name: str, value: int) -> Optional[str]:
    wide = name.startswith("const-wide")
    if wide:
        if not _is_likely_double(value):
            return None
        unsigned = value & 0xFFFFFFFFFFFFFFFF
        double_value = struct.unpack("<d", struct.pack("<Q", unsigned))[0]
        if math.isinf(double_value):
            return (
                "Double.NEGATIVE_INFINITY"
                if double_value < 0
                else "Double.POSITIVE_INFINITY"
            )
        if math.isnan(double_value):
            return "Double.NaN"
        if unsigned == 0x7FEFFFFFFFFFFFFF:
            return "Double.MAX_VALUE"
        if double_value == math.pi:
            return "Math.PI"
        if double_value == math.e:
            return "Math.E"
        return _java_decimal(double_value, float32=False)

    if not _is_likely_float(value):
        return None
    unsigned = value & 0xFFFFFFFF
    float_value = struct.unpack("<f", struct.pack("<I", unsigned))[0]
    if math.isinf(float_value):
        return (
            "Float.NEGATIVE_INFINITY"
            if float_value < 0
            else "Float.POSITIVE_INFINITY"
        )
    if math.isnan(float_value):
        return "Float.NaN"
    if unsigned == 0x7F7FFFFF:
        return "Float.MAX_VALUE"
    if unsigned == struct.unpack("<I", struct.pack("<f", math.pi))[0]:
        return "(float)Math.PI"
    if unsigned == struct.unpack("<I", struct.pack("<f", math.e))[0]:
        return "(float)Math.E"
    return _java_decimal(float_value, float32=True) + "f"


def _field_initializer(
    field: object,
    assigned_static_fields: set[str],
    string_resolver: Callable[[int], str],
) -> Optional[str]:
    encoded = field.get_init_value()
    if encoded is None:
        return None
    field_key = (
        f"{field.get_class_name()}->{field.get_name()}:{field.get_descriptor()}"
    )
    value_type = encoded.get_value_type()
    raw_value = encoded.get_value()
    is_default = (
        value_type == 0x1E
        or (value_type == 0x1F and not raw_value)
        or (
            value_type in {0x00, 0x02, 0x03, 0x04, 0x06, 0x10, 0x11}
            and int(raw_value) == 0
        )
    )
    if (
        field.get_access_flags() & 0x0010
        and field_key in assigned_static_fields
        and is_default
    ):
        return None
    return _format_annotation_scalar(encoded, string_resolver)


def _sign_extend(value: int, byte_count: int) -> int:
    sign_bit = 1 << (byte_count * 8 - 1)
    return value - (1 << (byte_count * 8)) if value & sign_bit else value


def _encoded_index(value: object) -> int:
    return int.from_bytes(value.raw_value, "little")


def _format_annotation_scalar(
    value: object,
    string_resolver: Callable[[int], str],
) -> str:
    value_type = value.get_value_type()
    raw_value = value.get_value()
    byte_count = value.get_value_arg() + 1

    if value_type == 0x00:
        signed = _sign_extend(int(raw_value), 1)
        return f"-0x{-signed:x}t" if signed < 0 else f"0x{signed:x}t"
    if value_type == 0x02:
        signed = _sign_extend(int(raw_value), byte_count)
        return f"-0x{-signed:x}s" if signed < 0 else f"0x{signed:x}s"
    if value_type == 0x03:
        return _quote_char(int(raw_value))
    if value_type == 0x04:
        signed = _sign_extend(int(raw_value), byte_count)
        return f"-0x{-signed:x}" if signed < 0 else f"0x{signed:x}"
    if value_type == 0x06:
        signed = _sign_extend(int(raw_value), byte_count)
        return f"-0x{-signed:x}L" if signed < 0 else f"0x{signed:x}L"
    if value_type == 0x10:
        bits = int(raw_value) << ((4 - byte_count) * 8)
        return (
            _java_decimal(
                struct.unpack("<f", struct.pack("<I", bits))[0],
                float32=True,
            )
            + "f"
        )
    if value_type == 0x11:
        bits = int(raw_value) << ((8 - byte_count) * 8)
        return _java_decimal(
            struct.unpack("<d", struct.pack("<Q", bits))[0],
            float32=False,
        )
    if value_type == 0x17:
        return _quote_string(string_resolver(_encoded_index(value)))
    if value_type == 0x18:
        return str(raw_value)
    if value_type in {0x19, 0x1B}:
        class_name, type_name, field_name = raw_value
        reference = f"{class_name}->{field_name}:{type_name}"
        return f".enum {reference}" if value_type == 0x1B else reference
    if value_type == 0x1A:
        class_name, method_name, proto = raw_value
        return f"{class_name}->{method_name}{''.join(proto).replace(' ', '')}"
    if value_type == 0x1E:
        return "null"
    if value_type == 0x1F:
        return "true" if raw_value else "false"
    return f"0x{int(raw_value):x}"


def _render_annotation_value(
    name: str,
    value: object,
    indent: str,
    string_resolver: Callable[[int], str],
) -> list[str]:
    value_type = value.get_value_type()
    raw_value = value.get_value()

    if value_type == 0x1C:
        values = raw_value.get_values()
        if not values:
            return [f"{indent}{name} = {{}}"]
        lines = [f"{indent}{name} = {{"]
        for index, item in enumerate(values):
            suffix = "," if index + 1 < len(values) else ""
            if item.get_value_type() == 0x1D:
                nested = _render_subannotation(
                    item.get_value(),
                    indent + "    ",
                    string_resolver,
                )
                nested[-1] += suffix
                lines.extend(nested)
            else:
                lines.append(
                    f"{indent}    "
                    f"{_format_annotation_scalar(item, string_resolver)}{suffix}"
                )
        lines.append(f"{indent}}}")
        return lines

    if value_type == 0x1D:
        lines = [f"{indent}{name} = {_subannotation_header(raw_value)}"]
        lines.extend(
            _render_annotation_elements(
                raw_value,
                indent + "    ",
                string_resolver,
            )
        )
        lines.append(f"{indent}.end subannotation")
        return lines

    return [
        f"{indent}{name} = "
        f"{_format_annotation_scalar(value, string_resolver)}"
    ]


def _subannotation_header(annotation: object) -> str:
    return f".subannotation {annotation.CM.get_type(annotation.get_type_idx())}"


def _render_subannotation(
    annotation: object,
    indent: str,
    string_resolver: Callable[[int], str],
) -> list[str]:
    lines = [f"{indent}{_subannotation_header(annotation)}"]
    lines.extend(
        _render_annotation_elements(
            annotation,
            indent + "    ",
            string_resolver,
        )
    )
    lines.append(f"{indent}.end subannotation")
    return lines


def _render_annotation_elements(
    annotation: object,
    indent: str,
    string_resolver: Callable[[int], str],
) -> list[str]:
    lines: list[str] = []
    for element in annotation.get_elements():
        name = string_resolver(element.get_name_idx())
        lines.extend(
            _render_annotation_value(
                name,
                element.get_value(),
                indent,
                string_resolver,
            )
        )
    return lines


def _render_annotation_set(
    annotation_set: object,
    annotation_items: Dict[int, object],
    string_resolver: Callable[[int], str],
    indent: str = "",
) -> list[str]:
    if annotation_set is None:
        return []

    visibility_names = {0: "build", 1: "runtime", 2: "system"}
    lines: list[str] = []
    for annotation_off in annotation_set.get_annotation_off_item():
        item = annotation_items.get(annotation_off.get_annotation_off())
        if item is None:
            continue
        if lines:
            lines.append("")
        annotation = item.get_annotation()
        visibility = visibility_names.get(item.get_visibility(), "build")
        annotation_type = annotation.CM.get_type(annotation.get_type_idx())
        lines.append(f"{indent}.annotation {visibility} {annotation_type}")
        lines.extend(
            _render_annotation_elements(
                annotation,
                indent + "    ",
                string_resolver,
            )
        )
        lines.append(f"{indent}.end annotation")
    return lines


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


def _format_local(
    directive: str,
    register: str,
    local: tuple[str, str, Optional[str]],
) -> str:
    name, type_name, signature = local
    value = f"{_quote_string(name)}:{type_name}"
    if signature is not None:
        value += f", {_quote_string(signature)}"
    if directive == ".local":
        return f"{directive} {register}, {value}"
    return f"{directive} {register}    # {value}"


def _initial_parameter_locals(
    method: object,
    code: object,
    names: list[Optional[str]],
) -> Dict[int, tuple[str, str, Optional[str]]]:
    descriptors = _parameter_descriptors(method.get_descriptor())
    register = code.get_registers_size() - code.get_ins_size()
    locals_by_register: Dict[int, tuple[str, str, Optional[str]]] = {}
    if not method.get_access_flags() & 0x0008:
        locals_by_register[register] = ("this", method.get_class_name(), None)
        register += 1

    for index, descriptor in enumerate(descriptors):
        name = names[index] if index < len(names) else None
        if name is not None:
            locals_by_register[register] = (name, descriptor, None)
        register += 2 if descriptor in {"J", "D"} else 1
    return locals_by_register


def _debug_directives(
    data: bytes,
    offset: int,
    parameter_start: int,
    string_resolver: object,
    type_resolver: object,
    initial_locals: Dict[int, tuple[str, str, Optional[str]]],
) -> Dict[int, list[str]]:
    if offset == 0:
        return {}

    try:
        line, cursor = _read_uleb128(data, offset)
        parameter_count, cursor = _read_uleb128(data, cursor)
        for _ in range(parameter_count):
            _, cursor = _read_uleb128(data, cursor)

        address = 0
        directives: Dict[int, list[str]] = {}
        active_locals = dict(initial_locals)
        previous_locals = dict(initial_locals)
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
            elif opcode in {3, 4}:
                register, cursor = _read_uleb128(data, cursor)
                name_index, cursor = _read_uleb128(data, cursor)
                type_index, cursor = _read_uleb128(data, cursor)
                signature_index = 0
                if opcode == 4:
                    signature_index, cursor = _read_uleb128(data, cursor)
                if name_index == 0 or type_index == 0:
                    continue
                local = (
                    string_resolver(name_index - 1),
                    type_resolver(type_index - 1),
                    (
                        string_resolver(signature_index - 1)
                        if signature_index > 0
                        else None
                    ),
                )
                active_locals[register] = local
                previous_locals[register] = local
                directives.setdefault(address * 2, []).append(
                    _format_local(
                        ".local",
                        _register_name(register, parameter_start),
                        local,
                    )
                )
            elif opcode == 5:
                register, cursor = _read_uleb128(data, cursor)
                local = active_locals.pop(register, None)
                if local is not None:
                    previous_locals[register] = local
                    directives.setdefault(address * 2, []).append(
                        _format_local(
                            ".end local",
                            _register_name(register, parameter_start),
                            local,
                        )
                    )
            elif opcode == 6:
                register, cursor = _read_uleb128(data, cursor)
                local = previous_locals.get(register)
                if local is not None:
                    active_locals[register] = local
                    directives.setdefault(address * 2, []).append(
                        _format_local(
                            ".restart local",
                            _register_name(register, parameter_start),
                            local,
                        )
                    )
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


def _debug_parameter_names(
    data: bytes,
    offset: int,
    string_resolver: object,
) -> list[Optional[str]]:
    if offset == 0:
        return []
    try:
        _, cursor = _read_uleb128(data, offset)
        parameter_count, cursor = _read_uleb128(data, cursor)
        names: list[Optional[str]] = []
        for _ in range(parameter_count):
            encoded_index, cursor = _read_uleb128(data, cursor)
            names.append(
                None
                if encoded_index == 0
                else string_resolver(encoded_index - 1)
            )
        return names
    except (IndexError, ValueError):
        return []


def _parameter_descriptors(descriptor: str) -> list[str]:
    compact = descriptor.replace(" ", "")
    parameters = compact[compact.find("(") + 1 : compact.find(")")]
    result: list[str] = []
    cursor = 0
    while cursor < len(parameters):
        start = cursor
        while cursor < len(parameters) and parameters[cursor] == "[":
            cursor += 1
        if cursor < len(parameters) and parameters[cursor] == "L":
            end = parameters.find(";", cursor)
            if end < 0:
                break
            cursor = end + 1
        else:
            cursor += 1
        result.append(parameters[start:cursor])
    return result


def _parameter_lines(
    method: object,
    names: list[Optional[str]],
    annotations: list[list[str]],
) -> list[str]:
    descriptors = _parameter_descriptors(method.get_descriptor())
    register = 0 if method.get_access_flags() & 0x0008 else 1
    lines: list[str] = []
    for index, descriptor in enumerate(descriptors):
        name = names[index] if index < len(names) else None
        parameter_annotations = (
            annotations[index] if index < len(annotations) else []
        )
        if name is not None or parameter_annotations:
            name_text = f", {_quote_string(name)}" if name is not None else ""
            lines.append(f"    .param p{register}{name_text}    # {descriptor}")
            lines.extend(parameter_annotations)
            if parameter_annotations:
                lines.append("    .end param")
        register += 2 if descriptor in {"J", "D"} else 1
    return lines


def _try_directives(code: object, type_resolver: object) -> TryDirectives:
    starts: Dict[int, list[str]] = {}
    ends: Dict[int, list[str]] = {}
    handler_labels: Dict[int, list[str]] = {}
    handler_list = code.get_handlers()
    if handler_list is None:
        return TryDirectives(starts, ends, handler_labels)

    handlers_by_offset = {
        handler.get_off() - handler_list.get_off(): handler
        for handler in handler_list.get_list()
    }
    catch_targets: set[int] = set()
    catchall_targets: set[int] = set()
    for try_item in code.get_tries():
        handler = handlers_by_offset.get(try_item.get_handler_off())
        if handler is None:
            continue
        catch_targets.update(pair.get_addr() * 2 for pair in handler.get_handlers())
        if handler.get_size() <= 0:
            catchall_targets.add(handler.get_catch_all_addr() * 2)

    catch_labels = {
        target: f":catch_{index:x}"
        for index, target in enumerate(sorted(catch_targets))
    }
    catchall_labels = {
        target: f":catchall_{index:x}"
        for index, target in enumerate(sorted(catchall_targets))
    }
    for target, label in catch_labels.items():
        handler_labels.setdefault(target, []).append(label)
    for target, label in catchall_labels.items():
        handler_labels.setdefault(target, []).append(label)

    for try_index, try_item in enumerate(code.get_tries()):
        start_offset = try_item.get_start_addr() * 2
        end_offset = (
            try_item.get_start_addr() + try_item.get_insn_count()
        ) * 2
        start_label = f":try_start_{try_index:x}"
        end_label = f":try_end_{try_index:x}"
        starts.setdefault(start_offset, []).append(start_label)
        end_lines = [end_label]

        handler = handlers_by_offset.get(try_item.get_handler_off())
        if handler is None:
            ends.setdefault(end_offset, []).extend(end_lines)
            continue

        for pair in handler.get_handlers():
            target_offset = pair.get_addr() * 2
            target_label = catch_labels[target_offset]
            exception_type = type_resolver(pair.get_type_idx())
            end_lines.append(
                f".catch {exception_type} "
                f"{{{start_label} .. {end_label}}} {target_label}"
            )

        if handler.get_size() <= 0:
            target_offset = handler.get_catch_all_addr() * 2
            target_label = catchall_labels[target_offset]
            end_lines.append(
                f".catchall {{{start_label} .. {end_label}}} {target_label}"
            )

        ends.setdefault(end_offset, []).extend(end_lines)

    return TryDirectives(starts, ends, handler_labels)


def _render_array_payload(instruction: object) -> list[str]:
    width = instruction.element_width
    data = instruction.get_data()[: instruction.size * width]
    lines = [f"    .array-data {width}"]
    for offset in range(0, len(data), width):
        raw = data[offset : offset + width]
        if len(raw) != width:
            break
        value = int.from_bytes(raw, "little", signed=True)
        rendered = f"        {_array_literal(value, width)}"
        if width == 4:
            comment = _literal_comment("const", value)
            if comment is not None:
                rendered += f"    # {comment}"
        elif width == 8:
            comment = _literal_comment("const-wide", value)
            if comment is not None:
                rendered += f"    # {comment}"
        lines.append(rendered)
    lines.append("    .end array-data")
    return lines


def _render_switch_payload(
    instruction: object,
    owner_offset: int,
    sparse: bool,
    target_labels: Dict[int, str],
) -> list[str]:
    targets = instruction.get_targets()
    keys = instruction.get_keys()

    if sparse:
        lines = ["    .sparse-switch"]
        for key, target in zip(keys, targets):
            target_offset = owner_offset + target * 2
            lines.append(
                f"        {_hex_literal(key)} -> {target_labels[target_offset]}"
            )
        lines.append("    .end sparse-switch")
    else:
        first_key = keys[0] if keys else 0
        lines = [f"    .packed-switch {_hex_literal(first_key)}"]
        for target in targets:
            target_offset = owner_offset + target * 2
            lines.append(f"        {target_labels[target_offset]}")
        lines.append("    .end packed-switch")
    return lines


def _assign_branch_labels(
    targets_by_kind: Dict[str, set[int]],
) -> tuple[Dict[tuple[str, int], str], Dict[int, list[str]]]:
    labels: Dict[tuple[str, int], str] = {}
    labels_at: Dict[int, list[str]] = {}
    kind_order = [
        "cond",
        "goto",
        "pswitch",
        "sswitch",
        "array",
        "pswitch_data",
        "sswitch_data",
        "label",
    ]
    for kind in kind_order:
        for index, target in enumerate(sorted(targets_by_kind.get(kind, set()))):
            label = f":{kind}_{index:x}"
            labels[(kind, target)] = label
            labels_at.setdefault(target, []).append(label)
    return labels, labels_at


def _format_normal_instruction(
    offset: int,
    instruction: object,
    parameter_start: int,
    target_label: Optional[str],
    string_resolver: Callable[[int], str],
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
            register_text = f"{registers[0]} .. {registers[-1]}"
        else:
            register_text = ", ".join(registers)
        reference = _reference_operand(instruction)
        output = f"{{{register_text}}}"
        if reference:
            output += f", {_format_reference(reference)}"
    elif name in {"const-string", "const-string/jumbo"}:
        registers = [operand for operand in operands if int(operand[0]) == 0]
        string_indexes = [
            int(operand[1])
            for operand in operands
            if len(operand) >= 3
        ]
        if registers and string_indexes:
            output = (
                f"{_register_name(int(registers[0][1]), parameter_start)}, "
                f"{_quote_string(string_resolver(string_indexes[-1]))}"
            )
    else:
        output = _replace_registers(output, parameter_start)
        output = _format_reference(output)
        literals = [operand for operand in operands if int(operand[0]) == 1]
        if literals:
            literal = int(literals[-1][1])
            suffix = "L" if name in {"const-wide", "const-wide/high16"} else ""
            formatted = _hex_literal(literal, suffix)
            output = re.sub(r"(?<=,\s)[-+]?(?:0x[0-9a-fA-F]+|\d+)(?=\s*$)", formatted, output)
            if name in {
                "const/16",
                "const/high16",
                "const",
                "const-wide/16",
                "const-wide/32",
                "const-wide/high16",
                "const-wide",
            }:
                comment = _literal_comment(name, literal)
                if comment is not None:
                    output += f"    # {comment}"

    if target_label:
        output = OFFSET_RE.sub(target_label, output)
    return f"    {name}" + (f" {output}" if output else "")


def disassemble_dex(data: bytes) -> DexDisassembly:
    from loguru import logger

    logger.remove()
    from androguard.core.dex import DEX, Operand, TypeMapItem

    dex = DEX(data)
    string_ids = dex.map_list.get_item_type(TypeMapItem.STRING_ID_ITEM) or []
    string_cache: Dict[int, str] = {}

    def resolve_string(index: int) -> str:
        if index not in string_cache:
            try:
                item = dex.CM.get_string_by_offset(
                    string_ids[index].get_string_data_off()
                )
                string_cache[index] = _decode_mutf8_code_units(item.data)
            except (IndexError, KeyError, UnicodeDecodeError):
                string_cache[index] = dex.CM.get_string(index)
        return string_cache[index]

    annotation_sets = {
        item.get_off(): item
        for item in (
            dex.map_list.get_item_type(TypeMapItem.ANNOTATION_SET_ITEM) or []
        )
    }
    annotation_items = {
        item.get_off(): item
        for item in (dex.map_list.get_item_type(TypeMapItem.ANNOTATION_ITEM) or [])
    }
    annotation_set_ref_lists = {
        item.get_off(): item
        for item in (
            dex.map_list.get_item_type(TypeMapItem.ANNOTATION_SET_REF_LIST) or []
        )
    }
    result: Dict[str, MethodBody] = {}
    field_initializers: Dict[str, str] = {}
    class_annotations: Dict[str, list[str]] = {}
    field_annotations: Dict[str, list[str]] = {}
    method_annotations: Dict[str, list[str]] = {}
    parameter_annotation_sets: Dict[str, list[list[str]]] = {}
    parameter_annotations: Dict[str, list[str]] = {}

    for class_def in dex.get_classes():
        assigned_static_fields: set[str] = set()
        for method in class_def.get_methods():
            if method.get_name() != "<clinit>":
                continue
            for instruction in method.get_instructions():
                if not instruction.get_name().startswith("sput"):
                    continue
                reference = _reference_operand(instruction)
                if reference is not None:
                    assigned_static_fields.add(_format_reference(reference))

        for field in class_def.get_fields():
            initializer = _field_initializer(
                field,
                assigned_static_fields,
                resolve_string,
            )
            if initializer is not None:
                field_initializers[
                    f"{field.get_class_name()}->{field.get_name()}:{field.get_descriptor()}"
                ] = initializer

        directory = class_def.annotations_directory_item
        if directory is None:
            continue
        rendered = _render_annotation_set(
            annotation_sets.get(directory.get_class_annotations_off()),
            annotation_items,
            resolve_string,
        )
        if rendered:
            class_annotations[class_def.get_name()] = rendered

        for field_annotation in directory.get_field_annotations():
            class_name, type_name, field_name = dex.get_cm_field(
                field_annotation.get_field_idx()
            )
            rendered = _render_annotation_set(
                annotation_sets.get(field_annotation.get_annotations_off()),
                annotation_items,
                resolve_string,
                indent="    ",
            )
            if rendered:
                field_annotations[
                    f"{class_name}->{field_name}:{type_name}"
                ] = rendered

        for method_annotation in directory.get_method_annotations():
            class_name, method_name, proto = dex.get_cm_method(
                method_annotation.get_method_idx()
            )
            rendered = _render_annotation_set(
                annotation_sets.get(method_annotation.get_annotations_off()),
                annotation_items,
                resolve_string,
                indent="    ",
            )
            if rendered:
                method_annotations[
                    _method_key(class_name, method_name, "".join(proto))
                ] = rendered

        for parameter_annotation in directory.get_parameter_annotations():
            class_name, method_name, proto = dex.get_cm_method(
                parameter_annotation.get_method_idx()
            )
            annotation_ref_list = annotation_set_ref_lists.get(
                parameter_annotation.get_annotations_off()
            )
            if annotation_ref_list is None:
                continue
            rendered_parameters: list[list[str]] = []
            for annotation_ref in annotation_ref_list.get_list():
                rendered_parameters.append(
                    _render_annotation_set(
                        annotation_sets.get(
                            annotation_ref.get_annotations_off()
                        ),
                        annotation_items,
                        resolve_string,
                        indent="        ",
                    )
                )
            parameter_annotation_sets[
                _method_key(class_name, method_name, "".join(proto))
            ] = rendered_parameters

    for method in dex.get_encoded_methods():
        method_key = _method_key(
            method.get_class_name(),
            method.get_name(),
            method.get_descriptor(),
        )
        code = method.get_code()
        if code is None:
            lines = _parameter_lines(
                method,
                [],
                parameter_annotation_sets.get(method_key, []),
            )
            if lines:
                parameter_annotations[method_key] = lines
            continue

        instructions = list(method.get_instructions_idx())
        payload_owners: Dict[int, tuple[int, str]] = {}
        targets_by_kind: Dict[str, set[int]] = {}

        for offset, instruction in instructions:
            name = instruction.get_name()
            for operand in instruction.get_operands():
                if operand[0] != Operand.OFFSET:
                    continue
                target_offset = offset + int(operand[1]) * 2
                kind = _label_kind(name)
                targets_by_kind.setdefault(kind, set()).add(target_offset)
                if kind in {"pswitch_data", "sswitch_data"}:
                    payload_owners[target_offset] = (offset, kind)

        for offset, instruction in instructions:
            owner = payload_owners.get(offset)
            if owner is None:
                continue
            owner_offset, kind = owner
            target_kind = "sswitch" if kind == "sswitch_data" else "pswitch"
            for target in instruction.get_targets():
                targets_by_kind.setdefault(target_kind, set()).add(
                    owner_offset + target * 2
                )

        branch_labels, labels_at = _assign_branch_labels(targets_by_kind)

        try_directives = _try_directives(code, method.CM.get_type)
        for target, handler_labels in try_directives.handler_labels.items():
            labels_at[target] = handler_labels + labels_at.get(target, [])
        parameter_start = code.get_registers_size() - code.get_ins_size()
        parameter_names = _debug_parameter_names(
            data, code.get_debug_info_off(), resolve_string
        )
        debug_directives = _debug_directives(
            data,
            code.get_debug_info_off(),
            parameter_start,
            resolve_string,
            method.CM.get_type,
            _initial_parameter_locals(method, code, parameter_names),
        )
        lines: list[str] = []
        for offset, instruction in instructions:
            end_directives = try_directives.ends.get(offset, [])
            if end_directives:
                while lines and not lines[-1]:
                    lines.pop()
                for directive in end_directives:
                    lines.append(f"    {directive}")
                lines.append("")

            for directive in debug_directives.get(offset, []):
                lines.append(f"    {directive}")

            for label in labels_at.get(offset, []):
                lines.append(f"    {label}")

            for directive in try_directives.starts.get(offset, []):
                lines.append(f"    {directive}")

            name = instruction.get_name()
            if name == "fill-array-data-payload":
                lines.extend(_render_array_payload(instruction))
                lines.append("")
                continue
            if name in {"packed-switch-payload", "sparse-switch-payload"}:
                owner_offset, kind = payload_owners.get(offset, (offset, "pswitch_data"))
                target_kind = (
                    "sswitch" if kind == "sswitch_data" else "pswitch"
                )
                target_labels = {
                    owner_offset + target * 2: branch_labels[
                        (target_kind, owner_offset + target * 2)
                    ]
                    for target in instruction.get_targets()
                }
                payload_lines = _render_switch_payload(
                    instruction,
                    owner_offset,
                    sparse=kind == "sswitch_data",
                    target_labels=target_labels,
                )
                lines.extend(payload_lines)
                lines.append("")
                continue

            target_label = None
            for operand in instruction.get_operands():
                if operand[0] == Operand.OFFSET:
                    target_offset = offset + int(operand[1]) * 2
                    target_label = branch_labels[
                        (_label_kind(name), target_offset)
                    ]
                    break
            lines.append(
                _format_normal_instruction(
                    offset,
                    instruction,
                    parameter_start,
                    target_label,
                    resolve_string,
                )
            )
            lines.append("")

        code_end = code.get_insns_size() * 2
        end_directives = try_directives.ends.get(code_end, [])
        if end_directives:
            while lines and not lines[-1]:
                lines.pop()
            for directive in end_directives:
                lines.append(f"    {directive}")
            lines.append("")
        for label in labels_at.get(code_end, []):
            lines.append(f"    {label}")
        for directive in try_directives.starts.get(code_end, []):
            lines.append(f"    {directive}")

        while lines and not lines[-1]:
            lines.pop()

        result[method_key] = MethodBody(
            locals_count=code.get_registers_size() - code.get_ins_size(),
            parameter_lines=_parameter_lines(
                method,
                parameter_names,
                parameter_annotation_sets.get(method_key, []),
            ),
            lines=lines,
        )

    return DexDisassembly(
        methods=result,
        field_initializers=field_initializers,
        class_annotations=class_annotations,
        field_annotations=field_annotations,
        method_annotations=method_annotations,
        parameter_annotations=parameter_annotations,
    )
