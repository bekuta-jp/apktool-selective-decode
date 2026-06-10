#!/usr/bin/env python3
"""Resource-name and Android manifest attribute resolution helpers."""

from __future__ import annotations

from functools import lru_cache
import json
from pathlib import Path
from typing import Dict, Optional


TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
INTEGER_TYPES = {TYPE_INT_DEC, TYPE_INT_HEX}


@lru_cache(maxsize=1)
def _framework_data() -> Dict[str, object]:
    path = Path(__file__).with_name("data") / "framework_resources.json"
    return json.loads(path.read_text(encoding="utf-8"))


def resolve_framework_reference(resource_id: int) -> Optional[str]:
    names = _framework_data()["resources"]
    return names.get(f"{resource_id:08x}")


def _java_signed_int(value: int) -> int:
    return value if value < 0x80000000 else value - 0x100000000


def _format_flags(symbols: list[list[object]], data: int) -> Optional[str]:
    ordered = sorted(
        symbols,
        key=lambda symbol: (
            -int(symbol[0]).bit_count(),
            _java_signed_int(int(symbol[0])),
        ),
    )

    selected: list[list[object]] = []
    if data == 0:
        selected = [symbol for symbol in ordered if int(symbol[0]) == 0]
    else:
        mask = 0
        for symbol in ordered:
            flag = int(symbol[0])
            if (data & flag) != flag or (mask & flag) == flag:
                continue
            selected.append(symbol)
            mask |= flag
            if mask == data:
                break

        if len(selected) > 2:
            filtered: list[list[object]] = []
            for index, symbol in enumerate(selected):
                other_mask = 0
                for other_index, other in enumerate(selected):
                    if other_index != index:
                        other_mask |= int(other[0])
                if int(symbol[0]) & ~other_mask:
                    filtered.append(symbol)
            selected = filtered

    if not selected:
        return None
    return "|".join(str(symbol[1]) for symbol in selected)


def resolve_framework_attribute(
    attribute_id: int, value_type: int, value_data: int
) -> Optional[str]:
    if value_type not in INTEGER_TYPES:
        return None

    attrs = _framework_data()["attributes"]
    attr = attrs.get(f"{attribute_id:08x}")
    if not attr:
        return None

    symbols = attr["symbols"]
    if attr["kind"] == "enum":
        for value, name in symbols:
            if int(value) == value_data:
                return str(name)
        return None
    return _format_flags(symbols, value_data)


class ApkResourceResolver:
    """Resolve names from an APK resources.arsc without writing resources."""

    def __init__(self, arsc_bytes: Optional[bytes]) -> None:
        self._parser = None
        self._packages: set[str] = set()
        self.error: Optional[str] = None

        if not arsc_bytes:
            return

        try:
            from loguru import logger

            logger.remove()
            from androguard.core.axml import ARSCParser

            self._parser = ARSCParser(arsc_bytes)
            self._packages = set(self._parser.get_packages_names())
        except Exception as ex:
            self.error = str(ex)
            self._parser = None

    @property
    def available(self) -> bool:
        return self._parser is not None

    def resolve(self, resource_id: int) -> Optional[str]:
        framework = resolve_framework_reference(resource_id)
        if framework:
            return framework
        if self._parser is None:
            return None

        try:
            name = self._parser.get_resource_xml_name(resource_id)
        except Exception:
            return None
        if not name:
            return None

        for package in self._packages:
            prefix = f"@{package}:"
            if name.startswith(prefix):
                return "@" + name[len(prefix) :]
        return name


def resolve_manifest_attribute(
    attribute_id: int, value_type: int, value_data: int
) -> Optional[str]:
    return resolve_framework_attribute(attribute_id, value_type, value_data)
