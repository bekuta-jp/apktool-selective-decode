#!/usr/bin/env python3
"""Generate the compact framework resource table used by the Python decoder."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import zipfile


ATTR_TYPE = 0x01000000
ATTR_TYPE_ENUM = 0x00010000
ATTR_TYPE_FLAGS = 0x00020000


def _resource_name(parser: object, resource_id: int) -> str | None:
    name = parser.get_resource_xml_name(resource_id)
    return name or None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("framework_jar")
    parser.add_argument("output")
    args = parser.parse_args()

    from loguru import logger

    logger.remove()
    from androguard.core.axml import ARSCParser

    with zipfile.ZipFile(args.framework_jar) as framework:
        resources = ARSCParser(framework.read("resources.arsc"))
    resources._analyse()

    names: dict[str, str] = {}
    attributes: dict[str, object] = {}

    for resource_id, configured_entries in resources.resource_values.items():
        name = _resource_name(resources, resource_id)
        if name:
            names[f"{resource_id:08x}"] = name

        entry = next(iter(configured_entries.values()), None)
        if entry is None or not entry.is_complex():
            continue

        attr_type = 0
        symbols: list[list[object]] = []
        for symbol_id, value in entry.item.items:
            if symbol_id == ATTR_TYPE:
                attr_type = value.data
                continue
            if symbol_id < 0x01000004:
                continue
            symbol_name = _resource_name(resources, symbol_id)
            if not symbol_name:
                continue
            symbols.append([value.data, symbol_name.rsplit("/", 1)[-1]])

        if not symbols:
            continue
        if attr_type & ATTR_TYPE_ENUM:
            kind = "enum"
        elif attr_type & ATTR_TYPE_FLAGS:
            kind = "flags"
        else:
            continue
        attributes[f"{resource_id:08x}"] = {"kind": kind, "symbols": symbols}

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(
            {"resources": names, "attributes": attributes},
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    print(
        f"wrote {output}: resources={len(names)} attributes={len(attributes)} "
        f"bytes={output.stat().st_size}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
