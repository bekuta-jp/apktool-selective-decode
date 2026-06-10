#!/usr/bin/env python3
"""Prototype non-Java decoder for APK manifest and dex artifacts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import shutil
import sys
import time
import zipfile

from axml_decoder import AxmlDecodeError, decode_axml
from dex_decoder import decode_dex, generate_smali_files
from resource_resolver import ApkResourceResolver, resolve_manifest_attribute


DEX_NAME_RE = re.compile(r"^classes(?:\d+)?\.dex$")


def _safe_mkdir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def _write_text(path: Path, value: str) -> None:
    _safe_mkdir(path.parent)
    path.write_text(value, encoding="utf-8")


def _write_json(path: Path, obj: object) -> None:
    _safe_mkdir(path.parent)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _copy_raw(zipf: zipfile.ZipFile, name: str, out_path: Path) -> None:
    _safe_mkdir(out_path.parent)
    with zipf.open(name, "r") as src, out_path.open("wb") as dst:
        shutil.copyfileobj(src, dst)


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Prototype APK decoder without Java runtime")
    p.add_argument("apk", help="Input APK path")
    p.add_argument("-o", "--out", default="native_decode_out", help="Output directory")
    p.add_argument("--manifest-mode", choices=["decode", "raw", "skip"], default="decode")
    p.add_argument("--dex-mode", choices=["decode", "raw", "skip"], default="decode")
    p.add_argument(
        "--smali-mode",
        choices=["disassemble", "skeleton", "skip"],
        default="disassemble",
        help="Write instruction-level or structural .smali files when dex is decoded.",
    )
    p.add_argument("--preview-limit", type=int, default=32, help="Preview entry count in dex json")
    p.add_argument(
        "--include-signatures",
        action="store_true",
        help="Include full class/method signature lists in dex decoded json (large output).",
    )
    return p.parse_args(argv)


def main(argv: list[str]) -> int:
    args = _parse_args(argv)

    apk_path = Path(args.apk)
    out_dir = Path(args.out)

    if not apk_path.is_file():
        print(f"E: input apk does not exist: {apk_path}", file=sys.stderr)
        return 1

    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    summary = {
        "apk": str(apk_path),
        "out": str(out_dir),
        "manifest_mode": args.manifest_mode,
        "dex_mode": args.dex_mode,
        "manifest": "skip",
        "manifest_error": None,
        "resource_resolution": "not_used",
        "resource_resolution_error": None,
        "dex_total": 0,
        "dex_decoded": 0,
        "dex_raw": 0,
        "smali_mode": args.smali_mode,
        "smali_files": 0,
        "dex_results": [],
        "dex_errors": [],
    }

    print(f"I: reading apk: {apk_path}")

    with zipfile.ZipFile(apk_path, "r") as zipf:
        names = zipf.namelist()

        if "AndroidManifest.xml" in names:
            manifest_name = "AndroidManifest.xml"
            if args.manifest_mode == "skip":
                print("I: manifest skipped")
                summary["manifest"] = "skipped"
            elif args.manifest_mode == "raw":
                out_path = out_dir / "manifest" / "AndroidManifest.xml"
                _copy_raw(zipf, manifest_name, out_path)
                print(f"I: manifest raw copied -> {out_path}")
                summary["manifest"] = "raw"
            else:
                data = zipf.read(manifest_name)
                out_path = out_dir / "manifest" / "AndroidManifest.xml"
                try:
                    arsc_data = zipf.read("resources.arsc") if "resources.arsc" in names else None
                    resolver = ApkResourceResolver(arsc_data)
                    summary["resource_resolution"] = (
                        "apk_and_framework" if resolver.available else "framework_only"
                    )
                    summary["resource_resolution_error"] = resolver.error
                    xml_text = decode_axml(
                        data,
                        resource_resolver=resolver.resolve,
                        attribute_value_resolver=resolve_manifest_attribute,
                        apktool_compatible=True,
                    )
                    _write_text(out_path, xml_text)
                    print(f"I: manifest decoded -> {out_path}")
                    summary["manifest"] = "decoded"
                except AxmlDecodeError as ex:
                    fallback = out_dir / "manifest" / "AndroidManifest.raw.xml"
                    _copy_raw(zipf, manifest_name, fallback)
                    summary["manifest"] = "raw_fallback"
                    summary["manifest_error"] = str(ex)
                    print(f"W: manifest decode failed ({ex}); raw saved -> {fallback}")
        else:
            print("W: AndroidManifest.xml not found")
            summary["manifest"] = "not_found"

        dex_names = sorted(name for name in names if DEX_NAME_RE.match(name))
        summary["dex_total"] = len(dex_names)

        if not dex_names:
            print("W: no classes*.dex found")
        elif args.dex_mode == "skip":
            print(f"I: dex skipped ({len(dex_names)} files)")
        elif args.dex_mode == "raw":
            for dex_name in dex_names:
                started = time.perf_counter()
                out_path = out_dir / "dex" / "raw" / dex_name
                _copy_raw(zipf, dex_name, out_path)
                summary["dex_raw"] += 1
                summary["dex_results"].append(
                    {
                        "dex": dex_name,
                        "status": "raw",
                        "smali_files": 0,
                        "elapsed_sec": round(time.perf_counter() - started, 3),
                    }
                )
            print(f"I: dex raw copied ({summary['dex_raw']}/{summary['dex_total']})")
        else:
            for dex_name in dex_names:
                started = time.perf_counter()
                smali_before = summary["smali_files"]
                data = zipf.read(dex_name)
                out_path = out_dir / "dex" / "decoded" / f"{dex_name}.json"
                try:
                    decoded = decode_dex(
                        data,
                        preview_limit=max(1, args.preview_limit),
                        include_method_signatures=args.include_signatures,
                    )
                    _write_json(out_path, decoded)

                    if args.smali_mode != "skip":
                        smali_root_name = "smali" if dex_name == "classes.dex" else dex_name[:-4].replace("classes", "smali_classes")
                        for rel_path, smali_text in generate_smali_files(
                            data, disassemble=args.smali_mode == "disassemble"
                        ).items():
                            _write_text(out_dir / smali_root_name / rel_path, smali_text)
                            summary["smali_files"] += 1

                    summary["dex_decoded"] += 1
                    dex_result = {
                        "dex": dex_name,
                        "status": "decoded",
                        "classes": decoded["counts"]["classes"],
                        "defined_methods": decoded["counts"]["defined_methods"],
                        "smali_files": summary["smali_files"] - smali_before,
                        "elapsed_sec": round(time.perf_counter() - started, 3),
                    }
                    summary["dex_results"].append(dex_result)
                    print(
                        "I: dex processed | "
                        f"dex={dex_name} classes={dex_result['classes']} "
                        f"smali={dex_result['smali_files']} "
                        f"elapsed={dex_result['elapsed_sec']:.3f}s"
                    )
                except Exception as ex:
                    summary["dex_errors"].append({"dex": dex_name, "error": str(ex)})
                    summary["dex_results"].append(
                        {
                            "dex": dex_name,
                            "status": "error",
                            "error": str(ex),
                            "smali_files": summary["smali_files"] - smali_before,
                            "elapsed_sec": round(time.perf_counter() - started, 3),
                        }
                    )
                    print(f"W: dex decode failed for {dex_name}: {ex}")

            print(
                f"I: dex decoded ({summary['dex_decoded']}/{summary['dex_total']}); "
                f"smali_files={summary['smali_files']}"
            )

    _write_json(out_dir / "summary.json", summary)
    print("I: summary written ->", out_dir / "summary.json")
    print(
        "I: done | "
        f"manifest={summary['manifest']} | "
        f"dex_total={summary['dex_total']} dex_decoded={summary['dex_decoded']} "
        f"dex_raw={summary['dex_raw']} smali_files={summary['smali_files']}"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
