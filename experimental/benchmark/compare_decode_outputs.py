#!/usr/bin/env python3
"""Benchmark decoder outputs across original, selective, and Python implementations."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import random
import re
import shlex
import shutil
import subprocess
import sys
import time
from typing import Dict, Iterable, List, Optional, Tuple
import xml.etree.ElementTree as ET


SMALI_TOP_DIR_RE = re.compile(r"^smali(?:_classes(\d+))?$")
SMALI_CLASS_RE = re.compile(r"^\.class\b.*\s(L[^;\s]+;)\s*$")
SMALI_METHOD_RE = re.compile(r"^\.method\b.*\s([^\s(]+)\(([^)]*)\)(\S+)\s*$")


def _now() -> str:
    return dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hash_lines(lines: Iterable[str]) -> str:
    h = hashlib.sha256()
    for line in sorted(set(lines)):
        h.update(line.encode("utf-8", errors="replace"))
        h.update(b"\n")
    return h.hexdigest()


def _hash_mapping(mapping: Dict[str, str]) -> str:
    h = hashlib.sha256()
    for key in sorted(mapping):
        h.update(key.encode("utf-8", errors="replace"))
        h.update(b"\0")
        h.update(mapping[key].encode("ascii", errors="replace"))
        h.update(b"\n")
    return h.hexdigest()


def _canonical_manifest_hash(data: bytes) -> Tuple[str, Optional[str]]:
    try:
        root = ET.fromstring(data)
    except ET.ParseError as ex:
        text = data.decode("utf-8", errors="replace")
        normalized = "\n".join(line.strip() for line in text.splitlines() if line.strip())
        return _sha256_bytes(normalized.encode("utf-8")), str(ex)

    rows: List[Tuple[str, object]] = []

    def walk(node: ET.Element) -> None:
        attrs = sorted((k, v) for k, v in node.attrib.items())
        text = (node.text or "").strip()
        rows.append(("start", (node.tag, attrs, text)))
        for child in list(node):
            walk(child)
        rows.append(("end", node.tag))

    walk(root)
    canonical = json.dumps(rows, ensure_ascii=False, separators=(",", ":"))
    return _sha256_bytes(canonical.encode("utf-8")), None


def _read_manifest(out_dir: Path) -> Dict[str, object]:
    candidates = [
        out_dir / "AndroidManifest.xml",
        out_dir / "manifest" / "AndroidManifest.xml",
        out_dir / "manifest" / "AndroidManifest.raw.xml",
        out_dir / "original" / "AndroidManifest.xml",
    ]
    manifest_path = next((p for p in candidates if p.is_file()), None)
    if manifest_path is None:
        return {"present": False}

    data = manifest_path.read_bytes()
    canonical_hash, canonical_error = _canonical_manifest_hash(data)
    return {
        "present": True,
        "path": str(manifest_path),
        "size": len(data),
        "sha256": _sha256_bytes(data),
        "canonical_sha256": canonical_hash,
        "canonical_error": canonical_error,
        "text": data.decode("utf-8", errors="replace"),
    }


def _dex_name_from_smali_top_dir(name: str) -> Optional[str]:
    match = SMALI_TOP_DIR_RE.match(name)
    if not match:
        return None
    number = match.group(1)
    if number is None:
        return "classes.dex"
    return f"classes{number}.dex"


def _collect_java_outputs(out_dir: Path) -> Dict[str, object]:
    smali_hashes: Dict[str, str] = {}
    dex_classes: Dict[str, set[str]] = {}
    dex_methods: Dict[str, set[str]] = {}

    for child in sorted(out_dir.iterdir()):
        if not child.is_dir():
            continue
        dex_name = _dex_name_from_smali_top_dir(child.name)
        if dex_name is None:
            continue

        class_set = dex_classes.setdefault(dex_name, set())
        method_set = dex_methods.setdefault(dex_name, set())

        for smali_path in sorted(child.rglob("*.smali")):
            rel_path = smali_path.relative_to(out_dir).as_posix()
            raw = smali_path.read_bytes()
            smali_hashes[rel_path] = _sha256_bytes(raw)

            class_desc: Optional[str] = None
            text = raw.decode("utf-8", errors="replace")
            for line in text.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if class_desc is None:
                    class_match = SMALI_CLASS_RE.match(stripped)
                    if class_match:
                        class_desc = class_match.group(1)
                        class_set.add(class_desc)
                        continue

                if class_desc is None:
                    continue

                method_match = SMALI_METHOD_RE.match(stripped)
                if method_match:
                    method_name, params, ret = method_match.groups()
                    method_set.add(f"{class_desc}->{method_name}({params}){ret}")

    dex_signatures: Dict[str, Dict[str, object]] = {}
    for dex_name in sorted(set(dex_classes) | set(dex_methods)):
        class_set = dex_classes.get(dex_name, set())
        method_set = dex_methods.get(dex_name, set())
        dex_signatures[dex_name] = {
            "class_count": len(class_set),
            "class_hash": _hash_lines(class_set),
            "method_signature_count": len(method_set),
            "method_signature_hash": _hash_lines(method_set),
        }

    return {
        "manifest": _read_manifest(out_dir),
        "smali_hashes": smali_hashes,
        "smali_summary": {
            "file_count": len(smali_hashes),
            "aggregate_hash": _hash_mapping(smali_hashes),
        },
        "dex_signatures": dex_signatures,
    }


def _collect_python_outputs(out_dir: Path) -> Dict[str, object]:
    smali_artifacts = _collect_java_outputs(out_dir)
    dex_signatures: Dict[str, Dict[str, object]] = {}
    decoded_dir = out_dir / "dex" / "decoded"
    if decoded_dir.is_dir():
        for dex_json_path in sorted(decoded_dir.glob("*.json")):
            obj = json.loads(dex_json_path.read_text(encoding="utf-8"))
            signatures = obj.get("signatures", {})
            dex_name = dex_json_path.name[:-5] if dex_json_path.name.endswith(".json") else dex_json_path.name
            dex_signatures[dex_name] = {
                "class_count": int(signatures.get("class_count", 0)),
                "class_hash": str(signatures.get("class_hash", "")),
                "method_signature_count": int(signatures.get("method_signature_count", 0)),
                "method_signature_hash": str(signatures.get("method_signature_hash", "")),
            }

    summary = {}
    summary_path = out_dir / "summary.json"
    if summary_path.is_file():
        summary = json.loads(summary_path.read_text(encoding="utf-8"))

    return {
        "manifest": smali_artifacts.get("manifest", _read_manifest(out_dir)),
        "smali_hashes": smali_artifacts.get("smali_hashes", {}),
        "smali_summary": smali_artifacts.get("smali_summary", {}),
        "dex_signatures": smali_artifacts.get("dex_signatures", {}) or dex_signatures,
        "json_dex_signatures": dex_signatures,
        "summary": summary,
    }


def _compare_manifest(a: Dict[str, object], b: Dict[str, object]) -> Dict[str, object]:
    if not a.get("present", False) and not b.get("present", False):
        return {"status": "same", "reason": "manifest_missing_both"}
    if not a.get("present", False) or not b.get("present", False):
        return {"status": "error", "reason": "manifest_missing_one_side"}

    left = str(a.get("canonical_sha256"))
    right = str(b.get("canonical_sha256"))
    if left == right:
        return {"status": "same", "left_hash": left, "right_hash": right}
    return {"status": "different", "left_hash": left, "right_hash": right}


def _compare_smali_hashes(a: Dict[str, str], b: Dict[str, str]) -> Dict[str, object]:
    missing = sorted(set(a) - set(b))
    extra = sorted(set(b) - set(a))
    mismatched = sorted(path for path in (set(a) & set(b)) if a[path] != b[path])
    if not missing and not extra and not mismatched:
        return {"status": "same"}
    return {
        "status": "different",
        "missing_count": len(missing),
        "extra_count": len(extra),
        "mismatched_count": len(mismatched),
        "missing_sample": missing[:20],
        "extra_sample": extra[:20],
        "mismatched_sample": mismatched[:20],
    }


def _compare_dex_signatures(
    java_signatures: Dict[str, Dict[str, object]],
    python_signatures: Dict[str, Dict[str, object]],
) -> Dict[str, object]:
    java_dex = set(java_signatures)
    python_dex = set(python_signatures)
    missing = sorted(java_dex - python_dex)
    extra = sorted(python_dex - java_dex)

    mismatches: Dict[str, Dict[str, Tuple[object, object]]] = {}
    for dex_name in sorted(java_dex & python_dex):
        left = java_signatures[dex_name]
        right = python_signatures[dex_name]
        fields = (
            "class_count",
            "class_hash",
            "method_signature_count",
            "method_signature_hash",
        )
        diff_fields = {
            field: (left.get(field), right.get(field))
            for field in fields
            if left.get(field) != right.get(field)
        }
        if diff_fields:
            mismatches[dex_name] = diff_fields

    if not missing and not extra and not mismatches:
        return {"status": "same"}
    return {
        "status": "different",
        "missing_count": len(missing),
        "extra_count": len(extra),
        "mismatched_dex_count": len(mismatches),
        "missing_sample": missing[:20],
        "extra_sample": extra[:20],
        "mismatch_sample": dict(list(mismatches.items())[:20]),
    }


def _manifest_without_text(manifest: Dict[str, object]) -> Dict[str, object]:
    if not manifest:
        return {"present": False}
    result = dict(manifest)
    result.pop("text", None)
    return result


def _run_command(
    command: List[str],
    stdout_path: Path,
    stderr_path: Path,
    timeout_seconds: int,
) -> Dict[str, object]:
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    try:
        with stdout_path.open("wb") as stdout_fp, stderr_path.open("wb") as stderr_fp:
            proc = subprocess.run(
                command,
                stdout=stdout_fp,
                stderr=stderr_fp,
                timeout=timeout_seconds,
                check=False,
            )
        elapsed = round(time.perf_counter() - started, 3)
        status = "ok" if proc.returncode == 0 else "error"
        return {
            "status": status,
            "exit_code": proc.returncode,
            "elapsed_sec": elapsed,
            "stdout_log": str(stdout_path),
            "stderr_log": str(stderr_path),
            "command": shlex.join(command),
        }
    except subprocess.TimeoutExpired:
        elapsed = round(time.perf_counter() - started, 3)
        return {
            "status": "error",
            "exit_code": None,
            "elapsed_sec": elapsed,
            "stdout_log": str(stdout_path),
            "stderr_log": str(stderr_path),
            "command": shlex.join(command),
            "error": f"timeout_after_{timeout_seconds}s",
        }
    except OSError as ex:
        elapsed = round(time.perf_counter() - started, 3)
        return {
            "status": "error",
            "exit_code": None,
            "elapsed_sec": elapsed,
            "stdout_log": str(stdout_path),
            "stderr_log": str(stderr_path),
            "command": shlex.join(command),
            "error": f"{type(ex).__name__}: {ex}",
        }


def _cleanup_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)


def _write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _log(message: str, run_log_path: Path) -> None:
    line = f"{_now()} {message}"
    print(line)
    run_log_path.parent.mkdir(parents=True, exist_ok=True)
    with run_log_path.open("a", encoding="utf-8") as fp:
        fp.write(line + "\n")


def _free_gb(path: Path) -> float:
    usage = shutil.disk_usage(path)
    return usage.free / (1024 ** 3)


def _build_parser(default_python_decoder: Path) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Compare original Apktool, selective Apktool, and Python prototype outputs."
    )
    parser.add_argument(
        "--apk-dir",
        default="/Volumes/bekuta/dataset12000/test/benign",
        help="Directory containing APK files.",
    )
    parser.add_argument(
        "--nas-root",
        default="/Volumes/bekuta/codex",
        help="Root directory for logs/results on NAS.",
    )
    parser.add_argument(
        "--tmpfs-root",
        default="/private/tmp/mem",
        help="tmpfs base directory for decode work.",
    )
    parser.add_argument("--sample-size", type=int, default=100, help="Number of random APKs to sample.")
    parser.add_argument("--seed", type=int, default=1337, help="Random seed for reproducible sampling.")
    parser.add_argument(
        "--run-id",
        default="",
        help="Optional run identifier. If omitted, timestamp is used.",
    )
    parser.add_argument(
        "--work-subdir",
        default="apktool-selective-benchmark",
        help="Output subdirectory under --nas-root.",
    )
    parser.add_argument(
        "--apktool-original-cmd",
        default="apktool",
        help="Base command for original decode mode.",
    )
    parser.add_argument(
        "--apktool-selective-cmd",
        default="",
        help="Base command for selective decode mode. Defaults to --apktool-original-cmd.",
    )
    parser.add_argument(
        "--frame-path",
        default="",
        help="Apktool framework directory. Defaults to <tmpfs>/.../framework for each run.",
    )
    parser.add_argument(
        "--python-bin",
        default="python3",
        help="Python interpreter for the prototype decoder.",
    )
    parser.add_argument(
        "--python-decoder",
        default=str(default_python_decoder),
        help="Path to experimental/python_port/apk_native_decode.py",
    )
    parser.add_argument(
        "--python-preview-limit",
        type=int,
        default=16,
        help="Preview limit passed to Python decoder.",
    )
    parser.add_argument(
        "--python-include-signatures",
        action="store_true",
        help="Pass --include-signatures to Python decoder for deeper debug output.",
    )
    parser.add_argument(
        "--selective-no-assets",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Use --no-assets in selective Apktool mode.",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=1800,
        help="Per-command timeout in seconds.",
    )
    parser.add_argument(
        "--min-free-gb",
        type=float,
        default=0.5,
        help="Skip mode execution when tmpfs free space is below this threshold.",
    )
    parser.add_argument(
        "--keep-tmp",
        action="store_true",
        help="Keep tmpfs working directories (for debugging).",
    )
    return parser


def main(argv: List[str]) -> int:
    script_dir = Path(__file__).resolve().parent
    repo_root = script_dir.parent.parent
    default_python_decoder = repo_root / "experimental" / "python_port" / "apk_native_decode.py"
    parser = _build_parser(default_python_decoder=default_python_decoder)
    args = parser.parse_args(argv)

    apk_dir = Path(args.apk_dir)
    nas_root = Path(args.nas_root)
    tmpfs_root = Path(args.tmpfs_root)
    python_decoder = Path(args.python_decoder)

    if not apk_dir.is_dir():
        print(f"E: apk directory not found: {apk_dir}", file=sys.stderr)
        return 1
    if not python_decoder.is_file():
        print(f"E: python decoder not found: {python_decoder}", file=sys.stderr)
        return 1

    run_id = args.run_id or dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    run_root = nas_root / args.work_subdir / run_id
    run_log = run_root / "run.log"
    results_dir = run_root / "results"
    lists_dir = run_root / "lists"
    artifacts_dir = run_root / "artifacts"
    tmp_run_root = tmpfs_root / "apktool-selective-benchmark" / run_id
    frame_path = Path(args.frame_path) if args.frame_path else tmp_run_root / "framework"

    for path in (run_root, results_dir, lists_dir, artifacts_dir):
        path.mkdir(parents=True, exist_ok=True)
    tmp_run_root.mkdir(parents=True, exist_ok=True)

    original_cmd_base = shlex.split(args.apktool_original_cmd)
    selective_cmd_base = shlex.split(args.apktool_selective_cmd) if args.apktool_selective_cmd else original_cmd_base

    apks = sorted(
        [path for path in apk_dir.iterdir() if path.is_file() and path.suffix.lower() == ".apk"],
        key=lambda p: p.name,
    )
    if not apks:
        _log(f"E: no apk files found in {apk_dir}", run_log)
        return 1

    sample_size = min(args.sample_size, len(apks))
    rng = random.Random(args.seed)
    sampled_apks = rng.sample(apks, sample_size)

    config = {
        "started_at": _now(),
        "run_id": run_id,
        "apk_dir": str(apk_dir),
        "nas_root": str(nas_root),
        "tmpfs_root": str(tmpfs_root),
        "sample_size": sample_size,
        "seed": args.seed,
        "apktool_original_cmd": original_cmd_base,
        "apktool_selective_cmd": selective_cmd_base,
        "python_bin": args.python_bin,
        "python_decoder": str(python_decoder),
        "python_preview_limit": args.python_preview_limit,
        "python_include_signatures": args.python_include_signatures,
        "selective_no_assets": args.selective_no_assets,
        "frame_path": str(frame_path),
        "timeout_seconds": args.timeout_seconds,
        "min_free_gb": args.min_free_gb,
        "keep_tmp": args.keep_tmp,
    }
    _write_json(run_root / "config.json", config)
    (run_root / "sample_apks.txt").write_text(
        "\n".join(path.name for path in sampled_apks) + "\n",
        encoding="utf-8",
    )

    _log(f"I: run_id={run_id}", run_log)
    _log(f"I: sampled {sample_size}/{len(apks)} APKs from {apk_dir}", run_log)
    _log(f"I: tmpfs working root: {tmp_run_root}", run_log)
    _log(f"I: output root: {run_root}", run_log)

    all_records: List[Dict[str, object]] = []
    results_jsonl_path = results_dir / "results.jsonl"
    if results_jsonl_path.exists():
        results_jsonl_path.unlink()

    for index, apk_path in enumerate(sampled_apks, start=1):
        apk_id = f"{index:04d}_{apk_path.stem}"
        _log(f"I: [{index}/{sample_size}] start {apk_path.name}", run_log)

        apk_tmp_root = tmp_run_root / apk_id
        mode_logs_dir = run_root / "logs" / apk_id
        mode_logs_dir.mkdir(parents=True, exist_ok=True)
        _cleanup_dir(apk_tmp_root)
        apk_tmp_root.mkdir(parents=True, exist_ok=True)

        mode_records: Dict[str, Dict[str, object]] = {}
        mode_artifacts: Dict[str, Dict[str, object]] = {}

        commands = {
            "original": original_cmd_base
            + [
                "d",
                str(apk_path),
                "-f",
                "-p",
                str(frame_path),
                "-o",
                str(apk_tmp_root / "original"),
            ],
            "selective": selective_cmd_base
            + [
                "d",
                str(apk_path),
                "-f",
                "-p",
                str(frame_path),
                "-o",
                str(apk_tmp_root / "selective"),
                "--dex-mode",
                "decode",
                "--manifest-mode",
                "decode",
                "--res-mode",
                "skip",
            ],
            "python": [
                args.python_bin,
                str(python_decoder),
                str(apk_path),
                "-o",
                str(apk_tmp_root / "python"),
                "--manifest-mode",
                "decode",
                "--dex-mode",
                "decode",
                "--preview-limit",
                str(args.python_preview_limit),
                "--smali-mode",
                "skeleton",
            ],
        }
        if args.selective_no_assets:
            commands["selective"].append("--no-assets")
        if args.python_include_signatures:
            commands["python"].append("--include-signatures")

        for mode_name in ("original", "selective", "python"):
            out_dir = apk_tmp_root / mode_name
            _cleanup_dir(out_dir)

            free_before = _free_gb(tmpfs_root)
            _log(f"I: [{apk_path.name}] tmpfs free before {mode_name}: {free_before:.2f} GB", run_log)
            if free_before < args.min_free_gb:
                mode_records[mode_name] = {
                    "status": "error",
                    "exit_code": None,
                    "elapsed_sec": 0.0,
                    "stdout_log": str(mode_logs_dir / f"{mode_name}.stdout.log"),
                    "stderr_log": str(mode_logs_dir / f"{mode_name}.stderr.log"),
                    "command": shlex.join(commands[mode_name]),
                    "error": f"insufficient_tmpfs_free_space: {free_before:.2f}GB < {args.min_free_gb:.2f}GB",
                }
                mode_artifacts[mode_name] = {}
                _log(
                    f"W: [{apk_path.name}] skip {mode_name} due to tmpfs free space threshold",
                    run_log,
                )
                continue

            _log(f"I: [{apk_path.name}] run {mode_name}", run_log)
            mode_result = _run_command(
                command=commands[mode_name],
                stdout_path=mode_logs_dir / f"{mode_name}.stdout.log",
                stderr_path=mode_logs_dir / f"{mode_name}.stderr.log",
                timeout_seconds=args.timeout_seconds,
            )
            mode_records[mode_name] = mode_result

            if mode_result["status"] == "ok":
                try:
                    if mode_name in ("original", "selective"):
                        mode_artifacts[mode_name] = _collect_java_outputs(out_dir)
                    else:
                        mode_artifacts[mode_name] = _collect_python_outputs(out_dir)
                except Exception as ex:  # pragma: no cover
                    mode_records[mode_name]["status"] = "error"
                    mode_records[mode_name]["error"] = f"collect_failed: {type(ex).__name__}: {ex}"
            else:
                mode_artifacts[mode_name] = {}

            if not args.keep_tmp:
                _cleanup_dir(out_dir)

            free_after = _free_gb(tmpfs_root)
            _log(f"I: [{apk_path.name}] tmpfs free after {mode_name}: {free_after:.2f} GB", run_log)

        compare_manifest_original_selective: Dict[str, object]
        compare_smali_original_selective: Dict[str, object]
        compare_manifest_original_python: Dict[str, object]
        compare_dexsig_original_python: Dict[str, object]

        if mode_records["original"]["status"] == "ok" and mode_records["selective"]["status"] == "ok":
            compare_manifest_original_selective = _compare_manifest(
                mode_artifacts["original"].get("manifest", {"present": False}),
                mode_artifacts["selective"].get("manifest", {"present": False}),
            )
            compare_smali_original_selective = _compare_smali_hashes(
                mode_artifacts["original"].get("smali_hashes", {}),
                mode_artifacts["selective"].get("smali_hashes", {}),
            )
        else:
            compare_manifest_original_selective = {
                "status": "error",
                "reason": "original_or_selective_failed",
            }
            compare_smali_original_selective = {
                "status": "error",
                "reason": "original_or_selective_failed",
            }

        if mode_records["original"]["status"] == "ok" and mode_records["python"]["status"] == "ok":
            compare_manifest_original_python = _compare_manifest(
                mode_artifacts["original"].get("manifest", {"present": False}),
                mode_artifacts["python"].get("manifest", {"present": False}),
            )
            compare_dexsig_original_python = _compare_dex_signatures(
                mode_artifacts["original"].get("dex_signatures", {}),
                mode_artifacts["python"].get("dex_signatures", {}),
            )
        else:
            compare_manifest_original_python = {
                "status": "error",
                "reason": "original_or_python_failed",
            }
            compare_dexsig_original_python = {
                "status": "error",
                "reason": "original_or_python_failed",
            }

        any_mode_error = any(mode_records[mode]["status"] != "ok" for mode in mode_records)
        compare_statuses = [
            compare_manifest_original_selective["status"],
            compare_smali_original_selective["status"],
            compare_manifest_original_python["status"],
            compare_dexsig_original_python["status"],
        ]
        if any_mode_error or any(status == "error" for status in compare_statuses):
            category = "error"
        elif all(status == "same" for status in compare_statuses):
            category = "same"
        else:
            category = "different"

        record = {
            "apk_name": apk_path.name,
            "apk_path": str(apk_path),
            "apk_id": apk_id,
            "category": category,
            "modes": mode_records,
            "mode_summaries": {
                "original": {
                    "manifest": _manifest_without_text(
                        mode_artifacts.get("original", {}).get("manifest", {"present": False})
                    ),
                    "smali_summary": mode_artifacts.get("original", {}).get("smali_summary", {}),
                    "dex_signature_dex_count": len(mode_artifacts.get("original", {}).get("dex_signatures", {})),
                },
                "selective": {
                    "manifest": _manifest_without_text(
                        mode_artifacts.get("selective", {}).get("manifest", {"present": False})
                    ),
                    "smali_summary": mode_artifacts.get("selective", {}).get("smali_summary", {}),
                    "dex_signature_dex_count": len(mode_artifacts.get("selective", {}).get("dex_signatures", {})),
                },
                "python": {
                    "manifest": _manifest_without_text(
                        mode_artifacts.get("python", {}).get("manifest", {"present": False})
                    ),
                    "smali_summary": mode_artifacts.get("python", {}).get("smali_summary", {}),
                    "dex_signature_dex_count": len(mode_artifacts.get("python", {}).get("dex_signatures", {})),
                    "summary": mode_artifacts.get("python", {}).get("summary", {}),
                },
            },
            "comparisons": {
                "manifest_original_vs_selective": compare_manifest_original_selective,
                "smali_original_vs_selective": compare_smali_original_selective,
                "manifest_original_vs_python": compare_manifest_original_python,
                "dex_signatures_original_vs_python": compare_dexsig_original_python,
            },
        }
        all_records.append(record)

        with results_jsonl_path.open("a", encoding="utf-8") as fp:
            fp.write(json.dumps(record, ensure_ascii=False) + "\n")

        if category != "same":
            case_dir = artifacts_dir / category / apk_id
            case_dir.mkdir(parents=True, exist_ok=True)
            for mode_name in ("original", "selective", "python"):
                mode_artifact = mode_artifacts.get(mode_name, {})
                manifest = mode_artifact.get("manifest", {})
                manifest_text = manifest.get("text")
                if manifest.get("present", False) and isinstance(manifest_text, str):
                    (case_dir / f"{mode_name}.AndroidManifest.xml").write_text(manifest_text, encoding="utf-8")
                if mode_name in ("original", "selective"):
                    _write_json(case_dir / f"{mode_name}.smali_summary.json", mode_artifact.get("smali_summary", {}))
                    _write_json(case_dir / f"{mode_name}.dex_signatures.json", mode_artifact.get("dex_signatures", {}))
                else:
                    _write_json(case_dir / "python.smali_summary.json", mode_artifact.get("smali_summary", {}))
                    _write_json(case_dir / "python.dex_signatures.json", mode_artifact.get("dex_signatures", {}))
                    _write_json(
                        case_dir / "python.json_dex_signatures.json",
                        mode_artifact.get("json_dex_signatures", {}),
                    )
                    _write_json(case_dir / "python.summary.json", mode_artifact.get("summary", {}))
            _write_json(case_dir / "comparisons.json", record["comparisons"])

        if not args.keep_tmp:
            _cleanup_dir(apk_tmp_root)

        _log(f"I: [{index}/{sample_size}] done {apk_path.name} -> {category}", run_log)

    same_names = sorted(record["apk_name"] for record in all_records if record["category"] == "same")
    different_names = sorted(record["apk_name"] for record in all_records if record["category"] == "different")
    error_names = sorted(record["apk_name"] for record in all_records if record["category"] == "error")

    (lists_dir / "same.txt").write_text("\n".join(same_names) + ("\n" if same_names else ""), encoding="utf-8")
    (lists_dir / "different.txt").write_text(
        "\n".join(different_names) + ("\n" if different_names else ""),
        encoding="utf-8",
    )
    (lists_dir / "error.txt").write_text("\n".join(error_names) + ("\n" if error_names else ""), encoding="utf-8")

    def count_by_status(key: str) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for record in all_records:
            status = record["comparisons"][key]["status"]
            counts[status] = counts.get(status, 0) + 1
        return counts

    summary = {
        "finished_at": _now(),
        "run_id": run_id,
        "total": len(all_records),
        "same_count": len(same_names),
        "different_count": len(different_names),
        "error_count": len(error_names),
        "same_apks": same_names,
        "different_apks": different_names,
        "error_apks": error_names,
        "comparison_status_counts": {
            "manifest_original_vs_selective": count_by_status("manifest_original_vs_selective"),
            "smali_original_vs_selective": count_by_status("smali_original_vs_selective"),
            "manifest_original_vs_python": count_by_status("manifest_original_vs_python"),
            "dex_signatures_original_vs_python": count_by_status("dex_signatures_original_vs_python"),
        },
    }
    _write_json(run_root / "summary.json", summary)

    summary_lines = [
        f"run_id: {run_id}",
        f"total: {summary['total']}",
        f"same: {summary['same_count']}",
        f"different: {summary['different_count']}",
        f"error: {summary['error_count']}",
        "",
        "[same]",
        *same_names,
        "",
        "[different]",
        *different_names,
        "",
        "[error]",
        *error_names,
        "",
    ]
    (run_root / "summary.txt").write_text("\n".join(summary_lines), encoding="utf-8")

    csv_path = results_dir / "results.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as fp:
        import csv

        writer = csv.writer(fp)
        writer.writerow(
            [
                "apk_name",
                "category",
                "original_status",
                "selective_status",
                "python_status",
                "manifest_orig_sel",
                "smali_orig_sel",
                "manifest_orig_py",
                "dexsig_orig_py",
            ]
        )
        for record in all_records:
            writer.writerow(
                [
                    record["apk_name"],
                    record["category"],
                    record["modes"]["original"]["status"],
                    record["modes"]["selective"]["status"],
                    record["modes"]["python"]["status"],
                    record["comparisons"]["manifest_original_vs_selective"]["status"],
                    record["comparisons"]["smali_original_vs_selective"]["status"],
                    record["comparisons"]["manifest_original_vs_python"]["status"],
                    record["comparisons"]["dex_signatures_original_vs_python"]["status"],
                ]
            )

    _log("I: finished", run_log)
    _log(f"I: summary -> {run_root / 'summary.json'}", run_log)
    _log(f"I: same={len(same_names)} different={len(different_names)} error={len(error_names)}", run_log)

    if not args.keep_tmp:
        _cleanup_dir(tmp_run_root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
