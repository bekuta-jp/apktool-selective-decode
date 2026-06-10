#!/usr/bin/env python3
"""Run the Python decoder against stored Java reference outputs."""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import time
from typing import Dict, Iterable, List, Optional, Tuple
import xml.etree.ElementTree as ET


SMALI_DIR_RE = re.compile(r"^smali(?:_classes\d+)?$")
SMALI_CLASS_RE = re.compile(r"^\.class\b.*\s(L[^;\s]+;)\s*$")
SMALI_METHOD_RE = re.compile(r"^\.method\b.*\s([^\s(]+)\(([^)]*)\)(\S+)\s*$")


def _now_id() -> str:
    return dt.datetime.now().strftime("%Y%m%d_%H%M%S")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hash_lines(lines: Iterable[str]) -> str:
    h = hashlib.sha256()
    for line in sorted(set(lines)):
        h.update(line.encode("utf-8", errors="replace"))
        h.update(b"\n")
    return h.hexdigest()


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _canonical_xml(path: Path) -> Tuple[Optional[str], Optional[str]]:
    if not path.is_file():
        return None, "missing"
    data = path.read_bytes()
    try:
        root = ET.fromstring(data)
    except ET.ParseError as ex:
        return None, str(ex)

    rows: List[object] = []

    def walk(node: ET.Element) -> None:
        rows.append(("start", node.tag, sorted(node.attrib.items()), (node.text or "").strip()))
        for child in list(node):
            walk(child)
        rows.append(("end", node.tag))

    walk(root)
    encoded = json.dumps(rows, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return _sha256(encoded), None


def _tree_metrics(root: Path) -> Dict[str, int]:
    file_count = 0
    logical_bytes = 0
    allocated_bytes = 0
    smali_count = 0

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        stat = path.stat()
        file_count += 1
        logical_bytes += stat.st_size
        allocated_bytes += getattr(stat, "st_blocks", 0) * 512
        if path.suffix == ".smali":
            smali_count += 1

    return {
        "file_count": file_count,
        "logical_bytes": logical_bytes,
        "disk_usage_kib": allocated_bytes // 1024,
        "smali_file_count": smali_count,
    }


def _smali_files(root: Path) -> Dict[str, Path]:
    result: Dict[str, Path] = {}
    for child in root.iterdir():
        if not child.is_dir() or not SMALI_DIR_RE.match(child.name):
            continue
        for path in child.rglob("*.smali"):
            result[path.relative_to(root).as_posix()] = path
    return result


def _smali_signatures(paths: Iterable[Path]) -> Dict[str, object]:
    classes: set[str] = set()
    methods: set[str] = set()

    for path in paths:
        class_desc: Optional[str] = None
        for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if class_desc is None:
                match = SMALI_CLASS_RE.match(line)
                if match:
                    class_desc = match.group(1)
                    classes.add(class_desc)
                continue
            match = SMALI_METHOD_RE.match(line)
            if match:
                name, params, return_type = match.groups()
                methods.add(f"{class_desc}->{name}({params}){return_type}")

    return {
        "class_count": len(classes),
        "class_hash": _hash_lines(classes),
        "method_count": len(methods),
        "method_hash": _hash_lines(methods),
    }


def _compare_smali(reference_root: Path, python_root: Path) -> Dict[str, object]:
    reference = _smali_files(reference_root)
    python = _smali_files(python_root)

    reference_names = set(reference)
    python_names = set(python)
    missing = sorted(reference_names - python_names)
    extra = sorted(python_names - reference_names)
    common = sorted(reference_names & python_names)

    exact = []
    different = []
    for name in common:
        if reference[name].read_bytes() == python[name].read_bytes():
            exact.append(name)
        else:
            different.append(name)

    reference_signatures = _smali_signatures(reference.values())
    python_signatures = _smali_signatures(python.values())

    return {
        "status": (
            "same"
            if not missing and not extra and not different
            else "different"
        ),
        "reference_file_count": len(reference),
        "python_file_count": len(python),
        "common_file_count": len(common),
        "exact_file_count": len(exact),
        "different_file_count": len(different),
        "missing_file_count": len(missing),
        "extra_file_count": len(extra),
        "missing_sample": missing[:20],
        "extra_sample": extra[:20],
        "different_sample": different[:20],
        "reference_signatures": reference_signatures,
        "python_signatures": python_signatures,
        "signatures_same": reference_signatures == python_signatures,
    }


def _parse_reference_info(path: Path) -> Dict[str, object]:
    if not path.is_file():
        return {}
    text = path.read_text(encoding="utf-8", errors="replace")
    info: Dict[str, object] = {}

    commit = re.search(r"Apktool commit:\s*([0-9a-f]+)", text)
    if commit:
        info["commit"] = commit.group(1)

    timed = re.search(r"Timed selective decode:\s*real\s*([\d.]+)s", text)
    if timed:
        info["wall_time_sec"] = float(timed.group(1))
    else:
        table_time = re.search(r"\|\s*Wall time\s*\|[^|]*\|\s*([\d.]+)s\s*\|", text)
        if table_time:
            info["wall_time_sec"] = float(table_time.group(1))

    file_count = re.search(r"Selective file count:\s*([\d,]+)", text)
    if file_count:
        info["file_count"] = int(file_count.group(1).replace(",", ""))
    else:
        table_files = re.search(r"\|\s*File count\s*\|[^|]*\|\s*([\d,]+)\s*\|", text)
        if table_files:
            info["file_count"] = int(table_files.group(1).replace(",", ""))

    disk_usage = re.search(r"\|\s*Disk usage\s*\|[^|]*\|\s*([\d,]+)\s*KiB\s*\|", text)
    if disk_usage:
        info["disk_usage_kib"] = int(disk_usage.group(1).replace(",", ""))

    smali_count = re.search(r"Selective smali file count:\s*([\d,]+)", text)
    if smali_count:
        info["smali_file_count"] = int(smali_count.group(1).replace(",", ""))
    else:
        table_smali = re.search(r"\|\s*Smali file count\s*\|[^|]*\|\s*([\d,]+)\s*\|", text)
        if table_smali:
            info["smali_file_count"] = int(table_smali.group(1).replace(",", ""))

    return info


def _find_apk(apk_dir: Path, prefix: str) -> Path:
    matches = sorted(apk_dir.glob(f"{prefix}*.apk"))
    if len(matches) != 1:
        raise RuntimeError(f"Expected one APK for prefix {prefix}, found {len(matches)}")
    return matches[0]


def _reference_cases(data_root: Path, selected: set[str]) -> List[Tuple[str, Path, Path]]:
    cases: List[Tuple[str, Path, Path]] = []
    for reference_root in sorted((data_root / "outputs").glob("main-*")):
        prefix = reference_root.name.rsplit("-", 1)[-1]
        if selected and prefix not in selected:
            continue
        apk_path = _find_apk(data_root / "apk", prefix)
        cases.append((prefix, apk_path, reference_root))
    return cases


def _run_python(command: List[str], stdout_path: Path, stderr_path: Path) -> Dict[str, object]:
    started = time.perf_counter()
    with stdout_path.open("wb") as stdout_fp, stderr_path.open("wb") as stderr_fp:
        proc = subprocess.run(command, stdout=stdout_fp, stderr=stderr_fp, check=False)
    return {
        "status": "ok" if proc.returncode == 0 else "error",
        "exit_code": proc.returncode,
        "wall_time_sec": round(time.perf_counter() - started, 3),
        "command": shlex.join(command),
        "stdout_log": str(stdout_path),
        "stderr_log": str(stderr_path),
    }


def _manifest_comparison(reference_root: Path, python_root: Path) -> Dict[str, object]:
    reference_path = reference_root / "AndroidManifest.xml"
    python_path = python_root / "manifest" / "AndroidManifest.xml"

    if not reference_path.is_file() or not python_path.is_file():
        return {
            "status": "error",
            "reference_present": reference_path.is_file(),
            "python_present": python_path.is_file(),
        }

    reference_data = reference_path.read_bytes()
    python_data = python_path.read_bytes()
    reference_canonical, reference_error = _canonical_xml(reference_path)
    python_canonical, python_error = _canonical_xml(python_path)

    return {
        "status": "same" if reference_data == python_data else "different",
        "byte_equal": reference_data == python_data,
        "reference_sha256": _sha256(reference_data),
        "python_sha256": _sha256(python_data),
        "canonical_equal": (
            reference_canonical is not None
            and reference_canonical == python_canonical
        ),
        "reference_canonical_sha256": reference_canonical,
        "python_canonical_sha256": python_canonical,
        "reference_parse_error": reference_error,
        "python_parse_error": python_error,
    }


def _render_report(run_id: str, records: List[Dict[str, object]]) -> str:
    lines = [
        "# Python Decoder Reference Comparison",
        "",
        f"- Run ID: {run_id}",
        f"- Cases: {len(records)}",
        "",
        "| APK | Python time | Java selective time | Speed ratio | Python files | Java files | Python disk KiB | Java disk KiB | Manifest bytes | Smali exact | Smali signatures |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---|---:|---|",
    ]

    for record in records:
        python_time = record["python_run"]["wall_time_sec"]
        java_time = record["reference_metrics"].get("wall_time_sec")
        ratio = ""
        if isinstance(java_time, (int, float)) and java_time > 0:
            ratio = f"{python_time / java_time:.2f}x"

        python_metrics = record["python_metrics"]
        java_metrics = record["reference_metrics"]
        manifest = record["manifest"]
        smali = record["smali"]
        exact_display = f"{smali['exact_file_count']}/{smali['reference_file_count']}"

        lines.append(
            "| {apk} | {py_time:.3f}s | {java_time} | {ratio} | {py_files:,} | {java_files} | "
            "{py_disk:,} | {java_disk} | {manifest} | {smali_exact} | {signatures} |".format(
                apk=record["apk_prefix"],
                py_time=python_time,
                java_time=f"{java_time:.2f}s" if isinstance(java_time, (int, float)) else "",
                ratio=ratio,
                py_files=python_metrics["file_count"],
                java_files=f"{java_metrics['file_count']:,}" if "file_count" in java_metrics else "",
                py_disk=python_metrics["disk_usage_kib"],
                java_disk=f"{java_metrics['disk_usage_kib']:,}" if "disk_usage_kib" in java_metrics else "",
                manifest="same" if manifest.get("byte_equal") else "different",
                smali_exact=exact_display,
                signatures="same" if smali.get("signatures_same") else "different",
            )
        )

    lines.append("")
    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--data-root",
        default="/Users/ohtsuka/workspace/apktool-dev-data",
        help="Directory containing apk/ and outputs/.",
    )
    parser.add_argument(
        "--python-decoder",
        default=str(Path(__file__).resolve().parents[1] / "python_port" / "apk_native_decode.py"),
    )
    parser.add_argument("--python-bin", default=sys.executable)
    parser.add_argument("--cases", default="", help="Comma-separated APK hash prefixes.")
    parser.add_argument("--run-id", default="")
    parser.add_argument("--result-root", default="local_results")
    parser.add_argument("--work-root", default="/private/tmp/apktool-python-reference")
    parser.add_argument(
        "--smali-mode",
        choices=["disassemble", "skeleton"],
        default="disassemble",
    )
    parser.add_argument("--keep-output", action="store_true")
    return parser


def main(argv: List[str]) -> int:
    args = _build_parser().parse_args(argv)
    data_root = Path(args.data_root).resolve()
    decoder = Path(args.python_decoder).resolve()
    run_id = args.run_id or f"python-reference-{_now_id()}"
    result_root = Path(args.result_root).resolve() / run_id
    work_root = Path(args.work_root).resolve() / run_id
    selected = {part.strip() for part in args.cases.split(",") if part.strip()}

    cases = _reference_cases(data_root, selected)
    if not cases:
        print("E: no reference cases found", file=sys.stderr)
        return 1

    result_root.mkdir(parents=True, exist_ok=True)
    work_root.mkdir(parents=True, exist_ok=True)
    records: List[Dict[str, object]] = []

    for index, (prefix, apk_path, reference_case_root) in enumerate(cases, start=1):
        print(f"[{index}/{len(cases)}] {prefix}: {apk_path.name}")
        case_result_root = result_root / prefix
        case_result_root.mkdir(parents=True, exist_ok=True)
        python_output = work_root / prefix
        if python_output.exists():
            shutil.rmtree(python_output)

        command = [
            args.python_bin,
            str(decoder),
            str(apk_path),
            "-o",
            str(python_output),
            "--manifest-mode",
            "decode",
            "--dex-mode",
            "decode",
            "--smali-mode",
            args.smali_mode,
        ]
        python_run = _run_python(
            command,
            case_result_root / "python.stdout.log",
            case_result_root / "python.stderr.log",
        )

        reference_output = reference_case_root / "smali_manifest_only"
        reference_metrics = _parse_reference_info(reference_case_root / "RUN_INFO.md")
        reference_metrics.update(_tree_metrics(reference_output))

        if python_run["status"] == "ok":
            python_metrics = _tree_metrics(python_output)
            manifest = _manifest_comparison(reference_output, python_output)
            smali = _compare_smali(reference_output, python_output)
        else:
            python_metrics = {}
            manifest = {"status": "error", "reason": "python_failed"}
            smali = {"status": "error", "reason": "python_failed"}

        record = {
            "apk_prefix": prefix,
            "apk_path": str(apk_path),
            "apk_size_bytes": apk_path.stat().st_size,
            "reference_root": str(reference_output),
            "python_output": str(python_output),
            "python_run": python_run,
            "reference_metrics": reference_metrics,
            "python_metrics": python_metrics,
            "manifest": manifest,
            "smali": smali,
        }
        records.append(record)
        _write_json(case_result_root / "result.json", record)

        if not args.keep_output and python_output.exists():
            shutil.rmtree(python_output)

    summary = {
        "run_id": run_id,
        "created_at": dt.datetime.now().isoformat(timespec="seconds"),
        "data_root": str(data_root),
        "smali_mode": args.smali_mode,
        "case_count": len(records),
        "records": records,
    }
    _write_json(result_root / "summary.json", summary)

    with (result_root / "results.csv").open("w", encoding="utf-8", newline="") as fp:
        writer = csv.writer(fp)
        writer.writerow(
            [
                "apk_prefix",
                "python_status",
                "python_wall_time_sec",
                "java_selective_wall_time_sec",
                "speed_ratio_python_over_java",
                "python_file_count",
                "java_file_count",
                "python_disk_usage_kib",
                "java_disk_usage_kib",
                "manifest_byte_equal",
                "manifest_canonical_equal",
                "python_smali_count",
                "java_smali_count",
                "smali_exact_count",
                "smali_different_count",
                "smali_missing_count",
                "smali_extra_count",
                "smali_signatures_same",
            ]
        )
        for record in records:
            python_time = record["python_run"].get("wall_time_sec")
            java_time = record["reference_metrics"].get("wall_time_sec")
            ratio = (
                python_time / java_time
                if isinstance(python_time, (int, float))
                and isinstance(java_time, (int, float))
                and java_time > 0
                else ""
            )
            python_metrics = record["python_metrics"]
            reference_metrics = record["reference_metrics"]
            manifest = record["manifest"]
            smali = record["smali"]
            writer.writerow(
                [
                    record["apk_prefix"],
                    record["python_run"]["status"],
                    python_time,
                    java_time or "",
                    ratio,
                    python_metrics.get("file_count", ""),
                    reference_metrics.get("file_count", ""),
                    python_metrics.get("disk_usage_kib", ""),
                    reference_metrics.get("disk_usage_kib", ""),
                    manifest.get("byte_equal", ""),
                    manifest.get("canonical_equal", ""),
                    python_metrics.get("smali_file_count", ""),
                    reference_metrics.get("smali_file_count", ""),
                    smali.get("exact_file_count", ""),
                    smali.get("different_file_count", ""),
                    smali.get("missing_file_count", ""),
                    smali.get("extra_file_count", ""),
                    smali.get("signatures_same", ""),
                ]
            )

    (result_root / "REPORT.md").write_text(_render_report(run_id, records), encoding="utf-8")
    print(f"summary: {result_root / 'summary.json'}")
    print(f"csv: {result_root / 'results.csv'}")
    print(f"report: {result_root / 'REPORT.md'}")
    return 0 if all(record["python_run"]["status"] == "ok" for record in records) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
