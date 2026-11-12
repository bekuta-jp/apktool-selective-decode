#!/usr/bin/env python3
"""Capture/compare APK decode trees without changing the input APKs.

Each capture uses one CPU per JVM and one Apktool job to avoid smali filename
ordering noise on case-insensitive filesystems. Full logs, commands, input/JAR
hashes and compressed output-tree manifests are retained. No APK is executed.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time


def sha256(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def save(path, obj):
    path.write_text(json.dumps(obj, ensure_ascii=True, indent=2) + '\n')


def snapshot(directory):
    tree = {}
    for root, dirs, files in os.walk(directory, followlinks=False):
        for name in dirs + files:
            path = Path(root) / name
            key = path.relative_to(directory).as_posix()
            if path.is_symlink():
                tree[key] = ['symlink', os.readlink(path)]
            elif path.is_dir():
                tree[key] = ['directory']
            else:
                tree[key] = ['file', path.stat().st_size, sha256(path)]
    return tree


def capture(args):
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    jar = args.jar.resolve()
    inputs = sorted(args.apk_dir.resolve().glob('*.apk'))
    if not inputs:
        raise ValueError('No APKs found')
    save(output / 'run.json', {'jar': str(jar), 'jar_sha256': sha256(jar),
        'java_version': subprocess.run([args.java, '-version'], capture_output=True, text=True).stderr,
        'input_directory': str(args.apk_dir.resolve()), 'input_count': len(inputs),
        'modes': ['normal', 'selective'], 'active_processors': 1, 'apktool_jobs': 1})

    def one(apk, mode):
        case = output / (apk.stem + '-' + mode)
        case.mkdir()
        decoded = case / 'decoded'
        framework = case / 'framework'
        input_hash = sha256(apk)
        command = [args.java, '-Xmx2g', '-XX:ActiveProcessorCount=1', '-jar', str(jar),
            'd', '-j', '1', '-p', str(framework), '-o', str(decoded)]
        if mode == 'selective':
            command += ['--dex-mode', 'decode', '--manifest-mode', 'decode', '--res-mode', 'skip', '--no-assets']
        command.append(str(apk))
        started = time.monotonic()
        row = {'input': str(apk), 'input_sha256': input_hash, 'mode': mode, 'command': command}
        with (case / 'stdout.log').open('wb') as stdout, (case / 'stderr.log').open('wb') as stderr:
            try:
                row['returncode'] = subprocess.run(command, stdout=stdout, stderr=stderr,
                    timeout=args.timeout).returncode
            except subprocess.TimeoutExpired:
                row['timeout'] = True
        row['decode_seconds'] = round(time.monotonic() - started, 3)
        row['input_unchanged'] = sha256(apk) == input_hash
        tree = snapshot(decoded)
        row['tree_entries'] = len(tree)
        row['file_count'] = sum(v[0] == 'file' for v in tree.values())
        with gzip.open(case / 'tree.json.gz', 'wt', encoding='utf-8') as stream:
            json.dump(tree, stream, ensure_ascii=True, sort_keys=True)
        save(case / 'result.json', row)
        # Only remove artifacts created in this new capture directory. Hash manifests retain
        # every file's path/content and all directories/symlink targets for exact comparison.
        if decoded.exists():
            shutil.rmtree(decoded)
        if framework.exists():
            shutil.rmtree(framework)
        return case.name, row

    results = {}
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        tasks = [pool.submit(one, apk, mode) for apk in inputs for mode in ['normal', 'selective']]
        for future in as_completed(tasks):
            name, row = future.result()
            results[name] = row
            save(output / 'results.json', results)
            print('%d/%d %s rc=%s files=%s' % (len(results), len(tasks), name,
                row.get('returncode', 'timeout'), row['file_count']), flush=True)
    if any(not r['input_unchanged'] or r.get('timeout') for r in results.values()):
        raise SystemExit('Input change or timeout; capture is not valid')


def compare(args):
    before = json.loads((args.before / 'results.json').read_text())
    after = json.loads((args.after / 'results.json').read_text())
    if before.keys() != after.keys():
        raise ValueError('Capture cases do not match')
    results = []
    for name, left in sorted(before.items()):
        right = after[name]
        assert left['input_sha256'] == right['input_sha256']
        with gzip.open(args.before / name / 'tree.json.gz', 'rt') as stream:
            old = json.load(stream)
        with gzip.open(args.after / name / 'tree.json.gz', 'rt') as stream:
            new = json.load(stream)
        differences = [p for p in sorted(old.keys() | new.keys()) if old.get(p) != new.get(p)]
        if left.get('timeout') or right.get('timeout'):
            status = 'timeout'
        elif left['returncode'] == right['returncode'] == 0:
            status = 'same' if not differences else 'different'
        elif left['returncode'] == 0:
            status = 'regression'
        elif right['returncode'] == 0:
            status = 'improved'
        else:
            status = 'both_failed'
        results.append({'case': name, 'status': status, 'input_sha256': left['input_sha256'],
            'before_returncode': left.get('returncode'), 'after_returncode': right.get('returncode'),
            'difference_count': len(differences), 'different_paths': differences})
    counts = {status: sum(r['status'] == status for r in results) for status in sorted({r['status'] for r in results})}
    save(args.output, {'before': str(args.before.resolve()), 'after': str(args.after.resolve()),
        'counts': counts, 'results': results})
    print(json.dumps(counts), flush=True)
    if any(r['status'] in ['different', 'regression', 'timeout'] for r in results):
        raise SystemExit(1)


if __name__ == '__main__':
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='operation', required=True)
    cap = commands.add_parser('capture')
    cap.add_argument('--jar', type=Path, required=True)
    cap.add_argument('--apk-dir', type=Path, required=True)
    cap.add_argument('--output', type=Path, required=True)
    cap.add_argument('--java', default='java')
    cap.add_argument('--workers', type=int, default=2)
    cap.add_argument('--timeout', type=int, default=600)
    cmp = commands.add_parser('compare')
    cmp.add_argument('--before', type=Path, required=True)
    cmp.add_argument('--after', type=Path, required=True)
    cmp.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    capture(args) if args.operation == 'capture' else compare(args)
