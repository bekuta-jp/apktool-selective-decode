#!/usr/bin/env python3
"""Verify the A/B/C incident inputs listed in copy-verification.json.

Uses original APKs read-only. Saves complete logs, commands and assertions. A is
expected to decode; B/C are expected to fail with useful, finite diagnostics.
"""
import argparse
import collections
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import time
import zipfile

from validate_decode_outputs import save, sha256, snapshot


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--before', type=Path, required=True)
    parser.add_argument('--after', type=Path, required=True)
    parser.add_argument('--data-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--java', default='java')
    args = parser.parse_args()
    args.before = args.before.resolve()
    args.after = args.after.resolve()
    args.output = args.output.resolve()
    args.data_dir = args.data_dir.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    cases = json.loads((args.data_dir / 'copy-verification.json').read_text())['cases']
    save(args.output / 'run.json', {'before_jar_sha256': sha256(args.before),
        'after_jar_sha256': sha256(args.after), 'data_dir': str(args.data_dir),
        'java_version': subprocess.run([args.java, '-version'], capture_output=True, text=True).stderr})

    def run(command, stem):
        command = list(map(str, command))
        result = {'command': command}
        started = time.monotonic()
        with stem.with_suffix('.stdout').open('wb') as stdout, stem.with_suffix('.stderr').open('wb') as stderr:
            try:
                result['returncode'] = subprocess.run(command, stdout=stdout, stderr=stderr, timeout=120).returncode
            except subprocess.TimeoutExpired:
                result['timeout'] = True
        result['seconds'] = round(time.monotonic() - started, 3)
        result['stderr'] = str(stem.with_suffix('.stderr'))
        return result

    def decode(jar, apk, root, name, modes=None):
        options = ['--dex-mode', 'decode', '--manifest-mode', 'decode', '--res-mode', 'skip', '--no-assets']
        if modes is not None:
            options = modes
        return run([args.java, '-Xmx1g', '-jar', jar, 'd', '-p', root / (name + '-framework'),
            '-o', root / name] + options + [apk], root / name)

    results = []
    for case in cases:
        apk = args.data_dir / case['path']
        assert sha256(apk) == case['sha256'], 'Input differs: ' + str(apk)
        root = args.output / case['sha256']
        root.mkdir()
        row = dict(case)
        checks = {}
        row['before'] = decode(args.before, apk, root, 'before')
        row['after'] = decode(args.after, apk, root, 'after')
        before_error = Path(row['before']['stderr']).read_text(errors='replace')
        after_error = Path(row['after']['stderr']).read_text(errors='replace')
        checks['before_failed'] = row['before'].get('returncode') == 1

        if case['group'] == 'zip_charset':
            checks['before_charset_error'] = ('invalid CEN header (bad entry name)' in before_error
                or ('MalformedInputException' in before_error and 'ZipCoder' in before_error))
            checks['after_decode_success'] = row['after'].get('returncode') == 0
            checks['manifest_present'] = (root / 'after/AndroidManifest.xml').is_file()
            row['normal'] = decode(args.after, apk, root, 'normal', [])
            checks['normal_decode_success'] = row['normal'].get('returncode') == 0
            row['raw'] = decode(args.after, apk, root, 'raw', ['--dex-mode', 'raw',
                '--manifest-mode', 'raw', '--res-mode', 'skip', '--no-assets'])
            checks['raw_decode_success'] = row['raw'].get('returncode') == 0
            dex_results = []
            with zipfile.ZipFile(apk) as archive:
                manifest = archive.read('AndroidManifest.xml')
                checks['manifest_bytes_unchanged'] = (root / 'raw/AndroidManifest.xml').read_bytes() == manifest
                for index, entry in enumerate(archive.infolist()):
                    if not re.fullmatch(r'classes(?:\d*)\.dex', entry.filename):
                        continue
                    data = archive.read(entry)
                    dex_file = root / ('dex-%d.dex' % index)
                    dex_file.write_bytes(data)
                    name = 'smali' if entry.filename == 'classes.dex' else 'smali_' + entry.filename[:-4]
                    target = root / ('standalone-%d' % index)
                    result = run([args.java, '-Xmx1g', '-cp', args.after,
                        'com.android.tools.smali.baksmali.Main', 'disassemble', '--use-locals',
                        '--sequential-labels', '--debug-info', 'true', '--parameter-registers', 'true',
                        '--accessor-comments', 'false', '--jobs', '1', '--output', target, dex_file], target)
                    expected = snapshot(target)
                    actual = snapshot(root / 'after' / name)
                    class_count = struct.unpack_from('<I', data, 96)[0]
                    smali_count = sum(p.endswith('.smali') for p in actual)
                    checks[entry.filename + ':raw_bytes_unchanged'] = (root / 'raw' / entry.filename).read_bytes() == data
                    checks[entry.filename + ':standalone_success'] = result.get('returncode') == 0
                    checks[entry.filename + ':all_classes'] = smali_count == class_count
                    checks[entry.filename + ':smali_identical'] = expected == actual
                    checks[entry.filename + ':normal_smali_identical'] = expected == snapshot(root / 'normal' / name)
                    dex_results.append({'entry': entry.filename, 'sha256': sha256(dex_file),
                        'class_count': class_count, 'smali_count': smali_count, 'standalone': result})
            checks['dex_present'] = bool(dex_results)
            row['dex'] = dex_results
        elif case['group'] == 'invalid_types_recursion':
            checks['before_stack_overflow'] = 'StackOverflowError' in before_error
            checks['after_explicit_invalid_type'] = (row['after'].get('returncode') == 1
                and 'Invalid type reference in classes.dex' in after_error and 'type index' in after_error)
            checks['after_no_recursion'] = 'StackOverflowError' not in after_error and len(after_error) < 20000
        elif case['group'] == 'malformed_resource_and_dex036':
            row['resources'] = decode(args.after, apk, root, 'resources', ['--dex-mode', 'skip',
                '--manifest-mode', 'decode', '--res-mode', 'skip', '--no-assets'])
            error = Path(row['resources']['stderr']).read_text(errors='replace')
            checks['resource_diagnostic'] = (row['resources'].get('returncode') == 1
                and 'Non-empty input contains no supported resource table chunk' in error
                and '!resources.arsc' in error and '00000c00c40c0000' in error and 'position=0x00000cc4' in error)
            checks['resource_not_called_empty'] = 'Input file is empty.' not in error
            row['dex_only'] = decode(args.after, apk, root, 'dex-only', ['--dex-mode', 'decode',
                '--manifest-mode', 'skip', '--res-mode', 'skip', '--no-assets'])
            checks['dex036_still_rejected'] = (row['dex_only'].get('returncode') == 1
                and 'Dex version 036 is not supported' in Path(row['dex_only']['stderr']).read_text())
        else:
            raise ValueError('Unexpected group: ' + case['group'])
        checks['input_unchanged'] = sha256(apk) == case['sha256']
        row['checks'] = checks
        row['passed'] = all(checks.values())
        save(root / 'result.json', row)
        results.append(row)
        save(args.output / 'results.json', results)
        print('%d/%d %s %s passed=%s failed_checks=%s' % (len(results), len(cases),
            case['sha256'][:12], case['group'], row['passed'], [k for k, v in checks.items() if not v]), flush=True)
    summary = {'cases': len(results), 'passed': sum(r['passed'] for r in results),
        'groups': dict(collections.Counter(r['group'] for r in results)),
        'all_passed': all(r['passed'] for r in results)}
    save(args.output / 'summary.json', summary)
    print(json.dumps(summary), flush=True)
    if not summary['all_passed']:
        raise SystemExit(1)


if __name__ == '__main__':
    os.umask(0o077)
    main()
