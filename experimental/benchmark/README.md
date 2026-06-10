# Decode Benchmark Harness / デコード比較ベンチ

## 日本語

このディレクトリは、以下3方式を同一APK集合で比較するための実験用スクリプトです。

1. `original`: 通常の Apktool デコード
2. `selective`: 追加した選択的デコード（`--dex-mode decode --manifest-mode decode --res-mode skip`）
3. `python`: `experimental/python_port/apk_native_decode.py`

比較対象:
- `AndroidManifest.xml`（正規化ハッシュ比較）
- `.smali`（`original` vs `selective` はファイル実体比較）
- DEXシグネチャ（`original` smali抽出結果 vs `python` smali/JSON出力）

出力:
- `summary.json` / `summary.txt`
- `results/results.jsonl`（APKごとの詳細）
- `lists/same.txt`, `lists/different.txt`, `lists/error.txt`
- 差分/エラー時の追加情報（`artifacts/`）

`tmpfs`運用:
- 各APK・各モードの作業は `--tmpfs-root` 配下で実行
- モードごとに解析後すぐ削除（`--keep-tmp` を除く）

### 保存済みJava基準との比較

`/Users/ohtsuka/workspace/apktool-dev-data` の `RUN_INFO.md` と
`smali_manifest_only` を基準にPython版を測定します。

```bash
python3 experimental/benchmark/compare_python_to_reference.py \
  --data-root /Users/ohtsuka/workspace/apktool-dev-data \
  --python-bin .venv/bin/python \
  --smali-mode disassemble
```

出力は `local_results/<run-id>/` に作られます。

- `summary.json`
- `results.csv`
- `REPORT.md`
- APKごとのstdout/stderrと詳細JSON

比較指標:
- wall time
- ファイル数
- ディスク使用量
- manifest byte/canonical一致
- smaliファイル数、完全一致数、構造署名一致

`--smali-mode skeleton`を指定すると、命令出力を省いた高速経路も同じ形式で測定できます。

### 実行例（今回の環境向け）

事前にapktool CLI Jarを作成:

```bash
./gradlew :brut.apktool:apktool-cli:shadowJar
```

```bash
python3 experimental/benchmark/compare_decode_outputs.py \
  --apk-dir /Volumes/bekuta/dataset12000/test/benign \
  --nas-root /Volumes/bekuta/codex \
  --tmpfs-root /private/tmp/mem \
  --sample-size 100 \
  --seed 20260221 \
  --apktool-original-cmd "java -jar /Users/ohtsuka/workspace/Apktool/brut.apktool/apktool-cli/build/libs/apktool-cli.jar" \
  --apktool-selective-cmd "java -jar /Users/ohtsuka/workspace/Apktool/brut.apktool/apktool-cli/build/libs/apktool-cli.jar" \
  --python-bin python3 \
  --python-decoder /Users/ohtsuka/workspace/Apktool/experimental/python_port/apk_native_decode.py
```

補足:
- `--apktool-selective-cmd` を省略すると `--apktool-original-cmd` を使います。
- `--selective-no-assets` はデフォルト有効です（`--no-selective-no-assets` で無効化）。
- `--frame-path` 未指定時は `tmpfs` 配下に一時frameworkディレクトリを作成して利用します。
- `--min-free-gb` でtmpfs残容量の下限を設定できます（既定0.5GB）。
- Python側で詳細シグネチャをJSONへ残す場合は `--python-include-signatures` を指定します（出力は大きくなります）。

## English

This directory contains an experiment script to compare three decode flows on the same APK sample set:

1. `original`: standard Apktool decode
2. `selective`: selective mode (`--dex-mode decode --manifest-mode decode --res-mode skip`)
3. `python`: `experimental/python_port/apk_native_decode.py`

Compared artifacts:
- `AndroidManifest.xml` (normalized hash comparison)
- `.smali` (file-level comparison for `original` vs `selective`)
- DEX signatures (`original` smali-derived signatures vs `python` smali/JSON signatures)

Outputs:
- `summary.json` / `summary.txt`
- `results/results.jsonl` (per-APK details)
- `lists/same.txt`, `lists/different.txt`, `lists/error.txt`
- extra diff/error artifacts in `artifacts/`

tmpfs behavior:
- each APK/mode runs under `--tmpfs-root`
- output is cleaned right after extraction unless `--keep-tmp` is set
- if `--frame-path` is omitted, a temporary framework directory is created under tmpfs
- `--min-free-gb` defines a free-space threshold to skip execution when tmpfs is too full

### Stored Java Reference Comparison

Use the stored `RUN_INFO.md` and `smali_manifest_only` outputs under
`/Users/ohtsuka/workspace/apktool-dev-data` as the Java baseline:

```bash
python3 experimental/benchmark/compare_python_to_reference.py \
  --data-root /Users/ohtsuka/workspace/apktool-dev-data \
  --python-bin .venv/bin/python \
  --smali-mode disassemble
```

Results are written under `local_results/<run-id>/` as `summary.json`,
`results.csv`, `REPORT.md`, and per-APK detail/log files.
Use `--smali-mode skeleton` to benchmark the faster structure-only path.

### Example

Build apktool CLI jar first:

```bash
./gradlew :brut.apktool:apktool-cli:shadowJar
```

```bash
python3 experimental/benchmark/compare_decode_outputs.py \
  --apk-dir /Volumes/bekuta/dataset12000/test/benign \
  --nas-root /Volumes/bekuta/codex \
  --tmpfs-root /private/tmp/mem \
  --sample-size 100 \
  --seed 20260221 \
  --apktool-original-cmd "java -jar /Users/ohtsuka/workspace/Apktool/brut.apktool/apktool-cli/build/libs/apktool-cli.jar" \
  --apktool-selective-cmd "java -jar /Users/ohtsuka/workspace/Apktool/brut.apktool/apktool-cli/build/libs/apktool-cli.jar" \
  --python-bin python3 \
  --python-decoder /Users/ohtsuka/workspace/Apktool/experimental/python_port/apk_native_decode.py
```
