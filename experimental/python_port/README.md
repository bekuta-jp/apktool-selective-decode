# Python Port Prototype / Python移植プロトタイプ

## 日本語

このディレクトリは、Java ランタイムに依存しない APK 解析の初期実装です。

現時点の対象:
- `AndroidManifest.xml` の処理: `decode|raw|skip`
- `classes*.dex` の処理: `decode|raw|skip`
- `.smali` 出力: `disassemble|skeleton|skip`

`decode` の意味:
- Manifest: AXML (バイナリXML) をテキスト XML へ変換
- DEX: ヘッダ/文字列/型/クラス/メソッド先頭のメタ情報を JSON へ出力
  - 追加で `class_hash` / `method_signature_hash` を出力
- Smali:
  - `disassemble`: class/field/methodとDEX命令を `.smali` として出力
  - `skeleton`: 命令を省いた高速な構造出力

注意:
- これは Apktool 本体の完全互換実装ではありません。
- ManifestはAPK自身の`resources.arsc`をメモリ上で読み、リソース名を解決します。`res/`への保存は行いません。
- `disassemble`は命令・行番号・基本的なpayloadを出力しますが、注釈、例外ハンドラ、ローカル変数情報は未完成です。
- Manifest デコードは特殊ケースでは `raw_fallback` に落ちます。

### 使い方

命令デコードとリソース名解決で使用する依存を隔離環境へインストール:

```bash
python3 -m venv .venv
.venv/bin/pip install -r experimental/python_port/requirements.txt
```

```bash
python3 experimental/python_port/apk_native_decode.py \
  /path/to/app.apk \
  -o /tmp/native_decode_out \
  --manifest-mode decode \
  --dex-mode decode \
  --smali-mode disassemble \
  --include-signatures
```

出力:
- `manifest/AndroidManifest.xml` (または `AndroidManifest.raw.xml`)
- `smali/**/*.smali`, `smali_classes2/**/*.smali`, ...
- `dex/decoded/*.json` または `dex/raw/*.dex`
- `summary.json`

`--include-signatures` を付けると、DEX JSONにクラス/メソッド署名一覧も含めます（大きな出力になります）。
`--smali-mode skeleton` は命令を省く代わりに、速度と出力サイズを優先します。

## English

This directory contains an initial non-Java APK analysis prototype.

Current scope:
- `AndroidManifest.xml` handling: `decode|raw|skip`
- `classes*.dex` handling: `decode|raw|skip`
- `.smali` output: `disassemble|skeleton|skip`

What `decode` means:
- Manifest: converts binary AXML into text XML
- DEX: writes metadata JSON (header/strings/types/classes/method preview)
  - includes `class_hash` and `method_signature_hash`
- Smali:
  - `disassemble`: writes class/field/method data and decoded DEX instructions
  - `skeleton`: writes fast structural output without instructions

Notes:
- This is not full Apktool feature parity.
- Manifest decoding resolves resource names from the APK's `resources.arsc` in memory without writing `res/`.
- `disassemble` emits instructions, line numbers, and basic payloads. Annotations, exception handlers, and local-variable debug data are not complete yet.
- Manifest decoding is experimental and may fall back to raw output.

### Usage

Install the instruction/resource decoding dependency in an isolated environment:

```bash
python3 -m venv .venv
.venv/bin/pip install -r experimental/python_port/requirements.txt
```

```bash
python3 experimental/python_port/apk_native_decode.py \
  /path/to/app.apk \
  -o /tmp/native_decode_out \
  --manifest-mode decode \
  --dex-mode decode \
  --smali-mode disassemble \
  --include-signatures
```

Outputs:
- `manifest/AndroidManifest.xml` (or `AndroidManifest.raw.xml`)
- `smali/**/*.smali`, `smali_classes2/**/*.smali`, ...
- `dex/decoded/*.json` or `dex/raw/*.dex`
- `summary.json`

With `--include-signatures`, full class/method signature lists are added to DEX JSON output (large files).
Use `--smali-mode skeleton` when speed and output size matter more than instruction text.
