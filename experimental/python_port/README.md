# Python Port Prototype / Python移植プロトタイプ

## 日本語

このディレクトリは、Java ランタイムに依存しない APK 解析の初期実装です。

現時点の対象:
- `AndroidManifest.xml` の処理: `decode|raw|skip`
- `classes*.dex` の処理: `decode|raw|skip`

`decode` の意味:
- Manifest: AXML (バイナリXML) をテキスト XML へ変換
- DEX: ヘッダ/文字列/型/クラス/メソッド先頭のメタ情報を JSON へ出力

注意:
- これは Apktool 本体の完全互換実装ではありません。
- DEX の `decode` は smali 逆アセンブルではなく、メタデータ解析です。
- Manifest デコードは実験実装で、特殊ケースでは `raw_fallback` に落ちます。

### 使い方

```bash
python3 experimental/python_port/apk_native_decode.py \
  /path/to/app.apk \
  -o /tmp/native_decode_out \
  --manifest-mode decode \
  --dex-mode decode
```

出力:
- `manifest/AndroidManifest.xml` (または `AndroidManifest.raw.xml`)
- `dex/decoded/*.json` または `dex/raw/*.dex`
- `summary.json`

## English

This directory contains an initial non-Java APK analysis prototype.

Current scope:
- `AndroidManifest.xml` handling: `decode|raw|skip`
- `classes*.dex` handling: `decode|raw|skip`

What `decode` means:
- Manifest: converts binary AXML into text XML
- DEX: writes metadata JSON (header/strings/types/classes/method preview)

Notes:
- This is not full Apktool feature parity.
- DEX `decode` is metadata parsing, not full smali disassembly.
- Manifest decoding is experimental and may fall back to raw output.

### Usage

```bash
python3 experimental/python_port/apk_native_decode.py \
  /path/to/app.apk \
  -o /tmp/native_decode_out \
  --manifest-mode decode \
  --dex-mode decode
```

Outputs:
- `manifest/AndroidManifest.xml` (or `AndroidManifest.raw.xml`)
- `dex/decoded/*.json` or `dex/raw/*.dex`
- `summary.json`
