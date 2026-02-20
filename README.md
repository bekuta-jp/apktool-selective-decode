# Apktool Selective Decode (Unofficial Fork)

## 日本語
このリポジトリは [iBotPeaches/Apktool](https://github.com/iBotPeaches/Apktool) をベースに、  
大規模 APK の実験時に不要ファイル出力を減らすための選択的デコード機能を追加した非公式フォークです。

- 上流互換の基本ワークフロー（`decode` / `build`）は維持
- `dex` / `AndroidManifest.xml` / `resources` ごとに処理方式を選択可能
- 実行終了時に処理サマリをログ出力

### 追加オプション（decode）
- `--dex-mode <decode|raw|skip>`
- `--manifest-mode <decode|raw|skip>`
- `--res-mode <decode|raw|skip>`

意味:
- `decode`: 従来どおりデコードして保存
- `raw`: 生ファイルとして保存
- `skip`: 対象を出力しない

### 使用例
```bash
apktool d app.apk --dex-mode skip --manifest-mode decode --res-mode decode
apktool d app.apk --dex-mode raw --manifest-mode raw --res-mode skip
```

### 注意
- このフォークは公式 Apktool ではありません。
- Apktool は違法行為を目的としたツールではありません。利用する国・地域の法令に従ってください。
- ライセンスは Apache 2.0 です。再配布時は `LICENSE.md` を必ず同梱してください。

公開手順（新規リポジトリ作成、remote 設定、初回 push）は  
`PUBLISHING.md` を参照してください。

## English
This repository is an unofficial fork of [iBotPeaches/Apktool](https://github.com/iBotPeaches/Apktool),  
focused on reducing unnecessary file output when experimenting with large APKs.

- Keeps the core upstream workflow (`decode` / `build`)
- Adds per-component handling for `dex`, `AndroidManifest.xml`, and `resources`
- Emits a decode summary log after each run

### Added decode options
- `--dex-mode <decode|raw|skip>`
- `--manifest-mode <decode|raw|skip>`
- `--res-mode <decode|raw|skip>`

Semantics:
- `decode`: decode and save (default Apktool behavior)
- `raw`: save as raw/binary
- `skip`: do not write that component

### Examples
```bash
apktool d app.apk --dex-mode skip --manifest-mode decode --res-mode decode
apktool d app.apk --dex-mode raw --manifest-mode raw --res-mode skip
```

### Notes
- This is not an official Apktool distribution.
- Apktool is not intended for piracy or illegal use. Follow your local laws and policies.
- License: Apache 2.0. Keep `LICENSE.md` when redistributing.

For publishing steps (creating a new remote repo, setting remotes, first push),  
see `PUBLISHING.md`.

## Attribution
- Upstream project: [iBotPeaches/Apktool](https://github.com/iBotPeaches/Apktool)
- Original copyright holders are retained in source headers.
