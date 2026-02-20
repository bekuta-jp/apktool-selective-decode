# Publishing Guide / 公開ガイド

## 日本語

このフォークを「新規リポジトリ」として公開するための最短手順です。  
ここでは、Codex が代行できない作業（あなたしかできない作業）を明示します。

### 1. あなたしかできない作業
1. GitHub/GitLab などで新規リポジトリを作成する
2. 公開範囲（public/private）を決める
3. 必要に応じて組織・法務ポリシー確認を行う

### 2. ローカルで実行するコマンド
`<YOUR_REMOTE_URL>` は作成した新規リポジトリの URL に置き換えてください。

```bash
# 既存の upstream は残したまま、新規公開先 remote を追加
git remote add fork-origin <YOUR_REMOTE_URL>

# 変更を確認
git status

# 新規公開用コミット
git add README.md PUBLISHING.md \
  brut.apktool/apktool-cli/src/main/java/brut/apktool/Main.java \
  brut.apktool/apktool-lib/src/main/java/brut/androlib/Config.java \
  brut.apktool/apktool-lib/src/main/java/brut/androlib/ApkDecoder.java \
  brut.apktool/apktool-lib/src/test/java/brut/androlib/SelectiveDecodeModeTest.java
git commit -m "Add selective decode/save modes and bilingual docs"

# 新規リポジトリへ push
git push -u fork-origin HEAD:main
```

### 3. 公開時の必須チェック
1. `LICENSE.md` を同梱していること
2. 変更ファイルが明確であること（コミットメッセージ・README）
3. 公式版と誤認しない名称・説明になっていること
4. セキュリティ窓口を運用するなら `SECURITY.md` を更新すること

### 4. 上流追従（任意）
```bash
# upstream が未設定なら追加
git remote add upstream https://github.com/iBotPeaches/Apktool.git

# 上流取り込み
git fetch upstream
git rebase upstream/main

# フォーク側に反映
git push --force-with-lease fork-origin HEAD:main
```

---

## English

This is the shortest path to publish this fork as a **new repository**.  
The steps below explicitly separate what only you can do.

### 1. Tasks only you can do
1. Create a new repository on GitHub/GitLab
2. Decide visibility (public/private)
3. Confirm legal/compliance requirements if needed

### 2. Local commands
Replace `<YOUR_REMOTE_URL>` with your newly created repository URL.

```bash
# Keep existing upstream and add a new publishing remote
git remote add fork-origin <YOUR_REMOTE_URL>

# Check current changes
git status

# Commit publication-ready changes
git add README.md PUBLISHING.md \
  brut.apktool/apktool-cli/src/main/java/brut/apktool/Main.java \
  brut.apktool/apktool-lib/src/main/java/brut/androlib/Config.java \
  brut.apktool/apktool-lib/src/main/java/brut/androlib/ApkDecoder.java \
  brut.apktool/apktool-lib/src/test/java/brut/androlib/SelectiveDecodeModeTest.java
git commit -m "Add selective decode/save modes and bilingual docs"

# Push to your new repository
git push -u fork-origin HEAD:main
```

### 3. Required publication checks
1. Include `LICENSE.md` in the distributed source
2. Clearly indicate what was changed (commit history + README)
3. Avoid naming/wording that could imply an official release
4. If you operate a security channel, update `SECURITY.md`

### 4. Sync with upstream (optional)
```bash
# Add upstream if not present
git remote add upstream https://github.com/iBotPeaches/Apktool.git

# Rebase onto upstream
git fetch upstream
git rebase upstream/main

# Push updated history to your fork repo
git push --force-with-lease fork-origin HEAD:main
```
