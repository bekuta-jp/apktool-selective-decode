# Compatibility and Validation / 互換性と検証

## 日本語

### 目的

選択的デコードは、必要なコンポーネントだけを出力して、大規模 APK の解析時間と
ディスク使用量を抑えるための追加機能です。モード指定がない通常デコードについては、
ベースとなる `main` と同じ成果物を出すことを互換性要件とします。

### 互換性方針

1. `--dex-mode`、`--manifest-mode`、`--res-mode` を指定しない場合は、従来の通常デコードと同じ処理を行います。
2. 選択的デコードは、明示的に指定されたコンポーネントの処理・出力だけを変更します。
3. 壊れた入力から値を推測して生成しません。
4. 復元不能な局所情報は warning を出して無視し、読み取れる残りの情報を保持します。

現在の耐障害処理:

- 不正な string style offset:
  style 情報だけを無視し、文字列本体を plain string として保持します。
- 不正な binary XML attribute:
  その属性だけをスキップし、残りの `AndroidManifest.xml` をデコードします。
- 非標準の最上位 binary XML chunk type `0x0009`:
  外側headerと直後のstring pool chunkが妥当な場合だけAXMLとして扱います。
- null (`0x0000`) の最上位 binary XML chunk type:
  外側headerと直後のstring pool chunkが妥当な場合だけAXMLとして扱います。
  XML内部のnull chunkは従来どおりスキップします。
- 読み取り不能な非DEX APK entry:
  DEX探索では選択されたDEX entryだけを開き、後段のコピーではZIP入力破損が
  確認できたentryだけをwarning付きでスキップします。

いずれも、存在しない値を補完したり、文脈から値を推測したりしません。

### 通常デコード回帰検証

baseline の `main` と修正版を同じツールチェーンでビルドし、両方で通常デコードを
実行しました。全ファイルの相対パスと SHA-256、空ディレクトリ、symbolic link の
リンク先を比較対象とし、mtime や所有者などのファイルシステムメタデータは
比較対象外としました。

### 選択的デコード検証

`SelectiveDecodeModeTest` は次を検証します。

- dex skip で dex/smali を出力しない
- manifest raw で binary XML を保持する
- resource 出力を skip しても、manifest decode に必要な resource table を利用する
- manifest/resource skip で対象ファイルを出力しない

選択的デコードの manifest/smali 内容は、通常デコードの対応成果物と
相対パス・SHA-256で比較しました。resource や asset を意図的に出力しないため、
選択モードと通常モードの出力ツリー全体が同一になることは要件ではありません。
大小文字が衝突するクラス名の出力順を決定的にするため、比較時は両モードを
1 job に揃えました。

### 最新のサンプル検証

ユーザー提供の 13 APK で、`main` と耐障害修正後の通常デコードを比較しました。

| 結果 | APK 数 |
| --- | ---: |
| `same` | 11 |
| `baseline_failed_candidate_ok` | 2 |
| `different` | 0 |
| `baseline_ok_candidate_failed` | 0 |
| `both_failed` | 0 |

改善した2件:

- `4d0bf681db13f43b4e6c0459637e349165dd2a09b78fcf8ea0c38e0a8f92dd15.apk`
- `5de0cfd45af1777b1f5e929a841d6f61bed429eb854a1eb1de44af93ff9d9dbd.apk`

同じ13 APKで候補jarの通常デコードと選択的デコードを比較した結果、
`AndroidManifest.xml` と全smaliは13件すべて一致しました。

### 非標準XML headerの検証

追加の2 APKは、最上位chunk typeが標準の `0x0003` ではなく `0x0009` でした。
修正前はmanifest parser初期化時に失敗し、修正後はwarningを出して通常デコードが
完了しました。

- `008b603811de18b5cedfa27a3635b9d63c450282003a2f0fece324d73b11193b.apk`
- `0235b9ee5e5deb48abdc8f0d22623b99b25a986c50c4337541ca79ebdc60a3c3.apk`

全15 APKで修正前後を比較した結果、12件は出力ツリーが完全一致し、上記2件は
修正前失敗・修正後成功でした。残る1件は、大文字小文字だけが異なるsmaliクラスの
`.1` suffix付与先が実行ごとに反転しました。同じbaseline jarの再実行でも再現し、
対応するファイル内容のSHA-256は一致しているため、今回の変更による差分ではありません。

### Null XML headerの検証

次の APK は、最上位chunk typeがnull (`0x0000`) で、そのchunkがmanifest全体を
包含していました。修正前はnull chunk全体をスキップしてEOFに達し、
`Input file is empty` として失敗しました。修正後は直後のstring poolを構造検証して
AXMLとして扱い、通常デコードと選択的デコードの両方が完了しました。

- `7fa1d8719f46ccb1c918e847ba31acf512b153115575035ca3dc5cefa62ce84a.apk`

全16 APKの通常デコードを修正前後で比較した結果、14件は出力ツリーが完全一致し、
上記1件は修正前失敗・修正後成功でした。残る1件の差分は、大小文字が衝突する
smaliクラスの `.1` suffix付与先だけで、対応するファイル内容のSHA-256は一致しました。

### 既知の事象: smaliファイル名の大小文字衝突

大文字小文字を区別しないファイルシステムで、クラス名が大文字小文字だけ異なる場合、
衝突回避用の `.1` suffixがどちらへ付くか実行ごとに変わることがあります。
対応するsmali内容は同一で、manifest decodeの結果には影響しません。
再現可能な命名規則の導入は、今回のmanifest耐障害修正とは分離して扱います。

### 読み取り不能なAPK entryの検証

次のAPKは、`classes.dex`、`AndroidManifest.xml`、`resources.arsc`は正常ですが、
3つのnative library entryが壊れていました。修正前はDEX container初期化時に
ZIP全entryを走査して壊れたlibraryを開き、manifest処理前に失敗しました。

- `02d0456a6e5c695a7402e378471a31fa8bfa473b4e957e8cb612b9a9f358d2cc.apk`

修正後は選択されたDEXだけを直接読み込み、DEXとmanifestをdecodeしました。
コピー不能な次の3 entryだけをwarning付きで除外し、正常な6 libraryは保持しました。

- `lib/armeabi-v7a/libagora-rtc-sdk-jni.so`
- `lib/armeabi-v7a/libbdpush_V2_9.so`
- `lib/armeabi-v7a/libcrypto.so`

コピー処理で無視するのは、cause chainに `ZipException` がある入力破損だけです。
出力先のI/Oエラーは従来どおり失敗させます。また、選択されたDEX自体が読めない場合も
失敗させ、DEX skipの場合はDEXを開きません。

全25 APKの通常デコードを修正前後で比較した結果、23件は出力ツリーが完全一致し、
上記1件は修正前失敗・修正後成功でした。残る1件は既知の大小文字衝突による
smaliファイル名の揺らぎだけで、対応するファイル内容のSHA-256は一致しました。

## English

Selective decode changes only explicitly selected component handling. Standard decode
without mode flags must remain output-compatible with the baseline `main` branch.

Malformed input is handled conservatively:

- invalid string style metadata is dropped while preserving the plain string;
- an invalid binary XML attribute is omitted while the remaining manifest is decoded;
- top-level binary XML chunk type `0x0009` is accepted only when its outer header and
  first string pool chunk are structurally valid;
- values are never inferred or synthesized.

Baseline and candidate standard-decode output trees were compared by relative path and
SHA-256. The 13-APK sample run produced 11 exact matches and 2 baseline failures fixed
by the candidate, with no output differences or candidate regressions. Standard and
selective manifest/smali outputs matched for all 13 APKs.

Two additional APKs with top-level XML chunk type `0x0009` failed before parser
initialization on the baseline and decoded successfully with the candidate.

A top-level null (`0x0000`) XML chunk type is accepted under the same structural
checks. Null chunks inside XML continue to be skipped.

The affected APK
`7fa1d8719f46ccb1c918e847ba31acf512b153115575035ca3dc5cefa62ce84a.apk`
decoded successfully in both standard and selective modes. Across all 16 APKs,
14 output trees were exact matches, this APK changed from baseline failure to
candidate success, and one APK only varied in case-colliding smali suffix assignment
with matching file SHA-256 values.

Known issue: on case-insensitive file systems, the `.1` suffix used for smali class
name collisions can be assigned to either case variant between runs. The corresponding
file contents remain identical, and deterministic collision naming is outside the
scope of this manifest decoding change.

Unreadable non-dex APK entries no longer block dex discovery. Only selected dex
entries are opened, and archive entries that fail to copy due to a `ZipException`
are omitted with a warning. Output I/O failures and unreadable selected dex entries
remain fatal.

The affected APK
`02d0456a6e5c695a7402e378471a31fa8bfa473b4e957e8cb612b9a9f358d2cc.apk`
decoded successfully while omitting three unreadable native libraries and preserving
six readable libraries. Across all 25 APKs, 23 output trees were exact matches,
this APK changed from baseline failure to candidate success, and one APK only showed
the known case-colliding smali filename variance with matching file SHA-256 values.
