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

どちらも、存在しない値を補完したり、文脈から値を推測したりしません。

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

## English

Selective decode changes only explicitly selected component handling. Standard decode
without mode flags must remain output-compatible with the baseline `main` branch.

Malformed input is handled conservatively:

- invalid string style metadata is dropped while preserving the plain string;
- an invalid binary XML attribute is omitted while the remaining manifest is decoded;
- values are never inferred or synthesized.

Baseline and candidate standard-decode output trees were compared by relative path and
SHA-256. The 13-APK sample run produced 11 exact matches and 2 baseline failures fixed
by the candidate, with no output differences or candidate regressions. Standard and
selective manifest/smali outputs matched for all 13 APKs.
