# Decode hardening / デコードの耐障害性と診断改善（2026-11-12）

## 対象と比較基準

今回の比較対象は、このフォークの修正前コミット `284ad4c0` です。
公式 Apktool の最新リリースとの比較ではありません。従来の選択的デコード、
非標準の Manifest ヘッダー対応、読み取り不能な非DEXエントリの扱いは維持します。

対象は、CICMalDroid2020 の A: 8入力、B: 6入力、C: 4入力です。
A はデコード成功、B は再帰しない不正型エラー、C は正確なリソース診断を受入条件とします。
B/C の不正・未対応データの復元や画像生成成功は受入条件に含めません。

## A: 非UTF-8のZIPメタデータ

`ZipUtils.openZipFile` で従来と同じ UTF-8 読取りを最初に試みます。
エントリ名・コメントの文字コードエラーに限り、IBM437 で開き直し、warning を出します。
UTF-8フラグが付いたエントリは、代替読取りでもUTF-8のままです。

エントリ名が原因でZIPを開く際に失敗する場合と、コメントの遅延読取りにより
列挙中に失敗する場合の両方に対応します。呼出し元へZIPを返す前にメタデータの列挙を
完了させ、処理途中で文字コードを切り替えないようにします。

古いJDKの名前検索が、混在ZIPのUTF-8指定エントリを見つけられない場合には、
列挙済みの名前と照合します。入力ストリーム取得には元の `ZipEntry` を使い、
UTF-8フラグを保持します。ZIPディレクトリ、DEX読取り、frameworkインストールで
共通の読取り処理を利用します。

動作が変わる点:

- 従来失敗した非UTF-8メタデータのAPKを処理できるようになります。
- 代替読取りしたZIPでは、UTF-8フラグのない名前・コメントをIBM437として解釈します。
  これは元の言語や文字コードを特定したという意味ではありません。
  同じZIP内のフラグなしメタデータ全体に適用され、抽出先の名前にも反映されます。
- 元APK、DEX、Manifestのバイト列を書き換えません。
- 元々UTF-8で読めたZIP（UTF-8フラグなしのUTF-8名も含む）の解釈は維持します。
- ZIP構造・圧縮データ・出力先I/Oの不具合を文字コード問題として無視しません。
  再試行も失敗した場合は、初回の例外を suppressed exception として保持します。
- 元々の破損非DEXエントリのスキップ方針は変更しません。

## B: 不正なDEX型参照による再帰

Apktoolの `SmaliDecoder` で、選択されたDEXの型テーブルをbaksmaliへ渡す前に検査します。
同じdexlib2フォーマッタに生の `String` を渡して検査するため、
`TypeReference.toString → DexFormatter → TypeReference.toString` の循環を起こしません。
エラーにはDEX名、DEXオフセット、型インデックス、元の診断と原因例外を含めます。

動作が変わる点:

- 不正な型で `StackOverflowError` になる代わりに、有限の `AndrolibException` で失敗します。
- 選択されたDEXの型テーブル全体を検査するため、以前は参照されずに残っていた
  不正な型もdecode時にエラーになります。不正な型の推測・置換・黙認はしません。
- 検査はsmali出力前に行うため、不正DEXで失敗した場合の部分出力は以前と異なり得ます。
- 正常な型のsmali生成処理は維持します。型テーブルの事前走査分の処理が追加されます。
- DEXの `raw` / `skip` は型検査の対象外で、従来の保存・省略の動作を維持します。

この保護はApktoolのdecode経路で行います。smali/dexlib2の依存バージョンやクラスを
差し替えていません。同梱 `com.android.tools.smali.baksmali.Main` を直接起動する場合は
この事前検査を通らず、ライブラリ自体の不正型フォーマット問題は別途対応が必要です。

## C: 非空リソースに対するempty誤診断

`BinaryResourceParser` は、入力の先頭8バイトを記録してから従来と同じ解析を行います。
有効なチャンクに到達できなかった場合に、0バイトの入力と非空入力を区別します。
リソース解析エラーには、対象APKと `resources.arsc`、先頭ヘッダー、解析位置、
原因例外を含めます。成功時の解析・出力は変更しません。

例（対象APKのパスは省略）:

```text
Could not decode sample.apk!resources.arsc
(first header at 0x00000000: 00000c00c40c0000; position=0x00000cc4):
Non-empty input contains no supported resource table chunk.
```

動作が変わる点:

- NULLチャンクを読み飛ばして終了した非空入力を `Input file is empty.` と報告しません。
- 真に空の入力は引き続きemptyと診断し、不完全なヘッダーは非空として診断します。
- NULLのリソーステーブルを有効なテーブルとして扱う変更ではありません。
- `--res-mode skip` でもManifest解釈に必要なリソースを読む仕様は維持します。
- 4入力に共通するDEX 036は引き続き未対応として失敗します。ヘッダーを改変しません。

## 検証手順

両JARを同じソース基点、Java 11.0.27（Amazon Corretto / macOS arm64）、Gradle 8.14.4、
同じ依存バージョンでビルドします。比較用JARの埋込みバージョンも揃えます。
Java 8/21およびLinuxでの今回の修正版の実行確認は含みません。

開発用35 APKについて通常・選択的decodeをそれぞれ実行し、70組を比較します。
全ファイルの相対パス、サイズ、SHA-256、ディレクトリ、symlinkのリンク先を対象とし、
mtimeや所有者は比較しません。ファイル名の大小文字衝突に伴う順序の揺らぎを抑えるため、
両方とも `-XX:ActiveProcessorCount=1` / `-j 1` に揃えます。
検証のための実行条件であり、製品のデフォルト並列度は変更していません。

```bash
python3 scripts/validate_decode_outputs.py capture \
  --jar /path/to/before.jar --apk-dir /path/to/apk \
  --output /path/to/results/before
python3 scripts/validate_decode_outputs.py capture \
  --jar /path/to/after.jar --apk-dir /path/to/apk \
  --output /path/to/results/after
python3 scripts/validate_decode_outputs.py compare \
  --before /path/to/results/before --after /path/to/results/after \
  --output /path/to/results/comparison.json
python3 scripts/validate_decode_incidents.py \
  --before /path/to/before.jar --after /path/to/after.jar \
  --data-dir /path/to/CICMalDroid2020 --output /path/to/results/incidents
```

`validate_decode_incidents.py` はデータディレクトリの `copy-verification.json` を参照します。
各要素の `path`、`sha256`、`group` で入力と受入条件を特定します。
元入力を変更せず、stdout/stderr全文、コマンド、ハッシュと各検査結果を保存します。
互換性検証スクリプトは比較用の出力ツリーをハッシュ記録後に削除し、ログと
圧縮したツリーマニフェストを保持します。入力APKは削除しません。

## 検証結果

- 全216テスト（既存199 + 追加17）が成功。失敗・エラー・スキップなし。
- `build shadowJar proguard` が成功。
- 対象18入力は全件で受入条件を満たしました。
  - Aの8件は通常・選択的decodeが両方成功。全DEXのsmaliは抽出DEX単体の逆アセンブル結果と
    パス・内容が一致し、クラス数も一致。raw保存したDEX・Manifestは元エントリと同一。
  - Bの6件は型インデックス付きの有限の例外で失敗し、StackOverflowErrorは発生しません。
  - Cの4件は非空リソースをヘッダー・位置付きで診断。DEXのみの処理では036未対応を確認。
- 開発用35件 × 通常/選択的decodeの70組はすべて成功し、出力ツリーが完全一致しました。
  修正前後合わせて140回のdecodeを実行し、差分・回帰・timeoutは0件でした。
  今回は大小文字衝突によるファイル名の差分もありませんでした。
- 全53入力の元APKのハッシュは維持されています。

入力一覧、JARのSHA-256、ファイル数、受入条件の結果は
[`validation/2026-11-12-decode-hardening.json`](validation/2026-11-12-decode-hardening.json) に記録しています。
ローカルの全文ログ・出力ツリーのハッシュ記録は `build/reports/decode-fixes-20261112/` にあります。
比較用JARは両方とも `v3.0.2-16-284ad4c0-SNAPSHOT` の埋込みバージョンです。
コミット後の配布JARでは通常のビルド仕様によりバージョン識別子が更新され、
`apktool.yml` の `version` にも反映されます。これはデコード内容の変更とは区別します。

## English summary

UTF-8 ZIP metadata remains the default. Only metadata decoding failures trigger an IBM437
retry, including errors during enumeration. UTF-8 flags and original payload bytes are
preserved; non-UTF-8-flagged metadata in a fallback archive is interpreted as IBM437.
Mixed-charset entry lookup also handles older JDKs that encode lookup names with the
archive charset. Invalid ZIP structure and unrelated I/O failures are not suppressed.

Before invoking baksmali, Apktool validates all type strings in each selected DEX using
the existing dexlib2 formatter on raw Strings, avoiding recursive TypeReference error
formatting. Invalid unused type entries now fail decode too. Raw/skip modes are unchanged.
This guards Apktool's decode path; it does not patch the standalone baksmali entry point.

Resource errors now distinguish empty input from nonempty, unsupported/truncated structure
and identify the source, first header and position. NULL resource tables and DEX 036 are
not repaired or silently accepted. Compatibility is measured against fork commit 284ad4c0,
not the latest official upstream release.

All 216 tests passed. All 35 development APKs produced identical trees in both normal
and selective modes (70 matching pairs / 140 decodes, with matching embedded build versions).
All 18 incident inputs met their respective acceptance criteria: 8 successful decodes,
6 finite invalid-type failures, and 4 correct resource diagnostics with DEX 036 still rejected.
