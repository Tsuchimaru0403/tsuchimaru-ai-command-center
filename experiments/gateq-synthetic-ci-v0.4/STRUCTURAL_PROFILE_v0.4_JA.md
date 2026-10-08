# Gate Q 合成CI v0.4: ZIP構造プロファイル（合成限定）

状態: **AUTHOR IMPLEMENTATION / TEST PASS; FRESH INDEPENDENT AUDIT NOT DONE**。

これは ZIP を展開するツールではなく、合成データの読み取り専用バイト構造検査器。検査結果は `SYNTHETIC_STRUCTURE_PASS_UNVERIFIED` であり、出所証明・承認・正本認定・Runtime許可ではない。

## 許可する構造

- シングルディスクZIP。先頭に自己解凍スタブ等の前置きデータなし。EOCDはファイルの末端にあり、合法なEOCDコメントは許容する。
- EOCDの中央ディレクトリ開始位置・長さ・メンバー数と、中央ディレクトリ内の全エントリの境界が完全一致。未参照の余剰バイトを認めない。
- 各中央ディレクトリエントリは、対応するローカルヘッダーをちょうど1つ持つ。ローカルメンバー間の領域に隙間・重複を認めない。
- 中央とローカルのバージョン、汎用フラグ、圧縮方式、タイムスタンプ、ファイル名が一致。CRCと展開・圧縮サイズも比較する。
- 汎用フラグで許すものは UTF-8 (bit 11) と Data Descriptor (bit 3) のみ。データの暗号化、分割ZIP等は拒否する。
- bit 3が立っている場合、圧縮データ直後にCRCと圧縮・展開サイズを持つData Descriptorが必要。署名あり/なし、32bit/64bitサイズの形を許容し、位置・サイズ・全値を照合する。
- ZIP64のローカル/中央Extraは、legacy size/offsetで `0xffffffff` を宣言している場合に、その値を順序通りに記録している必要がある。ZIP64 EOCDとlocatorも、legacyのセンチネル、オフセット、全長を照合する。
- その他のextra fieldは長さが正しい場合のみ許容する。ただし余剰/重複のZIP64 fieldは拒否する。
- 圧縮方式はSTORED/DEFLATEDに限定。圧縮ストリームについてはv0.3の展開サイズ、終端、CRC検査を引き続き適用する。
- メンバー名はv0.3同様の安全なフラットASCII名のみ。**ZIPファイルの展開は行わない。**

## 境界と限界

- ZIPの全仕様を汎用に解釈するものではない。デジタル署名レコード、スパンドZIP、一部の拡張フラグ等は許容しない（fail closed）。
- ZIP64は「ローカル `force_zip64=True`」「合法なZIP64 EOCD」「Data Descriptor」の合成テストで動作を確認。巨大なZIP64を実際に生成・検査したわけではない。上限2MBの合成ZIPのみ対象。
- expected.jsonの自己申告ハッシュは信頼できる署名・外部証跡ではない。trust_root/Owner/WebAuthn/Runtime等のGate Q本体ブロッカーは未解決。
- GitHub WorkflowはDRAFTのままで実行せず、必須statusへの昇格は不可。
