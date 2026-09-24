# X100F firmware analysis

FUJIFILM X100F ファームウェア（Ver.2.12）を静的に解析した結果とツール一式です。結果は [REPORT.md](REPORT.md) にまとめています。

ファームウェア本体（`FPUPDATE.DAT`）はリポジトリに含めていません。富士フイルムの公式サイトから入手してください。

圧縮パーティション（ID5/ID6）の独自 LZ 形式も解読済みで、完全展開できます（[REPORT.md](REPORT.md) 4 章）。

| ファイル | 内容 |
|---|---|
| `tools/x100f_unpack.py` | ヘッダ解析、ビット反転の復号、パーティション表の解析、圧縮領域の展開を含む領域の切り出し、`memory_map.json` の出力（標準ライブラリのみ） |
| `tools/x100f_lzss.py` | 圧縮パーティションの展開器（独自 LZSS。標準ライブラリのみ） |
| `tools/arm_xrefs.py` | 文字列の参照元探し、関数の逆アセンブル、ロードアドレスの推定（numpy と capstone が必要） |
| `tools/ana6.py` | 展開済み ID6 を対話的に解析するヘルパ（`X100F_REGIONS` で領域ディレクトリを指定） |
| `tools/codecheck.py` | 領域が本物の ARM コードかを判定（BL の飛び先が関数入口に当たる割合で測る） |
| `tools/jumptable_check.py` | ジャンプテーブルの境界チェックを全数検査（off-by-one 検出） |
| `tools/calcbug_scan.py` | ゼロ除算の可能性・掛け算の 16 ビット切り詰めを走査 |
| `tools/lz3.py` / `tools/lzss_ring.py` | 圧縮形式の特定に使った総当たり（記録として保存） |
| `tools/ghidra_import_x100f.py` | Ghidra 用。メモリマップの作成と、特定済みの関数名・コメントの適用 |
| `data/menu_items.txt` | ファームから抽出したメニュー項目の全一覧（372 個） |

```sh
python3 tools/x100f_unpack.py FPUPDATE.DAT out/
```

解析は読み取りのみです。改変したファームウェアを書き込むと、カメラが起動しなくなるおそれがあります。
