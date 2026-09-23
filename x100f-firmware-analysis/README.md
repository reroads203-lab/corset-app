# X100F firmware analysis

FUJIFILM X100F ファームウェア（Ver.2.12）を静的に解析した結果とツール一式です。結果は [REPORT.md](REPORT.md) にまとめています。

ファームウェア本体（`FPUPDATE.DAT`）はリポジトリに含めていません。富士フイルムの公式サイトから入手してください。

圧縮パーティション（ID5/ID6）の独自 LZ 形式も解読済みで、完全展開できます（[REPORT.md](REPORT.md) 4 章）。

| ファイル | 内容 |
|---|---|
| `tools/x100f_unpack.py` | ヘッダ解析、ビット反転の復号、パーティション表の解析、圧縮領域の展開を含む領域の切り出し、`memory_map.json` の出力（標準ライブラリのみ） |
| `tools/x100f_lzss.py` | 圧縮パーティションの展開器（独自 LZSS。標準ライブラリのみ） |
| `tools/arm_xrefs.py` | 文字列の参照元探し、関数の逆アセンブル、ロードアドレスの推定（numpy と capstone が必要） |
| `tools/ghidra_import_x100f.py` | Ghidra 用。メモリマップの作成と、特定済みの関数名・コメントの適用 |

```sh
python3 tools/x100f_unpack.py FPUPDATE.DAT out/
```

解析は読み取りのみです。改変したファームウェアを書き込むと、カメラが起動しなくなるおそれがあります。
