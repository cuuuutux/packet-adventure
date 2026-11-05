# パケットの大冒険 — 実装仕様（エージェント間の契約）

学校課題。「ブラウザに URL を入れてからページが表示され、ログインするまで」に
ネットワークで何が起きているかを、1 ステップずつ操作して学べるシミュレーター。

- 依存ゼロの静的サイト（HTML + CSS + 素の JavaScript）。ビルド不要。GitHub Pages で公開。
- 対象ブラウザ：Windows 11 の Edge / Chrome（最新）。スマホ幅（360px）でも崩れないこと。
- 言語：日本語 UI。フォント：`"Segoe UI", "Yu Gothic UI", "Meiryo", system-ui, sans-serif`
- ライト／ダーク両対応（`prefers-color-scheme`）。色は `:root` の CSS 変数で定義。
- 外部 CDN・外部画像・トラッキングなし。

## ファイル構成と担当

| ファイル | 担当 |
|---|---|
| `index.html`, `css/style.css`, `js/app.js` | エージェント A（画面・アニメーション・操作） |
| `js/steps.js`, `js/glossary.js` | エージェント B（教材データ） |

A は B のファイルを、B は A のファイルを**編集しない**。データ形式は下記に厳密に従う。
`index.html` は `js/glossary.js` → `js/steps.js` → `js/app.js` の順で読み込む（通常の `<script>`、module ではない。file:// で直接開いても動くこと）。

## ネットワーク上のノード（固定 ID）

| id | 表示名 | IP |
|---|---|---|
| `pc` | あなたのPC（ブラウザ） | 192.168.1.10（プライベート） |
| `router` | 家のルーター | 192.168.1.1 / グローバル 198.51.100.7 |
| `dns` | DNSサーバー（フルサービスリゾルバ） | 198.51.100.53 |
| `server` | Webサーバー（www.example.com） | 203.0.113.80 |
| `attacker` | 盗聴者（同じ公衆Wi-Fiにいる人のイメージ） | — 通信の当事者にはならない |

盗聴者は「pc–router 間のリンク」を覗いている設定。盗聴者モード ON のとき、
各ステップの `sniff` テキストを盗聴者の吹き出しに表示する。

## グローバル変数（B が定義、A が読む）

```js
window.STAGES = [ { id: "dns", label: "① DNS 名前解決", color: "var(--c-dns)" }, ... ];
// id は "dns" | "tcp" | "tls" | "http" | "close" のいずれか。表示順に並べる。

window.STEPS = [ Step, ... ];      // 表示順
window.GLOSSARY = { "SYN": Term, ... };
```

### Step

```js
{
  id: "tcp-syn",                 // 一意
  stage: "tcp",                  // STAGES の id
  title: "SYN：接続してもいい？",   // 短い見出し
  from: "pc", to: "server",      // ノード ID。経路は A が pc→router→(dns|server) と自動で通す
  label: "SYN",                  // パケットに描く短いラベル（8文字以内目安）
  encrypted: false,              // true ならパケットに🔒、中身は読めない表現
  dropped: false,                // true なら途中（router を過ぎたあたり）で💥消滅させる
  only: undefined,               // "http" | "https" | undefined。プロトコル切替で表示/非表示
  lossOnly: false,               // true のステップは「パケットロス」トグル ON のときだけ出る
  desc: "HTML文字列。2〜5文。何が起きていて、なぜ必要か。<b>, <code> 程度のみ使用",
  headers: [                     // パケットの中身パネル。下位層から順に
    { layer: "IP",  fields: [["送信元IP", "192.168.1.10"], ["宛先IP", "203.0.113.80"]] },
    { layer: "TCP", fields: [["送信元ポート", "50432"], ["宛先ポート", "443"], ["フラグ", "SYN"], ["シーケンス番号", "1000"]] }
  ],
  sniff: "盗聴者に見えるもの（プレーンテキスト）",
  terms: ["SYN", "ポート番号"]     // GLOSSARY のキー。解説パネル下に用語チップとして表示
}
```

### Term

```js
{ name: "SYN", reading: "シン", meaning: "…", origin: "SYNchronize（同期する）の略。…", memo: "覚え方：…" }
```

## 画面要件（A）

- ヘッダ：タイトル「パケットの大冒険」、サブ「URL を入力してからログインするまで」。
  アドレスバー風表示（HTTPS 時 `🔒 https://www.example.com/login`、HTTP 時 `⚠ http://...`）。
- コントロール：⏮ 最初へ / ◀ 戻る / ▶ 再生・⏸ 一時停止 / 次へ ▶、ステップスライダー、
  速度（0.5x/1x/2x）。キーボード：←/→ で前後、Space で再生/停止。
- トグル：🔒 HTTPS ⇄ 🔓 HTTP、👀 盗聴者モード、💥 パケットロス。
  切替時は表示ステップ列を再計算し、現在位置をできるだけ同じステージに保つ。
- ステージ進捗バー：STAGES を横に並べ、現在ステージを強調。クリックでそのステージ先頭へ。
- ネットワーク図：インライン SVG。pc / router / dns / server を配置し、リンクを線で描く。
  attacker は盗聴者モード ON 時だけ pc–router リンク付近に表示。
- パケットアニメーション：`from`→`to` の経路に沿ってパケット（角丸矩形＋label）が移動。
  ステージ色で塗る。encrypted は🔒付きで縞模様など。dropped は途中で💥→消える。
  `prefers-reduced-motion` のときはアニメーションを短縮。
- 解説パネル：ステップ番号「3 / 18」、ステージ名、title、desc、用語チップ（クリックで用語集モーダル：意味・由来・覚え方）。
- パケットの中身パネル：headers を層ごとのカードで表示（Ethernet→IP→TCP/UDP→TLS→HTTP の積み木のイメージ）。
- 盗聴者パネル（モード ON 時）：sniff を表示。暗号化ステップでは文字化け風に。
- 最後のステップの後に「まとめ」カード：HTTP と HTTPS の違い、盗聴者に何が見えたか。
- 画面下に小さく「このサイトは学習用シミュレーションです。IP アドレスは文書用の予約アドレス（RFC 5737）を使用」。
- 1 画面に収まるレイアウト（1366×768 で主要要素がスクロールなしで見えるのが理想）。スマホでは縦積み。
