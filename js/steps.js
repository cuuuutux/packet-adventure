/* =========================================================
 * パケットの大冒険 — ステップデータ（エージェント B 担当）
 *
 * シナリオ：ブラウザで www.example.com/login を開き、
 *           ID とパスワードでログインし、最後に接続を閉じる。
 *
 * - IP アドレスは文書用の予約アドレス（RFC 5737）。
 * - 値は PC 側から見たもの（NAT 変換前のプライベート IP）。
 * - クライアントの送信元ポートは 50432 で統一。
 * - only: "http" / "https" で表示を切り替え。lossOnly はパケットロス ON 時のみ。
 *
 * TCP の番号（データ長 = TCP ペイロードのバイト数）
 *   PC の初期シーケンス番号 = 1000、サーバー = 5000
 *   HTTPS: PC  1001 →(ClientHello 517)→ 1518 →(Finished 58)→ 1576 →(GET 424)→ 2000
 *               →(POST 570)→ 2570 →(GET 477)→ 3047 →FIN
 *          SV  5001 →(ServerHello〜Finished 2700)→ 7701 →(200 2332)→ 10033
 *               →(302 312)→ 10345 →(200 1842)→ 12187 →FIN
 *   HTTP : PC  1001 →(GET 402)→ 1403 →(POST 548)→ 1951 →(GET 455)→ 2406 →FIN
 *          SV  5001 →(200 2310)→ 7311 →(302 290)→ 7601 →(200 1820)→ 9421 →FIN
 *   （HTTPS の各 HTTP メッセージ = HTTP 版の長さ + TLS レコードのオーバーヘッド 22 バイト）
 * ========================================================= */
(function () {
  "use strict";

  var PC_IP = "192.168.1.10";
  var DNS_IP = "198.51.100.53";
  var SV_IP = "203.0.113.80";
  var CPORT = "50432";

  function port(mode) { return mode === "https" ? "443" : "80"; }
  function portName(mode) { return mode === "https" ? "443 (HTTPS)" : "80 (HTTP)"; }

  /* ---------- 層ごとのヘッダを作る小さな関数 ---------- */
  function ip(src, dst, proto, ttl) {
    return {
      layer: "IP",
      fields: [
        ["バージョン", "4 (IPv4)"],
        ["送信元IP", src],
        ["宛先IP", dst],
        ["プロトコル", proto === "UDP" ? "17 (UDP)" : "6 (TCP)"],
        ["TTL（ホップ上限）", ttl]
      ]
    };
  }
  function ipUp(dst, proto) { return ip(PC_IP, dst, proto, "64"); }
  function ipDown(src, proto) { return ip(src, PC_IP, proto, src === DNS_IP ? "58" : "53"); }

  // dir: "up"（PC→サーバー） / "down"（サーバー→PC）
  function tcp(mode, dir, flags, seq, ack, len, extra) {
    var sp = dir === "up" ? CPORT : port(mode);
    var dp = dir === "up" ? port(mode) : CPORT;
    var f = [
      ["送信元ポート", dir === "up" ? sp : portName(mode)],
      ["宛先ポート", dir === "up" ? portName(mode) : dp],
      ["フラグ", flags],
      ["シーケンス番号", String(seq)],
      ["確認応答番号", ack === null ? "0（まだ使わない）" : String(ack)],
      ["データ長", len]
    ];
    if (extra) f = f.concat(extra);
    return { layer: "TCP", fields: f };
  }

  // HTTPS で HTTP を運ぶ TLS レコード（外から見える部分）
  function tlsAppData(recLenHex, recLen) {
    return {
      layer: "TLS",
      fields: [
        ["レコード種別", "Application Data (23)"],
        ["バージョン表記", "0x0303"],
        ["レコード長", recLen + " バイト（" + recLenHex + "）"],
        ["中身", "🔒 AES-128-GCM で暗号化済み"]
      ]
    };
  }
  // 暗号化された HTTP 層（本人たちにしか読めない）
  function httpHidden(inner) {
    return {
      layer: "HTTP",
      fields: [
        ["盗聴者から", "🔒 暗号化されていて見えない"],
        ["暗号化前の中身（PCとサーバーだけが読める）", inner]
      ]
    };
  }

  var UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) …";

  /* ---------- ステージ ---------- */
  window.STAGES = [
    { id: "dns",   label: "① DNS 名前解決",          color: "var(--c-dns)" },
    { id: "tcp",   label: "② TCP 接続",              color: "var(--c-tcp)" },
    { id: "tls",   label: "③ TLS 暗号化の準備",      color: "var(--c-tls)" },
    { id: "http",  label: "④ HTTP ページ表示とログイン", color: "var(--c-http)" },
    { id: "close", label: "⑤ 切断",                  color: "var(--c-close)" }
  ];

  var S = [];

  /* =====================================================
   * ① DNS
   * ===================================================== */
  S.push({
    id: "dns-query",
    stage: "dns",
    title: "DNS：www.example.com の IP アドレスは？",
    from: "pc", to: "dns",
    label: "DNS問合せ",
    encrypted: false, dropped: false, lossOnly: false,
    desc: "ブラウザは「www.example.com」という名前のままでは相手にパケットを届けられないので、まず <b>DNS サーバー</b>に IP アドレスを問い合わせます。" +
      "問い合わせは <b>UDP</b> の 53 番ポート宛てで、「<b>A レコード</b>（IPv4 アドレス）を教えて。知らなければ代わりに調べて（再帰要求 <code>RD=1</code>）」という内容です。" +
      "今回はキャッシュに答えがないので、フルサービスリゾルバが ルート DNS → <code>.com</code> の TLD サーバー → example.com の権威 DNS サーバーの順にたどって答えを探してくれます。" +
      "電話帳で名前から電話番号を引くイメージです。",
    headers: [
      ipUp(DNS_IP, "UDP"),
      { layer: "UDP", fields: [["送信元ポート", CPORT], ["宛先ポート", "53 (DNS)"], ["長さ", "41 バイト"]] },
      { layer: "DNS", fields: [
        ["ID", "0x3a7c"],
        ["フラグ", "QR=0（問い合わせ）, RD=1（再帰要求）"],
        ["質問数", "1"],
        ["質問", "www.example.com / タイプ A / クラス IN"]
      ] }
    ],
    sniff: "DNS 問い合わせ（平文）：「www.example.com の A レコードは？」\n192.168.1.10:50432 → 198.51.100.53:53 (UDP)\n→ この人がこれから www.example.com に行くことがバレる",
    terms: ["DNS", "フルサービスリゾルバ", "UDP", "ポート番号", "Aレコード", "盗聴"]
  });

  S.push({
    id: "dns-response",
    stage: "dns",
    title: "DNS 応答：203.0.113.80 です",
    from: "dns", to: "pc",
    label: "DNS応答",
    encrypted: false, dropped: false, lossOnly: false,
    desc: "DNS サーバーから「www.example.com は <b>203.0.113.80</b>」という答えが返ってきました。問い合わせと同じ ID（<code>0x3a7c</code>）が付いているので、どの質問への答えかが分かります。" +
      "<b>TTL</b>=3600 は「この答えを 3600 秒（1 時間）は覚えておいてよい」という意味で、その間はキャッシュを使うので同じ問い合わせをしなくて済みます。" +
      "なお、インターネット側から見た PC の住所はルーターのグローバル IP（198.51.100.7）で、返事はルーターが <b>NAT</b> の対応表を見て PC（192.168.1.10）に届けています。",
    headers: [
      ipDown(DNS_IP, "UDP"),
      { layer: "UDP", fields: [["送信元ポート", "53 (DNS)"], ["宛先ポート", CPORT], ["長さ", "57 バイト"]] },
      { layer: "DNS", fields: [
        ["ID", "0x3a7c（問い合わせと同じ）"],
        ["フラグ", "QR=1（応答）, RD=1, RA=1（再帰できます）"],
        ["応答コード", "0 (NOERROR)"],
        ["質問", "www.example.com / A / IN"],
        ["回答", "www.example.com  A  203.0.113.80"],
        ["TTL", "3600 秒"]
      ] }
    ],
    sniff: "DNS 応答（平文）：www.example.com = 203.0.113.80（TTL 3600）\n→ このあと 203.0.113.80 と通信したら、それが www.example.com だと分かる",
    terms: ["DNS", "Aレコード", "TTL", "NAT", "IPアドレス"]
  });

  /* =====================================================
   * ② TCP 3ウェイハンドシェイク（HTTP=80番 / HTTPS=443番で別ステップ）
   * ===================================================== */
  ["https", "http"].forEach(function (mode) {
    S.push({
      id: "tcp-syn-lost-" + mode,
      stage: "tcp",
      title: "SYN が途中で消えた…！",
      from: "pc", to: "server",
      label: "SYN",
      encrypted: false, dropped: true, only: mode, lossOnly: true,
      desc: "PC は Web サーバーに接続を申し込む <b>SYN</b> を送りましたが、ルーターの先の混雑（待ち行列のあふれ）で捨てられてしまいました。" +
        "インターネットは「パケットが届かないこともある」前提で作られているので、送った側はまず返事（SYN+ACK）を待ちます。" +
        "決められた時間（<b>RTO</b>：再送タイムアウト。最初は約 1 秒）が過ぎても返事が来なければ「届かなかった」と判断し、同じ SYN を送り直します。" +
        "それでも届かなければ待ち時間を 2 倍、4 倍…と延ばして再挑戦します（指数バックオフ）。",
      headers: [
        ipUp(SV_IP, "TCP"),
        tcp(mode, "up", "SYN", 1000, null, "0", [["状態", "💥 途中で消失 → 約 1 秒待って再送へ"]])
      ],
      sniff: "192.168.1.10:50432 → 203.0.113.80:" + port(mode) + " [SYN] seq=1000\n（盗聴者のいる区間は通過した。この先で消えたので返事は来ない）",
      terms: ["SYN", "再送(RTO)", "TCP"]
    });
  });

  ["https", "http"].forEach(function (mode) {
    S.push({
      id: "tcp-syn-" + mode,
      stage: "tcp",
      title: "SYN：接続してもいい？",
      from: "pc", to: "server",
      label: "SYN",
      encrypted: false, dropped: false, only: mode, lossOnly: false,
      desc: "IP アドレスが分かったので、Web サーバーの <b>" + port(mode) + " 番ポート</b>（" + mode.toUpperCase() + " の窓口）に TCP の接続を申し込む <b>SYN</b> を送ります。" +
        "<b>TCP</b> は「抜けなく・順番どおり届ける」ために、データを送る前に 3 回のやりとり（<b>3ウェイハンドシェイク</b>）で準備をそろえます。" +
        "シーケンス番号 1000 は「私が送るデータはこの番号から数えます」という宣言です（実際は推測されにくいランダムな数）。" +
        "パケットロス ON のときは、これがタイムアウト後に送り直した<b>再送の SYN</b> です（中身は 1 回目とまったく同じ）。",
      headers: [
        ipUp(SV_IP, "TCP"),
        tcp(mode, "up", "SYN", 1000, null, "0", [
          ["ウィンドウ", "64240"],
          ["オプション", "MSS=1460, SACK許可, ウィンドウスケール=8"]
        ])
      ],
      sniff: "192.168.1.10:50432 → 203.0.113.80:" + port(mode) + " [SYN] seq=1000\n→ " + port(mode) + " 番なので" + (mode === "https" ? " HTTPS" : "暗号化なしの HTTP") + " で接続しようとしていると分かる",
      terms: ["TCP", "SYN", "3ウェイハンドシェイク", "シーケンス番号", "ポート番号"]
    });
  });

  ["https", "http"].forEach(function (mode) {
    S.push({
      id: "tcp-synack-" + mode,
      stage: "tcp",
      title: "SYN+ACK：いいよ、こっちからもよろしく",
      from: "server", to: "pc",
      label: "SYN+ACK",
      encrypted: false, dropped: false, only: mode, lossOnly: false,
      desc: "サーバーは「受け取ったよ（<b>ACK</b>）」と「こちらからも接続したい（<b>SYN</b>）」を 1 つのパケットにまとめて返します。" +
        "確認応答番号 <code>1001</code> は「あなたの 1000 番は受け取った。次は 1001 番からちょうだい」という意味で、相手のシーケンス番号 + 1 になります。" +
        "サーバーも自分のシーケンス番号の初期値 <code>5000</code> を宣言します。",
      headers: [
        ipDown(SV_IP, "TCP"),
        tcp(mode, "down", "SYN, ACK", 5000, 1001, "0", [
          ["ウィンドウ", "65535"],
          ["オプション", "MSS=1460, SACK許可, ウィンドウスケール=7"]
        ])
      ],
      sniff: "203.0.113.80:" + port(mode) + " → 192.168.1.10:50432 [SYN, ACK] seq=5000 ack=1001\n→ サーバーが接続に応じたことが分かる",
      terms: ["SYN", "ACK", "シーケンス番号", "3ウェイハンドシェイク"]
    });
  });

  ["https", "http"].forEach(function (mode) {
    S.push({
      id: "tcp-ack-" + mode,
      stage: "tcp",
      title: "ACK：接続完了！",
      from: "pc", to: "server",
      label: "ACK",
      encrypted: false, dropped: false, only: mode, lossOnly: false,
      desc: "PC が「あなたの 5000 番を受け取った」という <b>ACK</b>（確認応答番号 <code>5001</code>）を返し、<b>3ウェイハンドシェイク</b>が完了しました。" +
        "お互いが相手の番号を確認しあったので、これ以降はデータの抜けや順番の入れ替わりを番号で見つけて直せます。" +
        "電話の「もしもし」「はい、聞こえます」「では話しますね」のようなものです。",
      headers: [
        ipUp(SV_IP, "TCP"),
        tcp(mode, "up", "ACK", 1001, 5001, "0")
      ],
      sniff: "192.168.1.10:50432 → 203.0.113.80:" + port(mode) + " [ACK] seq=1001 ack=5001\n→ TCP 接続が確立したことが分かる",
      terms: ["ACK", "3ウェイハンドシェイク", "シーケンス番号"]
    });
  });

  /* =====================================================
   * ③ TLS 1.3 ハンドシェイク（HTTPS のみ）
   * ===================================================== */
  S.push({
    id: "tls-client-hello",
    stage: "tls",
    title: "ClientHello：暗号化の相談をしよう",
    from: "pc", to: "server",
    label: "Hello",
    encrypted: false, dropped: false, only: "https", lossOnly: false,
    desc: "TCP の接続ができたので、次は暗号化の準備（<b>TLS 1.3</b> のハンドシェイク）です。PC は <b>ClientHello</b> で、使える暗号方式の一覧と、鍵を作るための材料（<code>key_share</code>：鍵共有の公開値）を送ります。" +
      "1 台のサーバーが複数のサイトを受け持つことがあるので、どのサイトに用があるかを <b>SNI</b>（<code>www.example.com</code>）で伝えます。" +
      "この時点ではまだ鍵がないため、SNI を含めて ClientHello は<b>平文</b>です（ECH という新しい技術で隠す取り組みも進んでいます）。",
    headers: [
      ipUp(SV_IP, "TCP"),
      tcp("https", "up", "PSH, ACK", 1001, 5001, "517 バイト"),
      { layer: "TLS", fields: [
        ["レコード種別", "Handshake (22)"],
        ["バージョン表記", "0x0301（古い機器との互換用の値）"],
        ["レコード長", "512 バイト"],
        ["メッセージ", "ClientHello"],
        ["supported_versions", "TLS 1.3"],
        ["暗号スイート", "TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256"],
        ["SNI (server_name)", "www.example.com"],
        ["key_share", "x25519（公開値 32 バイト）"],
        ["ALPN", "http/1.1"]
      ] }
    ],
    sniff: "TLS ClientHello（平文）\nSNI: www.example.com ← 行き先のサイト名は見える！\n対応する暗号方式・key_share（公開値なので見られても鍵は作れない）\n16 03 01 02 00 01 00 01 fc 03 03 …",
    terms: ["TLS", "ClientHello", "SNI", "公開鍵暗号", "HTTPS"]
  });

  S.push({
    id: "tls-server-hello",
    stage: "tls",
    title: "ServerHello＋証明書：本物のサーバーです",
    from: "server", to: "pc",
    label: "Hello+証明",
    encrypted: true, dropped: false, only: "https", lossOnly: false,
    desc: "サーバーは <b>ServerHello</b> で暗号方式（TLS_AES_128_GCM_SHA256）を選び、自分の key_share を返します。お互いの key_share から、PC とサーバーだけが同じ鍵を計算でき（ECDHE 鍵交換）、<b>ここから先はすべて暗号化</b>されます。" +
      "続けて暗号化した状態で、<b>証明書</b>（Certificate）、その証明書の秘密鍵を本当に持っている証拠の署名（CertificateVerify）、ここまでのやりとりが改ざんされていない確認（Finished）が届きます。" +
      "ブラウザは、証明書が www.example.com 用か・有効期限内かを確かめ、さらに「サーバー証明書 → 中間 CA → OS やブラウザに最初から入っているルート<b>認証局（CA）</b>」と署名のチェーンがつながるかを検証します。" +
      "これで、途中で誰かがなりすましていないことを確認できます。",
    headers: [
      ipDown(SV_IP, "TCP"),
      tcp("https", "down", "PSH, ACK", 5001, 1518, "2700 バイト（実際は 2 セグメントに分かれて届く）"),
      { layer: "TLS（平文）", fields: [
        ["レコード種別", "Handshake (22)"],
        ["メッセージ", "ServerHello（127 バイト）"],
        ["supported_versions", "TLS 1.3"],
        ["選んだ暗号スイート", "TLS_AES_128_GCM_SHA256"],
        ["key_share", "x25519（サーバーの公開値 32 バイト）"]
      ] },
      { layer: "TLS（暗号化）", fields: [
        ["レコード種別（見かけ）", "Application Data (23)"],
        ["レコード長", "2568 バイト（0x0a08）"],
        ["中身", "🔒 EncryptedExtensions / Certificate / CertificateVerify / Finished"],
        ["証明書チェーン", "www.example.com → 中間CA → ルートCA"]
      ] }
    ],
    sniff: "ServerHello（平文）：TLS 1.3 / TLS_AES_128_GCM_SHA256 / key_share の公開値\nその後：17 03 03 0a 08 5e 91 c7 3b … (読めない)\n※TLS 1.3 では証明書も暗号化されるので見えない（TLS 1.2 までは丸見えだった）\n受信量：約 2.7 KB",
    terms: ["TLS", "証明書", "認証局(CA)", "公開鍵暗号", "共通鍵暗号"]
  });

  S.push({
    id: "tls-client-finished",
    stage: "tls",
    title: "Finished：暗号化の準備完了",
    from: "pc", to: "server",
    label: "Finished",
    encrypted: true, dropped: false, only: "https", lossOnly: false,
    desc: "証明書の検証に成功したので、PC もここまでの全メッセージから計算した <b>Finished</b> を暗号化して送り、TLS ハンドシェイクが完了します。" +
      "以降の HTTP のデータは、さきほど作った鍵による<b>共通鍵暗号</b>（AES-GCM）で暗号化されます。" +
      "計算に手間のかかる<b>公開鍵暗号</b>の技術は「鍵の受け渡し」と「本人確認」だけに使い、大量のデータは高速な共通鍵暗号で守る、という役割分担がポイントです。",
    headers: [
      ipUp(SV_IP, "TCP"),
      tcp("https", "up", "PSH, ACK", 1518, 7701, "58 バイト"),
      { layer: "TLS", fields: [
        ["レコード種別（見かけ）", "Application Data (23)"],
        ["レコード長", "53 バイト（0x0035）"],
        ["中身", "🔒 Finished（検証データ 32 バイト）"]
      ] }
    ],
    sniff: "17 03 03 00 35 a4 1f 6b 0e 92 … (読めない)\n→ 暗号化された短いデータが送られたことだけ分かる",
    terms: ["TLS", "共通鍵暗号", "公開鍵暗号"]
  });

  /* =====================================================
   * ④ HTTP（HTTPS 版は暗号化 / HTTP 版は平文）
   * ===================================================== */

  // --- GET /login ---
  S.push({
    id: "http-get-https",
    stage: "http",
    title: "GET /login：ログインページをください",
    from: "pc", to: "server",
    label: "GET",
    encrypted: true, dropped: false, only: "https", lossOnly: false,
    desc: "いよいよ <b>HTTP</b> の出番です。ブラウザは「/login のページをください」という <b>GET</b> リクエストを送ります。" +
      "<b>HTTPS</b> なので、このリクエストは TLS の Application Data として暗号化されてから送られ、途中の人には中身が読めません。" +
      "ただし、宛先の IP アドレス・ポート番号・データの大きさなど「封筒の外側」は見えます。",
    headers: [
      ipUp(SV_IP, "TCP"),
      tcp("https", "up", "PSH, ACK", 1576, 7701, "424 バイト"),
      tlsAppData("0x01a3", 419),
      httpHidden("GET /login HTTP/1.1 / Host: www.example.com / User-Agent: " + UA + " / Accept: text/html")
    ],
    sniff: "192.168.1.10:50432 → 203.0.113.80:443（424 バイト）\n17 03 03 01 a3 8f 2c e1 07 5d … (読めない)\n→ 何かを要求したことは分かるが、どのページかは分からない",
    terms: ["HTTP", "HTTPS", "GETメソッド", "共通鍵暗号"]
  });
  S.push({
    id: "http-get-http",
    stage: "http",
    title: "GET /login：ログインページをください",
    from: "pc", to: "server",
    label: "GET",
    encrypted: false, dropped: false, only: "http", lossOnly: false,
    desc: "いよいよ <b>HTTP</b> の出番です。ブラウザは「/login のページをください」という <b>GET</b> リクエストを、80 番ポートで送ります。" +
      "HTTP（https ではない）なので暗号化はされず、文字がそのまま流れています。" +
      "同じ Wi-Fi にいる人は、あなたがどのサイトのどのページを見ているかを、はがきを読むように読めてしまいます。",
    headers: [
      ipUp(SV_IP, "TCP"),
      tcp("http", "up", "PSH, ACK", 1001, 5001, "402 バイト"),
      { layer: "HTTP", fields: [
        ["リクエスト行", "GET /login HTTP/1.1"],
        ["Host", "www.example.com"],
        ["User-Agent", UA],
        ["Accept", "text/html"]
      ] }
    ],
    sniff: "GET /login HTTP/1.1\nHost: www.example.com\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) …\n→ どのページを見ているか丸見え",
    terms: ["HTTP", "GETメソッド", "盗聴"]
  });

  // --- 200 OK（ログインページ） ---
  S.push({
    id: "http-200-https",
    stage: "http",
    title: "200 OK：ログインページの HTML",
    from: "server", to: "pc",
    label: "200 OK",
    encrypted: true, dropped: false, only: "https", lossOnly: false,
    desc: "サーバーは <b>ステータスコード</b> <code>200 OK</code>（成功）とともに、ログインフォームの HTML を返します。" +
      "これも暗号化されているので、盗聴者にはページの中身は分かりません。" +
      "ブラウザは受け取ったデータを復号して HTML を読み、ID とパスワードの入力欄を画面に表示します。",
    headers: [
      ipDown(SV_IP, "TCP"),
      tcp("https", "down", "PSH, ACK", 7701, 2000, "2332 バイト（実際は 2 セグメント）"),
      tlsAppData("0x0917", 2327),
      httpHidden("HTTP/1.1 200 OK / Content-Type: text/html; charset=UTF-8 / Content-Length: 2048 / <form method=\"post\" action=\"/login\"> …")
    ],
    sniff: "203.0.113.80:443 → 192.168.1.10:50432（2332 バイト）\n17 03 03 09 17 c3 6a 0d f2 48 … (読めない)\n→ 約 2.3 KB のデータを受け取ったことだけ分かる",
    terms: ["ステータスコード", "HTTPS", "共通鍵暗号"]
  });
  S.push({
    id: "http-200-http",
    stage: "http",
    title: "200 OK：ログインページの HTML",
    from: "server", to: "pc",
    label: "200 OK",
    encrypted: false, dropped: false, only: "http", lossOnly: false,
    desc: "サーバーは <b>ステータスコード</b> <code>200 OK</code>（成功）とともに、ログインフォームの HTML を返します。" +
      "ブラウザはこの HTML を読んで、ID とパスワードの入力欄を表示します。" +
      "HTTP なので、ページの中身も平文のまま流れています。途中で書き換えられても気づけない（改ざんの危険）点も問題です。",
    headers: [
      ipDown(SV_IP, "TCP"),
      tcp("http", "down", "PSH, ACK", 5001, 1403, "2310 バイト（実際は 2 セグメント）"),
      { layer: "HTTP", fields: [
        ["ステータス行", "HTTP/1.1 200 OK"],
        ["Content-Type", "text/html; charset=UTF-8"],
        ["Content-Length", "2048"],
        ["本文", "<form method=\"post\" action=\"/login\"> <input name=\"id\"> <input name=\"password\" type=\"password\"> …"]
      ] }
    ],
    sniff: "HTTP/1.1 200 OK\nContent-Type: text/html\n<form method=\"post\" action=\"/login\"> …\n→ ページの中身まで丸見え",
    terms: ["ステータスコード", "HTTP", "盗聴"]
  });

  // --- POST /login ---
  S.push({
    id: "http-post-https",
    stage: "http",
    title: "POST /login：ID とパスワードを送信",
    from: "pc", to: "server",
    label: "POST",
    encrypted: true, dropped: false, only: "https", lossOnly: false,
    desc: "ID（taro）とパスワードを入力して「ログイン」を押すと、ブラウザはフォームの内容を <b>POST</b> リクエストの本文（ボディ）に入れて送ります。" +
      "HTTPS なので、パスワードは暗号化されていて盗聴者には読めません。これが HTTPS を使う一番大きな理由です。" +
      "ただし、どのサーバーと、いつ、どのくらいの量をやりとりしたかは外から分かります。",
    headers: [
      ipUp(SV_IP, "TCP"),
      tcp("https", "up", "PSH, ACK", 2000, 10033, "570 バイト"),
      tlsAppData("0x0235", 565),
      httpHidden("POST /login HTTP/1.1 / Host: www.example.com / Content-Type: application/x-www-form-urlencoded / Content-Length: 28 / 本文: id=taro&password=Passw0rd%21")
    ],
    sniff: "192.168.1.10:50432 → 203.0.113.80:443（570 バイト）\n17 03 03 02 35 8f 2c 4a 9b e3 71 … (読めない)\n→ パスワードは読めない！（でも相手が www.example.com であることは DNS と SNI で分かっている）",
    terms: ["POSTメソッド", "HTTPS", "共通鍵暗号", "盗聴"]
  });
  S.push({
    id: "http-post-http",
    stage: "http",
    title: "POST /login：ID とパスワードを送信",
    from: "pc", to: "server",
    label: "POST",
    encrypted: false, dropped: false, only: "http", lossOnly: false,
    desc: "ID（taro）とパスワードを入力して「ログイン」を押すと、ブラウザはフォームの内容を <b>POST</b> リクエストの本文（ボディ）に入れて送ります。" +
      "POST は URL にデータが出ないので一見安全そうですが、HTTP では本文も<b>暗号化されていません</b>。" +
      "同じ Wi-Fi の盗聴者には、パスワードがそのまま読めてしまいます（<code>%21</code> は「!」を URL エンコードしたもの）。",
    headers: [
      ipUp(SV_IP, "TCP"),
      tcp("http", "up", "PSH, ACK", 1403, 7311, "548 バイト"),
      { layer: "HTTP", fields: [
        ["リクエスト行", "POST /login HTTP/1.1"],
        ["Host", "www.example.com"],
        ["Content-Type", "application/x-www-form-urlencoded"],
        ["Content-Length", "28"],
        ["本文", "id=taro&password=Passw0rd%21"]
      ] }
    ],
    sniff: "POST /login HTTP/1.1\nHost: www.example.com\nContent-Type: application/x-www-form-urlencoded\n\nid=taro&password=Passw0rd%21\n→ ID「taro」とパスワード「Passw0rd!」が丸見え！！",
    terms: ["POSTメソッド", "HTTP", "盗聴"]
  });

  // --- 302 Found + Set-Cookie ---
  S.push({
    id: "http-302-https",
    stage: "http",
    title: "302 Found：ログイン成功、合言葉をどうぞ",
    from: "server", to: "pc",
    label: "302",
    encrypted: true, dropped: false, only: "https", lossOnly: false,
    desc: "ログイン成功。サーバーは <code>302 Found</code>（別の場所へ移動してね）と <code>Location: /mypage</code> で、マイページへ案内します。" +
      "HTTP は 1 回ごとのやりとりが独立していて前回を覚えていないので、<code>Set-Cookie</code> で「ログイン済み」を表す合言葉（セッション ID）をブラウザに預けます。" +
      "<code>Secure</code>（HTTPS のときだけ送る）や <code>HttpOnly</code>（JavaScript から読めない）を付けて、<b>Cookie</b> が盗まれにくくしています。",
    headers: [
      ipDown(SV_IP, "TCP"),
      tcp("https", "down", "PSH, ACK", 10033, 2570, "312 バイト"),
      tlsAppData("0x0133", 307),
      httpHidden("HTTP/1.1 302 Found / Location: /mypage / Set-Cookie: session=8f3a9c2e71b4d605; Path=/; Secure; HttpOnly; SameSite=Lax")
    ],
    sniff: "203.0.113.80:443 → 192.168.1.10:50432（312 バイト）\n17 03 03 01 33 b7 d2 08 6e 1c … (読めない)\n→ Cookie（セッション ID）も読めない",
    terms: ["ステータスコード", "Cookie", "HTTPS"]
  });
  S.push({
    id: "http-302-http",
    stage: "http",
    title: "302 Found：ログイン成功、合言葉をどうぞ",
    from: "server", to: "pc",
    label: "302",
    encrypted: false, dropped: false, only: "http", lossOnly: false,
    desc: "ログイン成功。サーバーは <code>302 Found</code>（別の場所へ移動してね）と <code>Location: /mypage</code> で、マイページへ案内します。" +
      "HTTP は前回のやりとりを覚えていないので、<code>Set-Cookie</code> で「ログイン済み」を表す合言葉（セッション ID）をブラウザに預けます。" +
      "しかし HTTP ではこの <b>Cookie</b> も丸見えで、盗んだ人があなたになりすましてログインできてしまいます（セッションハイジャック）。" +
      "なお、<code>Secure</code> 属性の Cookie は HTTP では使えないので付けられません。",
    headers: [
      ipDown(SV_IP, "TCP"),
      tcp("http", "down", "PSH, ACK", 7311, 1951, "290 バイト"),
      { layer: "HTTP", fields: [
        ["ステータス行", "HTTP/1.1 302 Found"],
        ["Location", "/mypage"],
        ["Set-Cookie", "session=8f3a9c2e71b4d605; Path=/; HttpOnly; SameSite=Lax"]
      ] }
    ],
    sniff: "HTTP/1.1 302 Found\nLocation: /mypage\nSet-Cookie: session=8f3a9c2e71b4d605\n→ セッション ID を盗めば、パスワードなしでなりすませる！",
    terms: ["ステータスコード", "Cookie", "盗聴"]
  });

  // --- GET /mypage（Cookie 付き） ---
  S.push({
    id: "http-mypage-https",
    stage: "http",
    title: "GET /mypage：Cookie を見せて入室",
    from: "pc", to: "server",
    label: "GET",
    encrypted: true, dropped: false, only: "https", lossOnly: false,
    desc: "ブラウザは 302 の指示に従って、自動で <code>/mypage</code> を <b>GET</b> します。" +
      "このとき、さっき預かった <b>Cookie</b>（<code>session=…</code>）を一緒に送るので、サーバーは「さっきログインした taro さんだ」と分かります。" +
      "同じ TCP・TLS の接続を使い回すので、ハンドシェイクのやり直しは不要です。",
    headers: [
      ipUp(SV_IP, "TCP"),
      tcp("https", "up", "PSH, ACK", 2570, 10345, "477 バイト"),
      tlsAppData("0x01d8", 472),
      httpHidden("GET /mypage HTTP/1.1 / Host: www.example.com / Cookie: session=8f3a9c2e71b4d605")
    ],
    sniff: "192.168.1.10:50432 → 203.0.113.80:443（477 バイト）\n17 03 03 01 d8 52 e0 9a 31 7f … (読めない)",
    terms: ["GETメソッド", "Cookie", "HTTPS"]
  });
  S.push({
    id: "http-mypage-http",
    stage: "http",
    title: "GET /mypage：Cookie を見せて入室",
    from: "pc", to: "server",
    label: "GET",
    encrypted: false, dropped: false, only: "http", lossOnly: false,
    desc: "ブラウザは 302 の指示に従って、自動で <code>/mypage</code> を <b>GET</b> します。" +
      "このとき、さっき預かった <b>Cookie</b>（<code>session=…</code>）を一緒に送るので、サーバーは「さっきログインした taro さんだ」と分かります。" +
      "ただし HTTP なので、ページを開くたびにこの Cookie が平文で流れ続けます。",
    headers: [
      ipUp(SV_IP, "TCP"),
      tcp("http", "up", "PSH, ACK", 1951, 7601, "455 バイト"),
      { layer: "HTTP", fields: [
        ["リクエスト行", "GET /mypage HTTP/1.1"],
        ["Host", "www.example.com"],
        ["Cookie", "session=8f3a9c2e71b4d605"]
      ] }
    ],
    sniff: "GET /mypage HTTP/1.1\nHost: www.example.com\nCookie: session=8f3a9c2e71b4d605\n→ ログイン中の合言葉が丸見え",
    terms: ["GETメソッド", "Cookie", "盗聴"]
  });

  // --- 200 OK（マイページ） ---
  S.push({
    id: "http-mypage-200-https",
    stage: "http",
    title: "200 OK：ようこそ taro さん",
    from: "server", to: "pc",
    label: "200 OK",
    encrypted: true, dropped: false, only: "https", lossOnly: false,
    desc: "Cookie で本人と確認できたので、サーバーは <code>200 OK</code> でマイページの HTML を返します。画面に「ようこそ taro さん」と表示され、ログイン完了です。" +
      "ここまでの HTTP のやりとりはすべて暗号化されていたので、盗聴者はパスワードも Cookie もページの中身も読めませんでした。",
    headers: [
      ipDown(SV_IP, "TCP"),
      tcp("https", "down", "PSH, ACK", 10345, 3047, "1842 バイト（実際は 2 セグメント）"),
      tlsAppData("0x072d", 1837),
      httpHidden("HTTP/1.1 200 OK / Content-Type: text/html; charset=UTF-8 / <h1>ようこそ taro さん</h1> …")
    ],
    sniff: "203.0.113.80:443 → 192.168.1.10:50432（1842 バイト）\n17 03 03 07 2d 0b 9e 64 d1 a8 … (読めない)",
    terms: ["ステータスコード", "HTTPS"]
  });
  S.push({
    id: "http-mypage-200-http",
    stage: "http",
    title: "200 OK：ようこそ taro さん",
    from: "server", to: "pc",
    label: "200 OK",
    encrypted: false, dropped: false, only: "http", lossOnly: false,
    desc: "Cookie で本人と確認できたので、サーバーは <code>200 OK</code> でマイページの HTML を返します。画面に「ようこそ taro さん」と表示され、ログイン完了です。" +
      "でも HTTP なので、マイページに表示される個人情報も、盗聴者にはすべて見えています。",
    headers: [
      ipDown(SV_IP, "TCP"),
      tcp("http", "down", "PSH, ACK", 7601, 2406, "1820 バイト（実際は 2 セグメント）"),
      { layer: "HTTP", fields: [
        ["ステータス行", "HTTP/1.1 200 OK"],
        ["Content-Type", "text/html; charset=UTF-8"],
        ["本文", "<h1>ようこそ taro さん</h1> …"]
      ] }
    ],
    sniff: "HTTP/1.1 200 OK\n<h1>ようこそ taro さん</h1> …\n→ マイページの内容も丸見え",
    terms: ["ステータスコード", "HTTP", "盗聴"]
  });

  /* =====================================================
   * ⑤ 切断（FIN / ACK の 4 ウェイ）
   * ===================================================== */
  var CLOSE = {
    https: { c: 3047, s: 12187 },
    http:  { c: 2406, s: 9421 }
  };
  ["https", "http"].forEach(function (mode) {
    var c = CLOSE[mode].c, s = CLOSE[mode].s, p = port(mode);
    S.push({
      id: "close-fin-" + mode,
      stage: "close",
      title: "FIN：もう送るものはありません",
      from: "pc", to: "server",
      label: "FIN",
      encrypted: false, dropped: false, only: mode, lossOnly: false,
      desc: "用事が済んだので、PC は「こちらから送るデータはもうない」という <b>FIN</b> を送ります。" +
        "TCP の切断は、両方向それぞれを閉じるために FIN と ACK を 2 往復させる（4 ウェイ）のが基本です。" +
        (mode === "https" ? "HTTPS の場合は、その前に TLS の <code>close_notify</code>（暗号化通信を終える合図）を送るのが正式な作法です。" :
          "実際のブラウザは、同じサイトをすぐまた開くときに備えて、しばらく接続を開いたままにしておくこともあります。"),
      headers: [
        ipUp(SV_IP, "TCP"),
        tcp(mode, "up", "FIN, ACK", c, s, "0")
      ],
      sniff: "192.168.1.10:50432 → 203.0.113.80:" + p + " [FIN, ACK] seq=" + c + " ack=" + s + "\n→ 通信が終わることが分かる（フラグは暗号化されない）",
      terms: ["FIN", "ACK", "TCP"]
    });
    S.push({
      id: "close-ack-" + mode,
      stage: "close",
      title: "ACK：了解です",
      from: "server", to: "pc",
      label: "ACK",
      encrypted: false, dropped: false, only: mode, lossOnly: false,
      desc: "サーバーは FIN を受け取ったことを <b>ACK</b>（確認応答番号 <code>" + (c + 1) + "</code>）で知らせます。FIN はデータがなくても番号を 1 つ消費するので、相手の seq + 1 になります。" +
        "この時点で「PC → サーバー」方向は閉じましたが、サーバー側にまだ送り残しがあれば送れます。",
      headers: [
        ipDown(SV_IP, "TCP"),
        tcp(mode, "down", "ACK", s, c + 1, "0")
      ],
      sniff: "203.0.113.80:" + p + " → 192.168.1.10:50432 [ACK] seq=" + s + " ack=" + (c + 1),
      terms: ["ACK", "シーケンス番号"]
    });
    S.push({
      id: "close-server-fin-" + mode,
      stage: "close",
      title: "FIN：こちらも終わります",
      from: "server", to: "pc",
      label: "FIN",
      encrypted: false, dropped: false, only: mode, lossOnly: false,
      desc: "サーバーも送るものがなくなったので、自分の側の <b>FIN</b> を送ります。" +
        "片方ずつ閉じるのは、TCP が「行き」と「帰り」の 2 本の通り道でできているからです。",
      headers: [
        ipDown(SV_IP, "TCP"),
        tcp(mode, "down", "FIN, ACK", s, c + 1, "0")
      ],
      sniff: "203.0.113.80:" + p + " → 192.168.1.10:50432 [FIN, ACK] seq=" + s + " ack=" + (c + 1),
      terms: ["FIN", "TCP"]
    });
    S.push({
      id: "close-last-ack-" + mode,
      stage: "close",
      title: "ACK：おつかれさまでした",
      from: "pc", to: "server",
      label: "ACK",
      encrypted: false, dropped: false, only: mode, lossOnly: false,
      desc: "PC が最後の <b>ACK</b>（確認応答番号 <code>" + (s + 1) + "</code>）を返して、接続は完全に閉じられました。" +
        "PC はこのあと少しの間（TIME_WAIT）この組み合わせを使わずに待ち、遅れて届いたパケットが次の接続に混ざらないようにします。" +
        (mode === "https"
          ? "振り返ると、盗聴者に見えたのは DNS の問い合わせ・SNI・IP アドレス・ポート・通信量で、パスワードや Cookie は見えませんでした。"
          : "振り返ると、盗聴者にはページの中身・パスワード・Cookie まで、すべて見えていました。"),
      headers: [
        ipUp(SV_IP, "TCP"),
        tcp(mode, "up", "ACK", c + 1, s + 1, "0")
      ],
      sniff: "192.168.1.10:50432 → 203.0.113.80:" + p + " [ACK] seq=" + (c + 1) + " ack=" + (s + 1) +
        (mode === "https"
          ? "\n【まとめ】見えた：行き先（DNS・SNI）、IP、ポート、時刻、通信量／見えない：URL のパス、パスワード、Cookie、ページ内容"
          : "\n【まとめ】見えた：URL、ページ内容、ID・パスワード、Cookie … ほぼすべて"),
      terms: ["ACK", "盗聴"]
    });
  });

  window.STEPS = S;
})();
