/* =========================================================
   パケットの大冒険 — app.js（エージェント A 担当）
   画面・アニメーション・操作。依存なし、ES2020、module 不使用。
   データは window.STAGES / window.STEPS / window.GLOSSARY（B 担当）を読む。
   ========================================================= */
(function () {
  "use strict";

  /* ---------- フォールバック用ダミーデータ（B のデータが無いときだけ使う） ---------- */
  var FALLBACK_STAGES = [
    { id: "dns", label: "① DNS 名前解決", color: "var(--c-dns)" },
    { id: "tcp", label: "② TCP 接続", color: "var(--c-tcp)" },
    { id: "tls", label: "③ TLS 暗号化", color: "var(--c-tls)" },
    { id: "http", label: "④ HTTP 通信", color: "var(--c-http)" },
    { id: "close", label: "⑤ 切断", color: "var(--c-close)" }
  ];
  var FALLBACK_STEPS = [
    {
      id: "dns-query", stage: "dns", title: "DNS：www.example.com の IP は？",
      from: "pc", to: "dns", label: "DNS?", encrypted: false, dropped: false,
      desc: "（ダミーデータ）ブラウザはまず <b>DNS サーバー</b> に名前の住所（IP アドレス）を問い合わせます。",
      headers: [
        { layer: "IP", fields: [["送信元IP", "192.168.1.10"], ["宛先IP", "198.51.100.53"]] },
        { layer: "UDP", fields: [["送信元ポート", "53124"], ["宛先ポート", "53"]] },
        { layer: "DNS", fields: [["質問", "www.example.com の A レコード"]] }
      ],
      sniff: "DNS 質問：www.example.com はどこ？", terms: ["DNS"]
    },
    {
      id: "tcp-syn-lost", stage: "tcp", title: "SYN が途中で消えた！", lossOnly: true,
      from: "pc", to: "server", label: "SYN", encrypted: false, dropped: true,
      desc: "（ダミーデータ）混雑などでパケットが途中で失われることがあります。返事が来ないので PC はしばらく待ってから<b>再送</b>します。",
      headers: [
        { layer: "IP", fields: [["送信元IP", "192.168.1.10"], ["宛先IP", "203.0.113.80"]] },
        { layer: "TCP", fields: [["宛先ポート", "443"], ["フラグ", "SYN"]] }
      ],
      sniff: "SYN → 203.0.113.80:443", terms: ["SYN"]
    },
    {
      id: "tcp-syn", stage: "tcp", title: "SYN：接続してもいい？",
      from: "pc", to: "server", label: "SYN", encrypted: false, dropped: false,
      desc: "（ダミーデータ）TCP では最初に <b>SYN</b> を送って接続を申し込みます。",
      headers: [
        { layer: "IP", fields: [["送信元IP", "192.168.1.10"], ["宛先IP", "203.0.113.80"]] },
        { layer: "TCP", fields: [["送信元ポート", "50432"], ["宛先ポート", "443"], ["フラグ", "SYN"], ["シーケンス番号", "1000"]] }
      ],
      sniff: "SYN → 203.0.113.80:443", terms: ["SYN"]
    },
    {
      id: "tls-finished", stage: "tls", title: "暗号化の準備完了", only: "https",
      from: "server", to: "pc", label: "TLS", encrypted: true, dropped: false,
      desc: "（ダミーデータ）ここから先の中身は <b>TLS</b> で暗号化されます。",
      headers: [
        { layer: "IP", fields: [["送信元IP", "203.0.113.80"], ["宛先IP", "192.168.1.10"]] },
        { layer: "TCP", fields: [["送信元ポート", "443"], ["宛先ポート", "50432"]] },
        { layer: "TLS", fields: [["種類", "Finished（暗号化済み）"]] }
      ],
      sniff: "暗号化されていて読めない", terms: ["TLS"]
    },
    {
      id: "http-login", stage: "http", title: "ログイン情報を送信",
      from: "pc", to: "server", label: "POST", encrypted: false, dropped: false,
      desc: "（ダミーデータ）ID とパスワードを <code>POST /login</code> で送ります。",
      headers: [
        { layer: "IP", fields: [["送信元IP", "192.168.1.10"], ["宛先IP", "203.0.113.80"]] },
        { layer: "TCP", fields: [["宛先ポート", "80"]] },
        { layer: "HTTP", fields: [["リクエスト", "POST /login"], ["本文", "id=taro&pass=himitsu123"]] }
      ],
      sniff: "POST /login id=taro&pass=himitsu123", terms: ["HTTP"]
    }
  ];
  var FALLBACK_GLOSSARY = {
    DNS: { name: "DNS", reading: "ディーエヌエス", meaning: "（ダミー）ドメイン名を IP アドレスに変換する仕組み。", origin: "Domain Name System の略。", memo: "覚え方：ネットの電話帳。" },
    SYN: { name: "SYN", reading: "シン", meaning: "（ダミー）TCP 接続の開始を申し込むフラグ。", origin: "SYNchronize（同期する）の略。", memo: "覚え方：「しんにちは（こんにちは）」。" },
    TLS: { name: "TLS", reading: "ティーエルエス", meaning: "（ダミー）通信を暗号化する仕組み。", origin: "Transport Layer Security の略。", memo: "覚え方：通信に鍵をかける。" },
    HTTP: { name: "HTTP", reading: "エイチティーティーピー", meaning: "（ダミー）Web ページをやりとりする約束事。", origin: "HyperText Transfer Protocol の略。", memo: "覚え方：Web の会話ルール。" }
  };

  var usingFallback = !Array.isArray(window.STEPS) || window.STEPS.length === 0;
  var STAGES = (Array.isArray(window.STAGES) && window.STAGES.length) ? window.STAGES : FALLBACK_STAGES;
  var ALL_STEPS = usingFallback ? FALLBACK_STEPS : window.STEPS;
  var GLOSSARY = (window.GLOSSARY && typeof window.GLOSSARY === "object") ? window.GLOSSARY : (usingFallback ? FALLBACK_GLOSSARY : {});
  if (usingFallback && window.console) console.info("[packet-adventure] window.STEPS が見つからないため、ダミーデータで動作しています。");

  /* ---------- 定数 ---------- */
  var SVGNS = "http://www.w3.org/2000/svg";
  var BASE_TRAVEL_MS = 1900;      // 1x 時のパケット移動時間
  var BASE_DWELL_MS = 3200;       // 自動再生で次へ進むまでの待ち時間
  var BOOM_MS = 1000;
  var reducedMotionMQ = window.matchMedia ? window.matchMedia("(prefers-reduced-motion: reduce)") : null;
  var narrowMQ = window.matchMedia ? window.matchMedia("(max-width: 640px)") : null;

  var NODE_INFO = {
    pc: { name: "あなたのPC", sub: ["192.168.1.10"] },
    router: { name: "家のルーター", sub: ["LAN 192.168.1.1", "WAN 198.51.100.7"] },
    dns: { name: "DNSサーバー", sub: ["198.51.100.53"] },
    server: { name: "Webサーバー", sub: ["www.example.com", "203.0.113.80"] },
    attacker: { name: "盗聴者", sub: ["公衆Wi-Fiで覗き見"] }
  };
  var NODE_LONG = {
    pc: "あなたのPC", router: "ルーター", dns: "DNSサーバー", server: "Webサーバー", attacker: "盗聴者"
  };
  var EDGES = [["pc", "router"], ["router", "dns"], ["router", "server"]];

  // 図のレイアウト（横長 / 縦長）
  var LAYOUTS = {
    wide: {
      w: 760, h: 380,
      nodes: { pc: [110, 170], router: [340, 170], dns: [628, 82], server: [628, 262] },
      labels: {
        pc: { dx: 0, dy: 50, anchor: "middle" },
        router: { dx: 0, dy: 50, anchor: "middle" },
        dns: { dx: 0, dy: 50, anchor: "middle" },
        server: { dx: 0, dy: 50, anchor: "middle" },
        attacker: { dx: 46, dy: -4, anchor: "start" }
      },
      attacker: [225, 318], tap: [225, 170],
      zones: [
        { cls: "zone-lan", x: 12, y: 24, w: 328, h: 344, label: "家の LAN／公衆 Wi-Fi", lx: 24, ly: 44, lcls: "lan" },
        { cls: "zone-net", x: 340, y: 12, w: 408, h: 356, label: "インターネット", lx: 734, ly: 32, lcls: "net", anchor: "end" }
      ]
    },
    narrow: {
      w: 360, h: 470,
      nodes: { pc: [180, 78], router: [180, 236], dns: [86, 372], server: [274, 372] },
      labels: {
        pc: { dx: 42, dy: -6, anchor: "start" },
        router: { dx: 42, dy: -6, anchor: "start" },
        dns: { dx: 0, dy: 50, anchor: "middle" },
        server: { dx: 0, dy: 50, anchor: "middle" },
        attacker: { dx: 0, dy: 44, anchor: "middle" }
      },
      attacker: [62, 150], tap: [180, 150],
      zones: [
        { cls: "zone-lan", x: 6, y: 6, w: 348, h: 230, label: "LAN／公衆 Wi-Fi", lx: 16, ly: 24, lcls: "lan" },
        { cls: "zone-net", x: 6, y: 236, w: 348, h: 228, label: "インターネット", lx: 16, ly: 256, lcls: "net" }
      ]
    }
  };

  /* ---------- 状態 ---------- */
  var state = {
    proto: "https",
    sniff: false,
    loss: false,
    speed: 1,
    playing: false,
    seq: [],
    pos: 0,            // 0..seq.length（seq.length は「まとめ」）
    layoutKey: "wide"
  };
  var anim = { token: 0, raf: 0, timers: [] };
  var playTimer = 0;
  var garbleTimer = 0;
  var svgRefs = {};

  /* ---------- ユーティリティ ---------- */
  function $(id) { return document.getElementById(id); }
  function el(tag, attrs, text) {
    var e = document.createElement(tag);
    if (attrs) for (var k in attrs) {
      if (k === "class") e.className = attrs[k];
      else if (k === "html") e.innerHTML = attrs[k];
      else e.setAttribute(k, attrs[k]);
    }
    if (text != null) e.textContent = text;
    return e;
  }
  function svg(tag, attrs, text) {
    var e = document.createElementNS(SVGNS, tag);
    if (attrs) for (var k in attrs) e.setAttribute(k, attrs[k]);
    if (text != null) e.textContent = text;
    return e;
  }
  function stageById(id) {
    for (var i = 0; i < STAGES.length; i++) if (STAGES[i].id === id) return STAGES[i];
    return null;
  }
  function stageIndex(id) {
    for (var i = 0; i < STAGES.length; i++) if (STAGES[i].id === id) return i;
    return -1;
  }
  function stageColor(id) {
    var s = stageById(id);
    return (s && s.color) || ("var(--c-" + id + ", var(--accent))");
  }
  function reducedMotion() { return !!(reducedMotionMQ && reducedMotionMQ.matches); }
  function hash(str) {
    var h = 2166136261;
    for (var i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = Math.imul(h, 16777619); }
    return h >>> 0;
  }
  function garble(seed, len) {
    var chars = "▓▒░#%&@$*+=?§¤¶ΞΨЖЯ0123456789abcdefｱｶｻﾀﾅ";
    var h = hash(String(seed)) || 1;
    var out = "";
    for (var i = 0; i < len; i++) {
      h ^= h << 13; h >>>= 0; h ^= h >>> 17; h ^= h << 5; h >>>= 0;
      out += (i > 0 && i % 6 === 0) ? " " : chars.charAt(h % chars.length);
    }
    return out;
  }
  function clearTimers() {
    anim.timers.forEach(function (t) { clearTimeout(t); });
    anim.timers = [];
  }
  function later(fn, ms) { var t = setTimeout(fn, ms); anim.timers.push(t); return t; }

  /* ---------- 表示ステップ列 ---------- */
  function computeSeq() {
    return ALL_STEPS.filter(function (s) {
      if (s.only && s.only !== state.proto) return false;
      if (s.lossOnly && !state.loss) return false;
      return true;
    });
  }
  function current() { return state.pos < state.seq.length ? state.seq[state.pos] : null; }
  function isSummary() { return state.pos >= state.seq.length; }

  function rebuildSeq() {
    var cur = current();
    var wasSummary = isSummary() && state.seq.length > 0;
    var oldPos = state.pos, oldLen = state.seq.length;
    state.seq = computeSeq();
    if (wasSummary) { state.pos = state.seq.length; return; }
    if (!cur) { state.pos = 0; return; }
    var idx = indexWhere(function (s) { return s.id === cur.id; });
    if (idx < 0) {
      // HTTP/HTTPS 切替：id 末尾の -https / -http を入れ替えた「対応するステップ」を優先
      var base = String(cur.id).replace(/-https?$/, "");
      if (base !== cur.id) idx = indexWhere(function (s) { return String(s.id).replace(/-https?$/, "") === base; });
    }
    if (idx < 0) idx = indexWhere(function (s) { return s.stage === cur.stage; });
    if (idx < 0) {
      // 同じステージが無い（例：HTTP では TLS が無い）→ ステージ順で一番近いもの。同距離なら先のステージ
      var target = stageIndex(cur.stage);
      var best = -1, bestD = 1e9;
      state.seq.forEach(function (s, i) {
        var d = Math.abs(stageIndex(s.stage) - target);
        if (stageIndex(s.stage) < target) d += 0.5;
        if (d < bestD) { bestD = d; best = i; }
      });
      idx = best >= 0 ? best : Math.round(oldPos / Math.max(1, oldLen) * state.seq.length);
    }
    state.pos = Math.max(0, Math.min(idx, state.seq.length));
  }
  function indexWhere(fn) {
    for (var i = 0; i < state.seq.length; i++) if (fn(state.seq[i])) return i;
    return -1;
  }

  /* ---------- 経路計算 ---------- */
  var ADJ = {};
  EDGES.forEach(function (e) {
    (ADJ[e[0]] = ADJ[e[0]] || []).push(e[1]);
    (ADJ[e[1]] = ADJ[e[1]] || []).push(e[0]);
  });
  function routeNodes(from, to) {
    if (!ADJ[from] || !ADJ[to]) return [from, to].filter(function (n) { return !!ADJ[n]; });
    if (from === to) return [from];
    var prev = {}; prev[from] = null;
    var q = [from];
    while (q.length) {
      var n = q.shift();
      if (n === to) break;
      (ADJ[n] || []).forEach(function (m) { if (!(m in prev)) { prev[m] = n; q.push(m); } });
    }
    if (!(to in prev)) return [from, to];
    var path = [];
    for (var c = to; c != null; c = prev[c]) path.unshift(c);
    return path;
  }
  function edgeKey(a, b) { return a < b ? a + "-" + b : b + "-" + a; }

  /* ---------- SVG 構築 ---------- */
  function iconFor(type) {
    var g = svg("g", { "class": "node-icon" });
    if (type === "pc") {
      g.appendChild(svg("rect", { "class": "stroke", x: -19, y: -16, width: 38, height: 26, rx: 3 }));
      g.appendChild(svg("rect", { "class": "screen", x: -15.5, y: -12.5, width: 31, height: 19, rx: 1.5 }));
      g.appendChild(svg("path", { "class": "stroke", d: "M-5 10 L-7 17 M5 10 L7 17 M-11 17 H11" }));
      g.appendChild(svg("path", { "class": "stroke", d: "M-9 -6 h10 M-9 -1 h16", style: "stroke-width:2;opacity:.6" }));
    } else if (type === "router") {
      g.appendChild(svg("path", { "class": "stroke", d: "M-12 -4 L-16 -18 M12 -4 L16 -18" }));
      g.appendChild(svg("rect", { "class": "stroke", x: -22, y: -4, width: 44, height: 16, rx: 5 }));
      g.appendChild(svg("circle", { "class": "led", cx: -13, cy: 4, r: 2.2 }));
      g.appendChild(svg("circle", { "class": "led", cx: -6, cy: 4, r: 2.2 }));
      g.appendChild(svg("circle", { "class": "led", cx: 1, cy: 4, r: 2.2 }));
      g.appendChild(svg("path", { "class": "stroke", d: "M-6 -14 a8 8 0 0 1 12 0 M-3 -10 a4 4 0 0 1 6 0", style: "stroke-width:2" }));
    } else if (type === "dns") {
      g.appendChild(svg("path", { "class": "stroke", d: "M-16 -12 V12 a16 5 0 0 0 32 0 V-12" }));
      g.appendChild(svg("ellipse", { "class": "stroke", cx: 0, cy: -12, rx: 16, ry: 5 }));
      g.appendChild(svg("path", { "class": "stroke", d: "M-16 0 a16 5 0 0 0 32 0", style: "stroke-width:1.6;opacity:.6" }));
      g.appendChild(svg("text", { x: 0, y: 9, "text-anchor": "middle", "class": "fill", style: "font-size:9px;font-weight:800;letter-spacing:.5px" }, "DNS"));
    } else if (type === "server") {
      for (var i = 0; i < 3; i++) {
        var y = -18 + i * 12.5;
        g.appendChild(svg("rect", { "class": "stroke", x: -16, y: y, width: 32, height: 10, rx: 2.5 }));
        g.appendChild(svg("circle", { "class": "led", cx: -10, cy: y + 5, r: 1.8 }));
        g.appendChild(svg("path", { "class": "stroke", d: "M0 " + (y + 5) + " h10", style: "stroke-width:1.6;opacity:.6" }));
      }
    } else if (type === "attacker") {
      g.appendChild(svg("path", { "class": "stroke", d: "M-16 16 C-16 2 -10 -4 0 -4 C10 -4 16 2 16 16" }));
      g.appendChild(svg("path", { "class": "stroke", d: "M-13 -6 C-13 -24 13 -24 13 -6" }));
      g.appendChild(svg("rect", { "class": "fill", x: -10, y: -13, width: 8, height: 5, rx: 2 }));
      g.appendChild(svg("rect", { "class": "fill", x: 2, y: -13, width: 8, height: 5, rx: 2 }));
      g.appendChild(svg("path", { "class": "stroke", d: "M-2 -11 h4", style: "stroke-width:1.6" }));
    }
    return g;
  }

  function buildDiagram() {
    var L = LAYOUTS[state.layoutKey];
    var root = $("net");
    // title/desc は残して中身を作り直す
    Array.prototype.slice.call(root.childNodes).forEach(function (n) {
      if (n.nodeName !== "title" && n.nodeName !== "desc") root.removeChild(n);
    });
    root.setAttribute("viewBox", "0 0 " + L.w + " " + L.h);

    var defs = svg("defs");
    var pat = svg("pattern", { id: "stripes", width: 8, height: 8, patternUnits: "userSpaceOnUse", patternTransform: "rotate(45)" });
    pat.appendChild(svg("rect", { width: 4, height: 8, fill: "rgba(255,255,255,.28)" }));
    defs.appendChild(pat);
    root.appendChild(defs);

    var gz = svg("g", { "class": "zones" });
    L.zones.forEach(function (z) {
      gz.appendChild(svg("rect", { "class": "zone " + z.cls, x: z.x, y: z.y, width: z.w, height: z.h, rx: 18 }));
      gz.appendChild(svg("text", { "class": "zone-label " + z.lcls, x: z.lx, y: z.ly, "text-anchor": z.anchor || "start" }, z.label));
    });
    root.appendChild(gz);

    // 盗聴者（リンクより下に描いてタップ線をリンクの下に）
    var ga = svg("g", { "class": "attacker", "aria-hidden": "true" });
    ga.appendChild(svg("line", { "class": "tap", x1: L.tap[0], y1: L.tap[1], x2: L.attacker[0], y2: L.attacker[1] }));
    root.appendChild(ga);

    var gl = svg("g", { "class": "links" });
    svgRefs.links = {};
    EDGES.forEach(function (e) {
      var a = L.nodes[e[0]], b = L.nodes[e[1]];
      var line = svg("line", { "class": "link", x1: a[0], y1: a[1], x2: b[0], y2: b[1] });
      var flow = svg("line", { "class": "link-flow", x1: a[0], y1: a[1], x2: b[0], y2: b[1] });
      gl.appendChild(line); gl.appendChild(flow);
      svgRefs.links[edgeKey(e[0], e[1])] = { line: line, flow: flow, a: e[0], b: e[1] };
    });
    root.appendChild(gl);

    // 盗聴者の本体（タップ点はリンクの上）
    var gaTop = svg("g", { "class": "attacker attacker-top", "aria-hidden": "true" });
    gaTop.appendChild(svg("circle", { "class": "tap-dot", cx: L.tap[0], cy: L.tap[1], r: 4.5 }));
    var ag = svg("g", { transform: "translate(" + L.attacker[0] + "," + L.attacker[1] + ")" });
    var ring = svg("circle", { "class": "eye-ring", r: 30, cx: 0, cy: 0 });
    ring.style.transformBox = "fill-box"; ring.style.transformOrigin = "center";
    ag.appendChild(ring);
    ag.appendChild(svg("circle", { "class": "node-disc", r: 30 }));
    ag.appendChild(iconFor("attacker"));
    appendLabel(ag, "attacker", L.labels.attacker);
    gaTop.appendChild(ag);
    svgRefs.attackerParts = [ga, gaTop];

    var gn = svg("g", { "class": "nodes" });
    svgRefs.nodes = {};
    Object.keys(L.nodes).forEach(function (id) {
      var p = L.nodes[id];
      var g = svg("g", { "class": "node node-" + id, transform: "translate(" + p[0] + "," + p[1] + ")" });
      g.appendChild(svg("circle", { "class": "node-disc", r: 34 }));
      g.appendChild(iconFor(id));
      appendLabel(g, id, L.labels[id]);
      gn.appendChild(g);
      svgRefs.nodes[id] = g;
    });
    root.appendChild(gn);
    root.appendChild(gaTop);

    svgRefs.fx = svg("g", { "class": "fx" });
    root.appendChild(svgRefs.fx);
    svgRefs.packetLayer = svg("g", { "class": "packets" });
    root.appendChild(svgRefs.packetLayer);
    applySniffVisibility();
  }

  function appendLabel(g, id, pos) {
    var info = NODE_INFO[id];
    var t = svg("text", { "class": "node-name halo", x: pos.dx, y: pos.dy, "text-anchor": pos.anchor }, info.name);
    g.appendChild(t);
    info.sub.forEach(function (s, i) {
      g.appendChild(svg("text", { "class": "node-sub halo", x: pos.dx, y: pos.dy + 15 + i * 13.5, "text-anchor": pos.anchor }, s));
    });
  }

  function applySniffVisibility() {
    (svgRefs.attackerParts || []).forEach(function (g) { g.style.display = state.sniff ? "" : "none"; });
  }

  /* ---------- パケット ---------- */
  function makePacket(step) {
    var color = stageColor(step.stage);
    var g = svg("g", { "class": "packet" });
    var body = svg("rect", { "class": "packet-body", rx: 8, ry: 8, height: 28, y: -14 });
    body.style.fill = color;
    g.appendChild(body);
    var stripes = null;
    if (step.encrypted) {
      stripes = svg("rect", { rx: 8, ry: 8, height: 28, y: -14, fill: "url(#stripes)" });
      g.appendChild(stripes);
    }
    var label = String(step.label || "");
    var text = svg("text", { "class": "packet-label", x: 0, y: 4.5, "text-anchor": "middle" }, label);
    g.appendChild(text);
    var lock = null;
    if (step.encrypted) {
      lock = svg("text", { "class": "packet-lock", y: 4.5, "text-anchor": "middle" }, "🔒");
      g.appendChild(lock);
    }
    svgRefs.packetLayer.appendChild(g);
    // 幅をテキストに合わせる
    var tw = 0;
    try { tw = text.getComputedTextLength(); } catch (e) { tw = 0; }
    if (!tw) tw = label.length * 9;
    var lockW = step.encrypted ? 18 : 0;
    var w = Math.max(44, tw + 20 + lockW);
    [body, stripes].forEach(function (r) { if (r) { r.setAttribute("x", -w / 2); r.setAttribute("width", w); } });
    if (lock) {
      lock.setAttribute("x", -w / 2 + 14);
      text.setAttribute("x", lockW / 2);
    }
    return g;
  }

  function polyline(nodes) {
    var L = LAYOUTS[state.layoutKey];
    var pts = nodes.map(function (n) { return L.nodes[n]; });
    var segs = [], total = 0;
    for (var i = 0; i < pts.length - 1; i++) {
      var dx = pts[i + 1][0] - pts[i][0], dy = pts[i + 1][1] - pts[i][1];
      var len = Math.sqrt(dx * dx + dy * dy);
      segs.push({ a: pts[i], b: pts[i + 1], len: len, start: total, na: nodes[i], nb: nodes[i + 1] });
      total += len;
    }
    return { pts: pts, segs: segs, total: total };
  }
  function pointAt(poly, d) {
    if (!poly.segs.length) return { x: poly.pts[0][0], y: poly.pts[0][1], seg: null };
    for (var i = 0; i < poly.segs.length; i++) {
      var s = poly.segs[i];
      if (d <= s.start + s.len || i === poly.segs.length - 1) {
        var t = s.len ? Math.max(0, Math.min(1, (d - s.start) / s.len)) : 0;
        return { x: s.a[0] + (s.b[0] - s.a[0]) * t, y: s.a[1] + (s.b[1] - s.a[1]) * t, seg: s };
      }
    }
  }
  function dropDistance(poly, nodes) {
    var ri = nodes.indexOf("router");
    if (ri > 0 && ri < nodes.length - 1) {
      var after = poly.segs[ri];
      return after.start + after.len * 0.35;
    }
    return poly.total * 0.55;
  }
  function ease(t) { return t < .5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2; }

  function setPeeking(on) {
    if (!svgRefs.attackerParts) return;
    svgRefs.attackerParts[1].classList.toggle("is-peeking", !!on && state.sniff);
  }

  function clearDiagramState() {
    anim.token++;
    cancelAnimationFrame(anim.raf);
    clearTimers();
    if (svgRefs.packetLayer) svgRefs.packetLayer.textContent = "";
    if (svgRefs.fx) svgRefs.fx.textContent = "";
    Object.keys(svgRefs.links || {}).forEach(function (k) {
      var l = svgRefs.links[k];
      l.line.classList.remove("is-active");
      l.line.style.stroke = "";
      l.flow.style.stroke = "";
    });
    Object.keys(svgRefs.nodes || {}).forEach(function (k) {
      var n = svgRefs.nodes[k];
      n.classList.remove("is-endpoint");
      n.querySelector(".node-disc").style.stroke = "";
    });
    setPeeking(false);
  }

  function playStep(step, opts) {
    opts = opts || {};
    clearDiagramState();
    var token = anim.token;
    var nodes = routeNodes(step.from, step.to);
    var poly = polyline(nodes);
    var color = stageColor(step.stage);

    // 経路とエンドポイントの強調
    for (var i = 0; i < nodes.length - 1; i++) {
      var lk = svgRefs.links[edgeKey(nodes[i], nodes[i + 1])];
      if (lk) { lk.line.classList.add("is-active"); lk.line.style.stroke = color; }
    }
    [step.from, step.to].forEach(function (n) {
      var g = svgRefs.nodes[n];
      if (g) { g.classList.add("is-endpoint"); g.querySelector(".node-disc").style.stroke = color; }
    });

    var pkt = makePacket(step);
    var dropAt = step.dropped ? dropDistance(poly, nodes) : poly.total;
    var rm = reducedMotion();
    var travel = rm ? 250 : BASE_TRAVEL_MS / state.speed;
    if (step.dropped) travel *= dropAt / Math.max(1, poly.total);
    var start = null;

    function place(d) {
      var p = pointAt(poly, d);
      pkt.setAttribute("transform", "translate(" + p.x.toFixed(1) + "," + p.y.toFixed(1) + ")");
      var onTap = p.seg && edgeKey(p.seg.na, p.seg.nb) === "pc-router";
      setPeeking(onTap);
    }
    place(0);

    function frame(now) {
      if (token !== anim.token) return;
      if (start == null) start = now;
      var t = Math.min(1, (now - start) / travel);
      var e = step.dropped ? t : ease(t);
      place(e * dropAt);
      if (t < 1) { anim.raf = requestAnimationFrame(frame); return; }
      setPeeking(false);
      if (step.dropped) explode(pkt, pointAt(poly, dropAt), token, opts.onDone);
      else {
        pkt.classList.add("is-rest");
        if (opts.onDone) opts.onDone();
      }
    }
    anim.raf = requestAnimationFrame(frame);
  }

  function explode(pkt, p, token, onDone) {
    var rm = reducedMotion();
    var boomMs = rm ? 200 : BOOM_MS / Math.max(0.75, state.speed);
    pkt.style.transition = "opacity " + Math.round(boomMs * 0.3) + "ms";
    pkt.style.opacity = "0";
    var boom = svg("text", { "class": "boom" + (rm ? "" : " boom-anim"), x: p.x, y: p.y + 12, "text-anchor": "middle" }, "💥");
    boom.style.animationDuration = boomMs + "ms";
    svgRefs.fx.appendChild(boom);
    later(function () {
      if (token !== anim.token) return;
      if (pkt.parentNode) pkt.parentNode.removeChild(pkt);
      if (boom.parentNode) boom.parentNode.removeChild(boom);
      // 消えた場所に小さな × を残す
      var g = svg("g", { "class": "lost", transform: "translate(" + p.x.toFixed(1) + "," + p.y.toFixed(1) + ")" });
      g.appendChild(svg("path", { "class": "lost-x", d: "M-7 -7 L7 7 M7 -7 L-7 7" }));
      g.appendChild(svg("text", { "class": "lost-mark halo", x: 0, y: 26, "text-anchor": "middle" }, "ロスト"));
      svgRefs.fx.appendChild(g);
      if (onDone) onDone();
    }, boomMs);
  }

  function showFinishedDiagram() {
    clearDiagramState();
    var L = LAYOUTS[state.layoutKey];
    var g = svg("g", { "class": "done" });
    var wide = state.layoutKey === "wide";
    g.appendChild(svg("text", { "class": "done-banner halo", x: wide ? L.nodes.server[0] : L.w / 2, y: wide ? L.h - 14 : 300, "text-anchor": "middle" }, "🎉 ログイン完了！"));
    svgRefs.fx.appendChild(g);
    var sg = svgRefs.nodes.server; if (sg) { sg.classList.add("is-endpoint"); sg.querySelector(".node-disc").style.stroke = "var(--c-http)"; }
    var pg = svgRefs.nodes.pc; if (pg) { pg.classList.add("is-endpoint"); pg.querySelector(".node-disc").style.stroke = "var(--c-http)"; }
  }

  /* ---------- 描画（パネル類） ---------- */
  function renderAddress() {
    var bar = $("addressbar");
    var https = state.proto === "https";
    bar.classList.toggle("is-http", !https);
    $("addrIcon").textContent = https ? "🔒" : "⚠";
    var url = $("addrUrl");
    url.textContent = "";
    url.appendChild(el("span", { "class": https ? "scheme-https" : "scheme-http" }, https ? "https" : "http"));
    url.appendChild(document.createTextNode("://"));
    url.appendChild(el("span", { "class": "host" }, "www.example.com"));
    url.appendChild(el("span", { "class": "path" }, "/login"));
    $("addrBadge").textContent = https ? "保護された通信" : "保護されていない通信";
    bar.setAttribute("aria-label", "アドレスバー：" + (https ? "保護された通信 https://www.example.com/login" : "保護されていない通信 http://www.example.com/login"));
  }

  function renderStagebar() {
    var bar = $("stagebar");
    bar.textContent = "";
    var cur = current();
    var curIdx = cur ? stageIndex(cur.stage) : STAGES.length;
    STAGES.forEach(function (st, i) {
      var count = state.seq.filter(function (s) { return s.stage === st.id; }).length;
      var b = el("button", { type: "button", "class": "stage-btn" });
      b.style.setProperty("--sc", st.color || stageColor(st.id));
      if (i === curIdx) { b.classList.add("is-current"); b.setAttribute("aria-current", "step"); }
      else if (i < curIdx) b.classList.add("is-done");
      b.disabled = count === 0;
      b.setAttribute("aria-label", st.label + "（" + count + " ステップ）へ移動");
      b.appendChild(el("span", { "class": "stage-label" }, st.label));
      b.appendChild(el("span", { "class": "stage-count", "aria-hidden": "true" }, String(count)));
      var fill = el("span", { "class": "stage-fill", "aria-hidden": "true" });
      if (i === curIdx && cur) {
        var inStage = state.seq.filter(function (s) { return s.stage === st.id; });
        var k = inStage.indexOf(cur);
        fill.style.width = ((k + 1) / inStage.length * 100) + "%";
      }
      b.appendChild(fill);
      b.addEventListener("click", function () {
        var idx = indexWhere(function (s) { return s.stage === st.id; });
        if (idx >= 0) goTo(idx, { user: true });
      });
      bar.appendChild(b);
    });
  }

  function renderControls() {
    var n = state.seq.length;
    var slider = $("slider");
    slider.max = String(n + 1);
    slider.value = String(state.pos + 1);
    var pct = n > 0 ? (state.pos / n * 100) : 0;
    slider.style.setProperty("--pct", pct + "%");
    var txt = isSummary() ? "まとめ" : (state.pos + 1) + " / " + n;
    $("stepCount").textContent = txt;
    slider.setAttribute("aria-valuetext", isSummary() ? "まとめ" : "ステップ " + (state.pos + 1) + " / " + n);
    $("btnFirst").disabled = state.pos === 0;
    $("btnPrev").disabled = state.pos === 0;
    $("btnNext").disabled = isSummary();
    $("playIcon").textContent = state.playing ? "⏸" : "▶";
    $("playText").textContent = state.playing ? "停止" : "再生";
    $("btnPlay").setAttribute("aria-label", state.playing ? "一時停止（Spaceキー）" : "自動再生（Spaceキー）");
    $("btnPlay").setAttribute("aria-pressed", state.playing ? "true" : "false");
  }

  function renderToggles() {
    setToggle("tglProto", state.proto === "https");
    $("protoText").textContent = state.proto === "https" ? "🔒 HTTPS" : "🔓 HTTP";
    $("tglProto").setAttribute("aria-label", state.proto === "https" ? "プロトコル：HTTPS（押すと HTTP に切替）" : "プロトコル：HTTP（押すと HTTPS に切替）");
    setToggle("tglSniff", state.sniff);
    setToggle("tglLoss", state.loss);
    document.querySelectorAll(".seg").forEach(function (b) {
      b.setAttribute("aria-checked", Number(b.getAttribute("data-speed")) === state.speed ? "true" : "false");
      b.tabIndex = Number(b.getAttribute("data-speed")) === state.speed ? 0 : -1;
    });
  }
  function setToggle(id, on) {
    var b = $(id);
    b.classList.toggle("is-on", on);
    b.setAttribute("aria-pressed", on ? "true" : "false");
  }

  function renderExplain(step) {
    var n = state.seq.length;
    $("stepNo").textContent = (state.pos + 1) + " / " + n;
    var st = stageById(step.stage);
    var pill = $("stagePill");
    pill.textContent = st ? st.label : step.stage;
    pill.style.setProperty("--sc", stageColor(step.stage));
    var flag = $("flagPill");
    flag.className = "flag-pill";
    if (step.dropped) { flag.hidden = false; flag.textContent = "💥 パケットロス"; flag.classList.add("is-warn"); }
    else if (step.encrypted) { flag.hidden = false; flag.textContent = "🔒 暗号化"; flag.classList.add("is-safe"); }
    else if (state.proto === "http" && step.stage === "http") { flag.hidden = false; flag.textContent = "⚠ 平文"; flag.classList.add("is-danger"); }
    else flag.hidden = true;
    $("stepTitle").textContent = step.title || "";
    $("stepDesc").innerHTML = step.desc || "";
    var terms = $("terms");
    terms.textContent = "";
    (step.terms || []).forEach(function (key) {
      var t = GLOSSARY[key];
      var chip = el("button", { type: "button", "class": "term-chip" + (t ? "" : " is-missing") }, (t && t.name) || key);
      if (t) {
        chip.setAttribute("aria-label", "用語「" + (t.name || key) + "」の解説を開く");
        chip.addEventListener("click", function () { openTerm(key); });
      } else {
        chip.disabled = true;
        chip.setAttribute("aria-label", "用語「" + key + "」（用語集に未登録）");
      }
      terms.appendChild(chip);
    });
  }

  var LAYER_TAGS = [
    [/ethernet|イーサ|mac|wi-?fi/i, "--l-eth", "L2 データリンク"],
    [/^ip|ipv4|ipv6/i, "--l-ip", "L3 ネットワーク"],
    [/tcp|udp/i, "--l-l4", "L4 トランスポート"],
    [/tls|ssl/i, "--l-tls", "TLS セキュリティ層"],
    [/http|dns|html|アプリ/i, "--l-app", "L7 アプリケーション"]
  ];
  function layerMeta(name) {
    for (var i = 0; i < LAYER_TAGS.length; i++) if (LAYER_TAGS[i][0].test(name)) return { color: "var(" + LAYER_TAGS[i][1] + ")", tag: LAYER_TAGS[i][2], kind: LAYER_TAGS[i][1] };
    return { color: "var(--l-other)", tag: "", kind: "--l-other" };
  }

  function renderLayers(step) {
    var box = $("layers");
    box.textContent = "";
    var hs = step.headers || [];
    if (!hs.length) { box.appendChild(el("p", { "class": "layers-empty" }, "このステップのパケット情報はありません。")); return; }
    var tlsSeen = false;
    hs.forEach(function (h, i) {
      var meta = layerMeta(String(h.layer || ""));
      if (meta.kind === "--l-tls") tlsSeen = true;
      var card = el("div", { "class": "layer" });
      card.style.setProperty("--lc", meta.color);
      card.style.marginLeft = Math.min(i * 6, 24) + "px";
      card.style.animationDelay = (reducedMotion() ? 0 : i * 60) + "ms";
      var head = el("div", { "class": "layer-head" });
      head.appendChild(el("span", { "class": "layer-name" }, h.layer));
      if (meta.tag) head.appendChild(el("span", { "class": "layer-tag" }, meta.tag));
      var sealed = step.encrypted && meta.kind === "--l-app" && tlsSeen;
      if (sealed) {
        card.classList.add("is-sealed");
        head.appendChild(el("span", { "class": "layer-seal" }, "🔒 TLS の中＝外からは読めない"));
      }
      card.appendChild(head);
      var dl = el("dl", { "class": "layer-fields" });
      (h.fields || []).forEach(function (f) {
        dl.appendChild(el("dt", null, f[0]));
        dl.appendChild(el("dd", null, f[1]));
      });
      card.appendChild(dl);
      box.appendChild(card);
    });
  }

  var HEX_RE = /(?:[0-9a-f]{2} ){3,}[0-9a-f]{2}(?: …)?/gi;
  function renderSniff(step) {
    var card = $("sniffCard");
    clearInterval(garbleTimer);
    if (!state.sniff || !step) { card.hidden = true; return; }
    card.hidden = false;
    var enc = !!step.encrypted;
    card.classList.toggle("is-encrypted", enc);
    var text = $("sniffText");
    text.textContent = "";
    var src = step.sniff || "（このステップで見えるものはありません）";
    if (!enc) { text.textContent = src; return; }
    // 暗号化ステップ：16進の暗号文部分だけを文字化け風に。IP・ポート・バイト数などはそのまま見せる
    var ciphers = [];
    var last = 0, m;
    HEX_RE.lastIndex = 0;
    while ((m = HEX_RE.exec(src))) {
      if (m.index > last) text.appendChild(document.createTextNode(src.slice(last, m.index)));
      var span = el("span", { "class": "cipher", title: "暗号文（鍵がないと読めない）" }, m[0]);
      span.setAttribute("data-final", m[0]);
      text.appendChild(span);
      ciphers.push(span);
      last = m.index + m[0].length;
    }
    if (last < src.length) text.appendChild(document.createTextNode(src.slice(last)));
    if (!ciphers.length || reducedMotion()) return;
    var n = 0;
    function scramble() {
      ciphers.forEach(function (c, i) {
        var fin = c.getAttribute("data-final");
        var g = garble(step.id + ":" + i + ":" + n, fin.length);
        // 空白位置は保つ
        var out = "";
        for (var k = 0; k < fin.length; k++) out += fin.charAt(k) === " " ? " " : g.charAt(k) === " " ? "▒" : g.charAt(k);
        c.textContent = out;
      });
    }
    scramble();
    garbleTimer = setInterval(function () {
      n++;
      if (n > 14) {
        clearInterval(garbleTimer);
        ciphers.forEach(function (c) { c.textContent = c.getAttribute("data-final"); });
        return;
      }
      scramble();
    }, 70);
  }

  function renderRouteText(step) {
    var nodes = routeNodes(step.from, step.to);
    var rt = $("routeText");
    rt.textContent = "";
    var lbl = el("b", null, step.label || "パケット");
    rt.appendChild(lbl);
    rt.appendChild(document.createTextNode("：" + nodes.map(function (n) { return NODE_LONG[n] || n; }).join(" → ")));
    if (step.dropped) rt.appendChild(document.createTextNode("（途中で消失💥）"));
  }

  // B の最終ステップの sniff に含まれる「【まとめ】…」をモード別に取り出す
  function matomeFor(proto) {
    for (var i = ALL_STEPS.length - 1; i >= 0; i--) {
      var st = ALL_STEPS[i];
      if (st.only && st.only !== proto) continue;
      var m = /【まとめ】\s*([^\n]+)/.exec(st.sniff || "");
      if (m) return m[1];
    }
    return "";
  }
  function renderSummary() {
    var card = $("summaryCard");
    card.textContent = "";
    var https = state.proto === "https";
    card.appendChild(el("h2", { id: "summaryHead" }, "🎉 まとめ：URL 入力からログインまで"));
    card.appendChild(el("p", { "class": "summary-lead" },
      "今回は " + (https ? "HTTPS" : "HTTP") + " で、全 " + state.seq.length + " ステップの旅をしました。" +
      (state.loss ? "パケットロスが起きても、TCP が再送して届けてくれました。" : "")));
    var ul = el("ul", { "class": "stage-recap" });
    STAGES.forEach(function (st) {
      var c = state.seq.filter(function (s) { return s.stage === st.id; }).length;
      if (!c) return;
      var li = el("li", null, st.label + "　" + c + " ステップ");
      li.style.setProperty("--sc", st.color || stageColor(st.id));
      ul.appendChild(li);
    });
    card.appendChild(ul);

    card.appendChild(el("h3", null, "HTTP と HTTPS のちがい"));
    var wrap = el("div", { "class": "compare-wrap" });
    var table = el("table", { "class": "compare" });
    var thead = el("thead");
    var hr = el("tr");
    hr.appendChild(el("th", { scope: "col" }, ""));
    var thH = el("th", { scope: "col" }, "🔓 HTTP");
    var thS = el("th", { scope: "col" }, "🔒 HTTPS");
    (https ? thS : thH).classList.add("is-current-mode");
    hr.appendChild(thH); hr.appendChild(thS);
    thead.appendChild(hr); table.appendChild(thead);
    var rows = [
      ["中身（パスワードなど）", ["そのまま（平文）で流れる", "bad"], ["TLS で暗号化され読めない", "good"]],
      ["途中での書き換え", ["気づけない", "bad"], ["改ざんを検知できる", "good"]],
      ["相手が本物か", ["確かめない", "bad"], ["証明書で確認する", "good"]],
      ["盗聴者に見えるもの", [matomeFor("http") || "URL・ID・パスワードまで全部", "bad"], [matomeFor("https") || "接続先の IP・ドメイン名・通信量くらい", "good"]],
      ["アドレスバー", ["⚠ 保護されていない通信", "bad"], ["🔒 鍵マーク", "good"]]
    ];
    var tb = el("tbody");
    rows.forEach(function (r) {
      var tr = el("tr");
      tr.appendChild(el("th", { scope: "row" }, r[0]));
      tr.appendChild(el("td", { "class": r[1][1] }, r[1][0]));
      tr.appendChild(el("td", { "class": r[2][1] }, r[2][0]));
      tb.appendChild(tr);
    });
    table.appendChild(tb);
    wrap.appendChild(table);
    card.appendChild(wrap);

    card.appendChild(el("h3", null, "👀 盗聴者に見えたもの（" + (https ? "HTTPS" : "HTTP") + "）"));
    var list = el("ul", { "class": "seen-list" });
    state.seq.forEach(function (s) {
      if (!s.sniff) return;
      var li = el("li", { "class": s.encrypted ? "is-enc" : "is-plain" });
      li.appendChild(el("span", { "class": "seen-step" }, s.title));
      var what = s.sniff.split("\n").filter(function (l) { return l.indexOf("【まとめ】") < 0; }).join("\n");
      if (!what) return;
      li.appendChild(el("span", { "class": "seen-what" }, (s.encrypted ? "🔒 " : "") + what));
      list.appendChild(li);
    });
    card.appendChild(list);

    var actions = el("div", { "class": "summary-actions" });
    var again = el("button", { type: "button", "class": "btn btn-primary" }, "⏮ もう一度最初から");
    again.addEventListener("click", function () { goTo(0, { user: true }); });
    var swap = el("button", { type: "button", "class": "btn" }, https ? "🔓 HTTP でも試して比べる" : "🔒 HTTPS でも試して比べる");
    swap.addEventListener("click", function () { setProto(https ? "http" : "https"); goTo(0, { user: true }); });
    actions.appendChild(again); actions.appendChild(swap);
    if (!state.sniff) {
      var sn = el("button", { type: "button", "class": "btn" }, "👀 盗聴者モードで見直す");
      sn.addEventListener("click", function () { state.sniff = true; renderToggles(); applySniffVisibility(); goTo(0, { user: true }); });
      actions.appendChild(sn);
    }
    card.appendChild(actions);
  }

  /* ---------- 全体描画 ---------- */
  function render(opts) {
    opts = opts || {};
    renderAddress();
    renderStagebar();
    renderControls();
    renderToggles();
    applySniffVisibility();
    var step = current();
    var summary = !step;
    $("explain").hidden = summary;
    $("packetCard").hidden = summary;
    $("summaryCard").hidden = !summary;
    $("btnReplay").hidden = summary;
    if (summary) {
      renderSummary();
      renderSniff(null);
      $("routeText").textContent = state.seq.length ? "すべてのステップが終わりました。" : "表示できるステップがありません。";
      showFinishedDiagram();
      if (opts.onDone) opts.onDone();
      return;
    }
    renderExplain(step);
    renderLayers(step);
    renderSniff(step);
    renderRouteText(step);
    if (opts.animate !== false) playStep(step, { onDone: opts.onDone });
  }

  /* ---------- ナビゲーション ---------- */
  function goTo(idx, opts) {
    opts = opts || {};
    if (opts.user && state.playing) stopPlay();
    state.pos = Math.max(0, Math.min(idx, state.seq.length));
    render({ onDone: state.playing ? scheduleNext : null });
  }
  function next(opts) { if (!isSummary()) goTo(state.pos + 1, opts); }
  function prev(opts) { if (state.pos > 0) goTo(state.pos - 1, opts); }

  function scheduleNext() {
    clearTimeout(playTimer);
    if (!state.playing) return;
    if (isSummary()) { stopPlay(); return; }
    var dwell = reducedMotion() ? BASE_DWELL_MS : BASE_DWELL_MS / state.speed;
    playTimer = setTimeout(function () {
      if (!state.playing) return;
      next();
    }, dwell);
  }
  function startPlay() {
    state.playing = true;
    if (isSummary()) { goTo(0); return; }
    renderControls();
    // 今のステップをもう一度流してから次へ
    render({ onDone: scheduleNext });
  }
  function stopPlay() {
    state.playing = false;
    clearTimeout(playTimer);
    renderControls();
  }
  function togglePlay() { if (state.playing) stopPlay(); else startPlay(); }

  function setProto(p) {
    if (state.proto === p) return;
    state.proto = p;
    rebuildSeq();
  }
  function afterToggle() {
    render({ onDone: state.playing ? scheduleNext : null });
  }

  /* ---------- 用語集ダイアログ ---------- */
  var lastFocus = null;
  var pointerFocused = null;
  function openTerm(key) {
    var dlg = $("termDialog");
    var body = $("termBody");
    body.textContent = "";
    var keys = Object.keys(GLOSSARY);
    if (!key && keys.length) key = keys[0];
    var t = key ? GLOSSARY[key] : null;
    if (t) {
      body.appendChild(el("h2", { "class": "term-title", id: "termName" }, t.name || key));
      if (t.reading) body.appendChild(el("p", { "class": "term-reading" }, "読み：" + t.reading));
      var dl = el("dl");
      [["意味", t.meaning, ""], ["由来", t.origin, ""], ["覚え方", t.memo, "term-memo"]].forEach(function (r) {
        if (!r[1]) return;
        var d = el("div", { "class": "term-sec " + r[2] });
        d.appendChild(el("dt", null, r[0]));
        d.appendChild(el("dd", null, r[1]));
        dl.appendChild(d);
      });
      body.appendChild(dl);
    } else {
      body.appendChild(el("h2", { "class": "term-title", id: "termName" }, "用語集"));
      body.appendChild(el("p", null, "用語がまだ登録されていません。"));
    }
    var idx = $("termIndex");
    idx.textContent = "";
    keys.forEach(function (k) {
      var c = el("button", { type: "button", "class": "term-chip" + (k === key ? " is-current" : "") }, GLOSSARY[k].name || k);
      c.addEventListener("click", function () { openTerm(k); var b = $("termIndex").querySelector(".is-current"); if (b) b.focus(); });
      idx.appendChild(c);
    });
    if (!dlg.open) {
      lastFocus = document.activeElement;
      if (state.playing) stopPlay();
      if (typeof dlg.showModal === "function") dlg.showModal(); else dlg.setAttribute("open", "");
      $("termClose").focus();
    }
  }
  function closeTerm() {
    var dlg = $("termDialog");
    if (typeof dlg.close === "function") dlg.close(); else dlg.removeAttribute("open");
  }

  /* ---------- イベント ---------- */
  function bind() {
    $("btnFirst").addEventListener("click", function () { goTo(0, { user: true }); });
    $("btnPrev").addEventListener("click", function () { prev({ user: true }); });
    $("btnNext").addEventListener("click", function () { next({ user: true }); });
    $("btnPlay").addEventListener("click", togglePlay);
    $("btnReplay").addEventListener("click", function () { var s = current(); if (s) playStep(s, { onDone: state.playing ? scheduleNext : null }); });
    $("slider").addEventListener("input", function (e) { goTo(Number(e.target.value) - 1, { user: true }); });

    document.querySelectorAll(".seg").forEach(function (b) {
      b.addEventListener("click", function () { state.speed = Number(b.getAttribute("data-speed")); renderToggles(); });
      b.addEventListener("keydown", function (e) {
        if (e.key !== "ArrowLeft" && e.key !== "ArrowRight") return;
        e.preventDefault(); e.stopPropagation();
        var segs = Array.prototype.slice.call(document.querySelectorAll(".seg"));
        var i = segs.indexOf(b) + (e.key === "ArrowRight" ? 1 : -1);
        i = Math.max(0, Math.min(segs.length - 1, i));
        segs[i].click(); segs[i].focus();
      });
    });

    $("tglProto").addEventListener("click", function () { setProto(state.proto === "https" ? "http" : "https"); afterToggle(); });
    $("tglSniff").addEventListener("click", function () { state.sniff = !state.sniff; afterToggle(); });
    $("tglLoss").addEventListener("click", function () { state.loss = !state.loss; rebuildSeq(); afterToggle(); });

    $("glossaryBtn").addEventListener("click", function () { openTerm(null); });
    $("termClose").addEventListener("click", closeTerm);
    var dlg = $("termDialog");
    dlg.addEventListener("click", function (e) { if (e.target === dlg) closeTerm(); });
    dlg.addEventListener("close", function () { if (lastFocus && lastFocus.focus) lastFocus.focus(); });

    // マウス/タッチでフォーカスされた要素を記録（Space の扱いを分けるため）
    var pointerDownAt = 0;
    document.addEventListener("pointerdown", function () { pointerDownAt = Date.now(); }, true);
    document.addEventListener("focusin", function (e) {
      pointerFocused = (Date.now() - pointerDownAt < 150) ? e.target : null;
    });
    document.addEventListener("keydown", function (e) {
      if (e.defaultPrevented || e.altKey || e.ctrlKey || e.metaKey) return;
      if ($("termDialog").open) return;
      var t = e.target;
      var tag = t && t.tagName ? t.tagName.toLowerCase() : "";
      if (tag === "input" || tag === "select" || tag === "textarea" || (t && t.isContentEditable)) return;
      if (e.key === "ArrowRight") { e.preventDefault(); next({ user: true }); }
      else if (e.key === "ArrowLeft") { e.preventDefault(); prev({ user: true }); }
      else if (e.key === " " || e.key === "Spacebar") {
        // キーボードでボタンにフォーカスしているときはボタン本来の動作（押下）を優先。
        // マウスで押した直後のボタンに残ったフォーカスでは再生/停止を優先する。
        if (tag === "button" || tag === "a" || tag === "summary") {
          if (t !== pointerFocused) return;
          t.blur();
        }
        e.preventDefault();
        togglePlay();
      }
    });

    if (narrowMQ) {
      var onLayout = function () {
        var key = narrowMQ.matches ? "narrow" : "wide";
        if (key === state.layoutKey) return;
        state.layoutKey = key;
        buildDiagram();
        var s = current();
        if (s) playStep(s, { onDone: state.playing ? scheduleNext : null });
        else showFinishedDiagram();
      };
      if (narrowMQ.addEventListener) narrowMQ.addEventListener("change", onLayout);
      else if (narrowMQ.addListener) narrowMQ.addListener(onLayout);
    }
    document.addEventListener("visibilitychange", function () { if (document.hidden && state.playing) stopPlay(); });
  }

  /* ---------- 起動 ---------- */
  function init() {
    state.layoutKey = narrowMQ && narrowMQ.matches ? "narrow" : "wide";
    state.seq = computeSeq();
    state.pos = 0;
    buildDiagram();
    bind();
    render();
    // テスト・デバッグ用に最小限の状態を公開
    window.PacketAdventure = {
      state: state,
      goTo: function (i) { goTo(i, { user: true }); },
      usingFallback: usingFallback
    };
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
