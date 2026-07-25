// CardVault webapp — losstaand bestand zodat de CSP geen inline script hoeft toe te staan.
(function () {
  "use strict";

  var CHUNK_SIZE = 1900;
  var COLORS = ["blue","green","orange","purple","red","dkblue","pink","dkgreen","yellow","dkred"];
  var COLOR_HEX = {
    blue:"#1e90ff", red:"#ff3b30", green:"#34c759", orange:"#ff9500", purple:"#af52de",
    pink:"#ff2d92", yellow:"#ffd60a", dkblue:"#0a3d91", dkgreen:"#1b6b2f", dkred:"#8a1c1c",
    ltgray:"#c8c8c8", dkgray:"#3a3a3a", white:"#ffffff"
  };
  var PICK_COLORS = ["blue","green","orange","purple","red","pink","yellow","dkblue","dkgreen","dkgray"];

  var cards = [];
  var colorCursor = 0;

  var ICON = {
    ok: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg>',
    err: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="M15 9l-6 6M9 9l6 6"/></svg>',
    info: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="M12 8v4M12 16h.01"/></svg>',
    trash: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/></svg>'
  };

  // ---------- toast ----------
  var toastEl = document.getElementById("toast");
  var toastTimer = null;
  function toast(msg, kind) {
    kind = kind || "info";
    toastEl.className = "show " + kind;
    document.getElementById("toast-ico").innerHTML = ICON[kind] || ICON.info;
    document.getElementById("toast-msg").textContent = msg;
    if (toastTimer) { clearTimeout(toastTimer); }
    toastTimer = setTimeout(function () { toastEl.className = ""; }, 4200);
  }

  // ---------- tabs ----------
  var tabs = document.querySelectorAll(".tab");
  tabs.forEach(function (t) {
    t.addEventListener("click", function () {
      tabs.forEach(function (x) { x.classList.remove("active"); });
      document.querySelectorAll(".tabpane").forEach(function (p) { p.classList.remove("active"); });
      t.classList.add("active");
      document.getElementById("pane-" + t.dataset.tab).classList.add("active");
      if (t.dataset.tab !== "scan") { stopScan(); }
    });
  });

  // ---------- base32 / protobuf / otpauth ----------
  function base32Encode(bytes) {
    var alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    var bits = 0, value = 0, out = "";
    for (var i = 0; i < bytes.length; i++) {
      value = (value << 8) | bytes[i]; bits += 8;
      while (bits >= 5) { out += alphabet[(value >>> (bits - 5)) & 31]; bits -= 5; }
    }
    if (bits > 0) { out += alphabet[(value << (5 - bits)) & 31]; }
    return out;
  }
  function base64ToBytes(b64) {
    var bin = atob(b64); var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) { out[i] = bin.charCodeAt(i); }
    return out;
  }
  function readVarint(bytes, i) {
    var result = 0, shift = 0, b;
    do { b = bytes[i++]; result |= (b & 0x7f) << shift; shift += 7; } while (b & 0x80);
    return [result >>> 0, i];
  }
  function skipField(bytes, i, wire) {
    if (wire === 0) { return readVarint(bytes, i)[1]; }
    if (wire === 2) { var r = readVarint(bytes, i); return r[1] + r[0]; }
    if (wire === 5) { return i + 4; }
    if (wire === 1) { return i + 8; }
    return bytes.length;
  }
  function utf8(bytes) { try { return new TextDecoder("utf-8").decode(bytes); } catch (e) { return ""; } }
  function parseOtpParams(msg) {
    var i = 0, secret = null, name = "", issuer = "", digits = 6, type = 2, algo = 1;
    while (i < msg.length) {
      var tag = msg[i++]; var field = tag >> 3, wire = tag & 7;
      if (field === 1 && wire === 2) { var r = readVarint(msg, i); i = r[1]; secret = msg.slice(i, i + r[0]); i += r[0]; }
      else if (field === 2 && wire === 2) { var r2 = readVarint(msg, i); i = r2[1]; name = utf8(msg.slice(i, i + r2[0])); i += r2[0]; }
      else if (field === 3 && wire === 2) { var r3 = readVarint(msg, i); i = r3[1]; issuer = utf8(msg.slice(i, i + r3[0])); i += r3[0]; }
      else if (field === 4 && wire === 0) { var r4 = readVarint(msg, i); algo = r4[0]; i = r4[1]; }
      else if (field === 5 && wire === 0) { var r5 = readVarint(msg, i); digits = (r5[0] === 2) ? 8 : 6; i = r5[1]; }
      else if (field === 6 && wire === 0) { var r6 = readVarint(msg, i); type = r6[0]; i = r6[1]; }
      else { i = skipField(msg, i, wire); }
    }
    return { secret: secret, name: name, issuer: issuer, digits: digits, type: type, algo: algo };
  }
  var ALGO_NAMES = { 1: "SHA1", 2: "SHA256", 3: "SHA512" };
  function parseMigration(uri) {
    var m = uri.match(/[?&]data=([^&]+)/);
    if (!m) { throw new Error("geen data in migration-QR"); }
    var bytes = base64ToBytes(decodeURIComponent(m[1]));
    var i = 0, added = 0;
    while (i < bytes.length) {
      var tag = bytes[i++]; var field = tag >> 3, wire = tag & 7;
      if (field === 1 && wire === 2) {
        var r = readVarint(bytes, i); i = r[1];
        var sub = bytes.slice(i, i + r[0]); i += r[0];
        var p = parseOtpParams(sub);
        if (p.type === 2 && p.secret) {
          addTotp(p.issuer || p.name, p.name, base32Encode(p.secret), ALGO_NAMES[p.algo] || "SHA1", p.digits, 30);
          added++;
        }
      } else { i = skipField(bytes, i, wire); }
    }
    if (added === 0) { throw new Error("geen TOTP-accounts gevonden"); }
    return added;
  }
  function parseOtpAuth(text) {
    var url = new URL(text);
    if (url.protocol !== "otpauth:") { throw new Error("geen otpauth:// URI"); }
    if (url.host.toLowerCase() !== "totp") { throw new Error("alleen TOTP wordt ondersteund"); }
    var label = decodeURIComponent(url.pathname.replace(/^\//, ""));
    var params = url.searchParams;
    var secret = params.get("secret");
    if (!secret) { throw new Error("geen secret in QR"); }
    var issuer = params.get("issuer") || "";
    var algo = (params.get("algorithm") || "SHA1").toUpperCase();
    var digits = parseInt(params.get("digits") || "6", 10);
    var period = parseInt(params.get("period") || "30", 10);
    var account = label;
    if (label.indexOf(":") !== -1) { var parts = label.split(":"); if (!issuer) { issuer = parts[0]; } account = parts.slice(1).join(":"); }
    if (!issuer) { issuer = label; }
    addTotp(issuer, account, secret, algo, digits, period);
  }

  // ---------- toevoegers ----------
  function nextColor() { var c = COLORS[colorCursor % COLORS.length]; colorCursor++; return c; }
  function isDuplicate(type, data) { return cards.some(function (c) { return c.type === type && c.data === data; }); }
  function addTotp(issuer, account, secret, algo, digits, period) {
    if (isDuplicate("totp", secret)) { return false; }
    cards.push({ type: "totp", name: issuer || "2FA", sub: account || "", color: "dkgray", icon: "lock", data: secret, extra: algo + ":" + digits + ":" + period, category: "2FA" });
    render(); return true;
  }
  function addBarcode(name, number, fmt) {
    if (isDuplicate("barcode", number)) { return false; }
    cards.push({ type: "barcode", name: name || "Card", sub: "", color: nextColor(), icon: "card", data: number, extra: fmt, category: "Overig" });
    render(); return true;
  }
  function addQr(name, data) {
    if (isDuplicate("qr", data)) { return false; }
    if (data.length > 230) { toast("QR text too long (max ~230 chars)", "err"); return false; }
    cards.push({ type: "qr", name: name || "QR", sub: "", color: nextColor(), icon: "ticket", data: data, extra: "QR", category: "Overig" });
    render(); return true;
  }

  // ---------- scanner ----------
  var video = document.getElementById("video");
  var startBtn = document.getElementById("startBtn");
  var stopBtn = document.getElementById("stopBtn");
  var reader = null;

  function barcodeFormatName(fmtEnum) {
    var BF = ZXing.BarcodeFormat;
    if (fmtEnum === BF.QR_CODE) { return "QR"; }
    if (fmtEnum === BF.EAN_13) { return "EAN13"; }
    return "CODE128";
  }
  // Inhoud van een QR-code verwerken (2FA / migration / vrije QR).
  function handleQrText(text) {
    try {
      if (/^otpauth-migration:\/\//i.test(text)) { var n = parseMigration(text); toast(n + " 2FA account(s) imported", "ok"); }
      else if (/^otpauth:\/\//i.test(text)) { parseOtpAuth(text); toast("2FA code added", "ok"); }
      else { var q = addQr("QR " + (cards.length + 1), text); toast(q ? "QR code added" : "Already added or too long", q ? "ok" : "info"); }
    } catch (e) { toast("Could not process: " + e.message, "err"); }
  }
  function handleResult(text, fmtEnum) {
    var BF = ZXing.BarcodeFormat;
    if (fmtEnum === BF.QR_CODE) {
      handleQrText(text);
    } else {
      var fmt = barcodeFormatName(fmtEnum);
      var added = addBarcode("Card " + (cards.length + 1), text, fmt);
      toast(added ? ("Barcode added (" + fmt + ")") : "Already added", added ? "ok" : "info");
    }
  }
  function startScan() {
    if (typeof ZXing === "undefined") { toast("Scanner not loaded (internet needed)", "err"); return; }
    reader = new ZXing.BrowserMultiFormatReader();
    reader.decodeFromVideoDevice(null, video, function (result) {
      if (result) { handleResult(result.getText(), result.getBarcodeFormat()); }
    }).then(function () {
      video.classList.remove("hidden");
      startBtn.classList.add("hidden");
      stopBtn.classList.remove("hidden");
      toast("Point at a QR or barcode", "info");
    }).catch(function (e) { toast("Could not open camera: " + e.message, "err"); });
  }
  function stopScan() {
    if (reader) { reader.reset(); reader = null; }
    video.classList.add("hidden");
    startBtn.classList.remove("hidden");
    stopBtn.classList.add("hidden");
  }
  startBtn.addEventListener("click", startScan);
  stopBtn.addEventListener("click", stopScan);

  // ---------- upload ----------
  var dropzone = document.getElementById("dropzone");
  var fileInput = document.getElementById("fileInput");
  function decodeImageFile(file) {
    if (!file || !/^image\//.test(file.type)) { toast("Not a valid image", "err"); return; }
    toast("Scanning image...", "info");
    var fileUrl = URL.createObjectURL(file);
    var img = new Image();
    img.onload = function () {
      // 1) QR-codes: jsQR op de pixeldata (betrouwbaar voor screenshots/foto's).
      var scales = [1400, 800, 2000];
      for (var s = 0; s < scales.length; s++) {
        var text = tryJsQR(img, scales[s]);
        if (text) { URL.revokeObjectURL(fileUrl); handleQrText(text); return; }
      }
      // 2) Barcodes: Quagga2 (speciaal voor 1D-barcodes uit foto's).
      tryQuagga(fileUrl, function (ok) {
        URL.revokeObjectURL(fileUrl);
        if (!ok) { toast("No QR or barcode found. Take a straight, sharp close-up photo.", "err"); }
      });
    };
    img.onerror = function () { URL.revokeObjectURL(fileUrl); toast("Could not load the image", "err"); };
    img.src = fileUrl;
  }

  // Quagga2 leest 1D-barcodes uit een afbeelding-URL. Callback(true) bij succes.
  function tryQuagga(src, done) {
    if (typeof Quagga === "undefined") { done(false); return; }
    Quagga.decodeSingle({
      src: src,
      numOfWorkers: 0,
      locate: true,
      inputStream: { size: 1600 },
      decoder: {
        readers: ["ean_reader", "ean_8_reader", "upc_reader", "upc_e_reader",
                  "code_128_reader", "code_39_reader", "i2of5_reader", "codabar_reader"]
      }
    }, function (result) {
      if (result && result.codeResult && result.codeResult.code) {
        var code = result.codeResult.code;
        // Formaat op basis van de code: 13 cijfers -> EAN13, anders CODE128
        // (het horloge ondersteunt die twee; CODE128 dekt al het overige).
        var fmt = /^\d{13}$/.test(code) ? "EAN13" : "CODE128";
        var added = addBarcode("Card " + (cards.length + 1), code, fmt);
        toast(added ? ("Barcode added (" + fmt + ")") : "Already added", added ? "ok" : "info");
        done(true);
      } else {
        done(false);
      }
    });
  }

  function drawToCanvas(img, maxDim) {
    var scale = Math.min(1, maxDim / Math.max(img.width, img.height));
    var canvas = document.createElement("canvas");
    canvas.width = Math.max(1, Math.round(img.width * scale));
    canvas.height = Math.max(1, Math.round(img.height * scale));
    var ctx = canvas.getContext("2d");
    ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
    return canvas;
  }

  function tryJsQR(img, maxDim) {
    if (typeof jsQR === "undefined") { return null; }
    try {
      var canvas = drawToCanvas(img, maxDim);
      var ctx = canvas.getContext("2d");
      var data = ctx.getImageData(0, 0, canvas.width, canvas.height);
      var res = jsQR(data.data, canvas.width, canvas.height, { inversionAttempts: "attemptBoth" });
      return (res && res.data) ? res.data : null;
    } catch (e) { return null; }
  }

  dropzone.addEventListener("click", function () { fileInput.click(); });
  fileInput.addEventListener("change", function (e) { if (e.target.files[0]) { decodeImageFile(e.target.files[0]); e.target.value = ""; } });
  ["dragenter","dragover"].forEach(function (ev) { dropzone.addEventListener(ev, function (e) { e.preventDefault(); dropzone.classList.add("drag"); }); });
  ["dragleave","drop"].forEach(function (ev) { dropzone.addEventListener(ev, function (e) { e.preventDefault(); dropzone.classList.remove("drag"); }); });
  dropzone.addEventListener("drop", function (e) { if (e.dataTransfer.files[0]) { decodeImageFile(e.dataTransfer.files[0]); } });

  // ---------- wallet render ----------
  var walletEl = document.getElementById("wallet");
  var emptyEl = document.getElementById("emptyHint");
  var countEl = document.getElementById("cardCount");

  function escapePipe(s) { return String(s).replace(/\|/g, "\\|"); }
  function cardLine(c) {
    return [c.type, escapePipe(c.name), escapePipe(c.sub), c.color, c.icon, escapePipe(c.data), c.extra, c.category].join("|");
  }
  function typeLabel(t) { return t === "totp" ? "2FA" : (t === "qr" ? "QR" : "PAS"); }
  function shade(hex, f) {
    var r = parseInt(hex.slice(1,3),16), g = parseInt(hex.slice(3,5),16), b = parseInt(hex.slice(5,7),16);
    r = Math.round(r*f); g = Math.round(g*f); b = Math.round(b*f);
    return "rgb(" + r + "," + g + "," + b + ")";
  }
  function luma(hex) {
    var r = parseInt(hex.slice(1,3),16), g = parseInt(hex.slice(3,5),16), b = parseInt(hex.slice(5,7),16);
    return (r*299 + g*587 + b*114) / 1000;
  }

  function render() {
    countEl.textContent = cards.length + (cards.length === 1 ? " card" : " cards");
    emptyEl.style.display = cards.length ? "none" : "block";
    walletEl.innerHTML = "";

    cards.forEach(function (c, idx) {
      var hex = COLOR_HEX[c.color] || "#555";
      var txtColor = luma(hex) > 150 ? "#111418" : "#ffffff";

      var wrap = document.createElement("div");
      wrap.className = "wcard-wrap";

      var card = document.createElement("div");
      card.className = "wcard";
      card.style.background = "linear-gradient(135deg, " + hex + " 0%, " + shade(hex, 0.55) + " 100%)";
      card.style.color = txtColor;

      var top = document.createElement("div");
      top.className = "wcard-top";
      var chip = document.createElement("span"); chip.className = "wchip";
      var tag = document.createElement("span"); tag.className = "wtype"; tag.textContent = typeLabel(c.type);
      top.appendChild(chip); top.appendChild(tag);
      card.appendChild(top);

      var spacer = document.createElement("div"); spacer.className = "spacer";
      card.appendChild(spacer);

      var nameInput = document.createElement("input");
      nameInput.className = "wname"; nameInput.value = c.name; nameInput.placeholder = "Name";
      nameInput.style.color = txtColor;
      nameInput.addEventListener("input", function () { c.name = nameInput.value; buildOutput(); });
      card.appendChild(nameInput);

      var subInput = document.createElement("input");
      subInput.className = "wsub"; subInput.value = c.sub || ""; subInput.placeholder = "Subtitle";
      subInput.style.color = txtColor;
      subInput.addEventListener("input", function () { c.sub = subInput.value; buildOutput(); });
      card.appendChild(subInput);

      var data = document.createElement("div");
      data.className = "wdata";
      data.textContent = (c.type === "totp") ? c.extra : c.data;
      card.appendChild(data);

      wrap.appendChild(card);

      // toolbar: kleurstippen + verwijderen
      var tools = document.createElement("div");
      tools.className = "wtools";
      PICK_COLORS.forEach(function (col) {
        var dot = document.createElement("span");
        dot.className = "dot" + (col === c.color ? " sel" : "");
        dot.style.background = COLOR_HEX[col];
        dot.title = col;
        dot.addEventListener("click", function () { c.color = col; render(); });
        tools.appendChild(dot);
      });
      var del = document.createElement("button");
      del.className = "del"; del.title = "Verwijderen"; del.innerHTML = ICON.trash;
      del.addEventListener("click", function () {
        var pos = cards.indexOf(c);   // verwijder exact deze kaart, niet op index
        if (pos !== -1) { cards.splice(pos, 1); render(); }
      });
      tools.appendChild(del);
      wrap.appendChild(tools);

      walletEl.appendChild(wrap);
    });
    buildOutput();
  }

  // ---------- output ----------
  var outputsEl = document.getElementById("outputs");
  function buildOutput() {
    var lines = cards.map(cardLine);
    var chunks = [""];
    lines.forEach(function (line) {
      var last = chunks[chunks.length - 1];
      var candidate = last.length ? (last + "\n" + line) : line;
      if (candidate.length > CHUNK_SIZE && last.length) { chunks.push(line); }
      else { chunks[chunks.length - 1] = candidate; }
    });
    outputsEl.innerHTML = "";
    chunks.forEach(function (chunk, i) {
      var block = document.createElement("div"); block.className = "output-block";
      var lbl = document.createElement("label"); lbl.style.marginTop = "0";
      lbl.textContent = "Cards (" + (i + 1) + "/4)";
      block.appendChild(lbl);
      var ta = document.createElement("textarea"); ta.readOnly = true; ta.value = chunk;
      block.appendChild(ta);
      outputsEl.appendChild(block);
    });
  }

  // ---------- restore ----------
  function splitEscaped(text, sep) {
    var ph = ""; var protectedText = text.split("\\" + sep).join(ph);
    return protectedText.split(sep).map(function (p) { return p.split(ph).join(sep).trim(); });
  }
  function restore(text) {
    var lines = text.split("\n"); var n = 0;
    lines.forEach(function (raw) {
      var line = raw.trim(); if (!line) { return; }
      var f = splitEscaped(line, "|"); if (f.length < 6) { return; }
      var type = f[0].toLowerCase();
      var card = {
        type: type, name: f[1], sub: f[2], color: f[3] || (type === "totp" ? "dkgray" : "blue"),
        icon: f[4] || (type === "totp" ? "lock" : "card"), data: f[5],
        extra: f[6] || (type === "totp" ? "SHA1:6:30" : (type === "qr" ? "QR" : "CODE128")),
        category: f[7] || (type === "totp" ? "2FA" : "Overig")
      };
      if (!isDuplicate(card.type, card.data)) { cards.push(card); n++; }
    });
    render();
    toast(n + " card(s) loaded", n ? "ok" : "err");
  }

  // ---------- events ----------
  document.getElementById("manualOtpBtn").addEventListener("click", function () {
    var el = document.getElementById("manualOtp");
    var t = el.value.trim(); if (!t) { return; }
    try {
      if (/^otpauth-migration:/i.test(t)) { var n = parseMigration(t); toast(n + " account(s) added", "ok"); }
      else { parseOtpAuth(t); toast("2FA code added", "ok"); }
      el.value = "";
    } catch (e) { toast("Error: " + e.message, "err"); }
  });
  document.getElementById("manualBcBtn").addEventListener("click", function () {
    var num = document.getElementById("bcNum").value.trim(); if (!num) { return; }
    var fmt = /^\d{13}$/.test(num) ? "EAN13" : "CODE128";
    addBarcode(document.getElementById("bcName").value.trim() || "Card", num, fmt);
    document.getElementById("bcNum").value = ""; document.getElementById("bcName").value = "";
    toast("Barcode added", "ok");
  });
  document.getElementById("manualQrBtn").addEventListener("click", function () {
    var d = document.getElementById("qrData").value.trim(); if (!d) { return; }
    if (addQr(document.getElementById("qrName").value.trim() || "QR", d)) {
      document.getElementById("qrData").value = ""; document.getElementById("qrName").value = "";
      toast("QR added", "ok");
    }
  });
  document.getElementById("restoreBtn").addEventListener("click", function () {
    var el = document.getElementById("restoreIn");
    var t = el.value.trim(); if (t) { restore(t); el.value = ""; }
  });
  document.getElementById("copyBtn").addEventListener("click", function () {
    var all = cards.map(cardLine).join("\n");
    navigator.clipboard.writeText(all).then(
      function () { toast("Copied — for multiple blocks, paste each field separately", "ok"); },
      function () { toast("Could not copy, select manually", "err"); }
    );
  });
  // ---------- koppelen ----------
  // De code van het horloge is eenmalig en 10 minuten geldig. Hij wordt hier
  // ingeruild voor een lange push-sleutel; die blijft in deze browser staan,
  // zodat je daarna alleen nog op Send hoeft te drukken.
  var CODE_RE = /^[A-HJ-NP-Z2-9]{6}$/;   // alfabet zonder I, O, 0 en 1
  var KEY_RE = /^[A-HJ-NP-Z2-9]{26}$/;

  var pairInput = document.getElementById("pairCode");
  var pairRow = document.getElementById("pairRow");
  var pairedRow = document.getElementById("pairedRow");

  var pushKey = "";
  try {
    pushKey = localStorage.getItem("cv_key") || "";
    localStorage.removeItem("cv_pair"); // rest van de oude, korte koppelcode
  } catch (e) {}
  if (!KEY_RE.test(pushKey)) { pushKey = ""; }

  function showPaired(on) {
    pairRow.style.display = on ? "none" : "flex";
    pairedRow.style.display = on ? "flex" : "none";
  }
  function forgetPairing() {
    pushKey = "";
    try { localStorage.removeItem("cv_key"); } catch (e) {}
    showPaired(false);
  }
  showPaired(pushKey !== "");

  document.getElementById("pairBtn").addEventListener("click", function () {
    var code = (pairInput.value || "").trim().toUpperCase();
    if (!CODE_RE.test(code)) { toast("Enter the 6-character code from your watch", "err"); return; }
    toast("Connecting...", "info");
    fetch("/api/claim", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code: code })
    })
      .then(function (r) { return r.json().then(function (j) { return { status: r.status, body: j }; }); })
      .then(function (res) {
        if (res.status === 200 && KEY_RE.test(res.body.key || "")) {
          pushKey = res.body.key;
          try { localStorage.setItem("cv_key", pushKey); } catch (e) {}
          pairInput.value = "";
          showPaired(true);
          toast("Watch connected — press Send", "ok");
        } else if (res.status === 429) {
          toast("Too many attempts — wait a moment", "err");
        } else {
          toast("Code unknown or expired — get a fresh one on your watch", "err");
        }
      })
      .catch(function (e) { toast("Could not connect: " + e.message, "err"); });
  });

  document.getElementById("unpairBtn").addEventListener("click", function () {
    forgetPairing();
    toast("Disconnected", "info");
  });

  document.getElementById("sendBtn").addEventListener("click", function () {
    if (!KEY_RE.test(pushKey)) { forgetPairing(); toast("Connect your watch first", "err"); return; }
    if (cards.length === 0) { toast("No cards to send yet", "err"); return; }
    toast("Sending...", "info");
    fetch("/api/push", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ key: pushKey, cards: cards.map(cardLine).join("\n") })
    })
      .then(function (r) { return r.json().then(function (j) { return { status: r.status, body: j }; }); })
      .then(function (res) {
        if (res.body.ok) {
          toast(res.body.count + " card(s) sent — open CardVault on your watch", "ok");
        } else if (res.status === 400) {
          forgetPairing();
          toast("Pairing expired — connect your watch again", "err");
        } else {
          toast("Error: " + (res.body.error || "unknown"), "err");
        }
      })
      .catch(function (e) { toast("Could not send: " + e.message, "err"); });
  });

  render();
})();
