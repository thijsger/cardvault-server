// CardVault sync-server.
//
// Koppelmodel (zo min mogelijk stappen, zonder raadbare codes):
//   1. Horloge vraagt eenmalig POST /api/pair  -> krijgt een geheime token
//      (100 bits) plus een korte koppelcode die 10 minuten geldig is.
//   2. Gebruiker typt die koppelcode één keer in de webapp: POST /api/claim
//      ruilt de code in voor een push-sleutel. De code is daarna verbruikt.
//   3. Webapp bewaart de push-sleutel en stuurt voortaan zonder codes:
//      POST /api/push. Het horloge haalt op met GET /api/pull?code=<token>.
//
// De push-sleutel is HMAC(SERVER_SECRET, token): de server hoeft de koppeling
// dus niet op te slaan en een herstart verbreekt geen enkele koppeling.
//
// Opslag is bewust vluchtig: kaarten staan max TTL_MS in het geheugen, worden
// na ophalen vrijwel meteen gewist en raken nooit een database of een log.

const express = require("express");
const crypto = require("crypto");
const path = require("path");

const app = express();

// Render zet de echte client-ip in X-Forwarded-For (één proxy-hop).
app.set("trust proxy", 1);
// Garmin-vriendelijk: geen etag (voorkomt lege 304's) en geen transform
// (Cloudflare gzip breekt de Garmin-parser).
app.set("etag", false);
app.disable("x-powered-by");

const PORT = process.env.PORT || 3000;
const TTL_MS = 30 * 60 * 1000;      // kaarten blijven max 30 min staan
const GRACE_MS = 90 * 1000;         // na ophalen nog kort bewaard voor een retry
const CODE_TTL_MS = 10 * 60 * 1000; // koppelcode is 10 min geldig
const MAX_CARDS_CHARS = 20000;
const MAX_PENDING = 5000;           // harde geheugengrens
const MAX_CODES = 2000;

// Sleutel voor het afleiden van push-sleutels. Zet PAIR_SECRET als env-var
// (render.yaml doet dat automatisch); zonder env-var werkt alles, maar breken
// bestaande koppelingen bij een herstart.
const SECRET = process.env.PAIR_SECRET || crypto.randomBytes(32).toString("hex");
if (!process.env.PAIR_SECRET) {
  console.warn("PAIR_SECRET niet gezet — koppelingen overleven geen herstart.");
}

// Alfabet zonder I, O, 0 en 1 (verwarrend bij overtypen). 32 tekens deelt 256
// precies, dus modulo geeft geen bias.
const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

function randomString(len) {
  const bytes = crypto.randomBytes(len);
  let out = "";
  for (let i = 0; i < len; i++) { out += ALPHABET[bytes[i] % ALPHABET.length]; }
  return out;
}

function encode(buf, len) {
  let out = "";
  for (let i = 0; i < len; i++) { out += ALPHABET[buf[i % buf.length] % ALPHABET.length]; }
  return out;
}

// Push-sleutel hoort deterministisch bij de token, maar is er niet uit af te
// leiden zonder SECRET (en andersom lekt een push-sleutel de token niet).
// De laatste 6 tekens zijn een controlegetal, zodat de server een verzonnen
// sleutel meteen kan weigeren en niemand het geheugen kan volgooien.
function pushKeyFor(token) {
  const mac = crypto.createHmac("sha256", SECRET).update("push|" + token).digest();
  const body = encode(mac, 20);
  return body + checksumFor(body);
}

function checksumFor(body) {
  const mac = crypto.createHmac("sha256", SECRET).update("check|" + body).digest();
  return encode(mac, 6);
}

function isIssuedKey(v) {
  if (!isPushKey(v)) { return false; }
  const expected = checksumFor(v.slice(0, 20));
  return crypto.timingSafeEqual(Buffer.from(v.slice(20)), Buffer.from(expected));
}

const TOKEN_LEN = 20;  // 20 * 5 bits = 100 bits entropie
const CODE_LEN = 6;    // 32^6 ≈ 1,07 miljard mogelijkheden, 10 minuten geldig
const isToken = (v) => typeof v === "string" && new RegExp("^[" + ALPHABET + "]{" + TOKEN_LEN + "}$").test(v);
const isCode = (v) => typeof v === "string" && new RegExp("^[" + ALPHABET + "]{" + CODE_LEN + "}$").test(v);
const isPushKey = (v) => typeof v === "string" && new RegExp("^[" + ALPHABET + "]{26}$").test(v);

// pushKey -> { cards, expires }
const pending = new Map();
// koppelcode -> { pushKey, expires }
const codes = new Map();

function sweep() {
  const now = Date.now();
  for (const [k, e] of pending) { if (e.expires <= now) { pending.delete(k); } }
  for (const [k, e] of codes) { if (e.expires <= now) { codes.delete(k); } }
}
setInterval(sweep, 30 * 1000).unref();

// ---------- rate limiting (vast venster per ip, in-memory) ----------
function limiter(max, windowMs) {
  const hits = new Map();
  setInterval(() => {
    const now = Date.now();
    for (const [k, e] of hits) { if (e.reset <= now) { hits.delete(k); } }
  }, windowMs).unref();

  return function (req, res, next) {
    const now = Date.now();
    const ip = req.ip || "?";
    let e = hits.get(ip);
    if (!e || e.reset <= now) { e = { count: 0, reset: now + windowMs }; hits.set(ip, e); }
    e.count++;
    if (hits.size > 20000) { hits.clear(); } // noodrem tegen geheugengroei
    if (e.count > max) {
      res.set("Retry-After", Math.ceil((e.reset - now) / 1000).toString());
      return res.status(429).json({ error: "te veel verzoeken" });
    }
    next();
  };
}

// Extra rem op het raden van koppelcodes. De eerste paar missers zijn gewoon
// typefouten; daarna gaat het slot er steeds langer op.
const failedClaims = new Map(); // ip -> { count, windowEnd, until }
const CLAIM_WINDOW_MS = 60 * 60 * 1000;

function claimGuard(req, res, next) {
  const e = failedClaims.get(req.ip);
  if (e && e.until > Date.now()) {
    return res.status(429).json({ error: "te veel mislukte pogingen" });
  }
  next();
}

function noteFailedClaim(ip) {
  const now = Date.now();
  let e = failedClaims.get(ip);
  if (!e || e.windowEnd <= now) { e = { count: 0, windowEnd: now + CLAIM_WINDOW_MS, until: 0 }; }
  e.count++;
  if (e.count >= 8) { e.until = now + CLAIM_WINDOW_MS; }
  else if (e.count >= 3) { e.until = now + 30 * 1000; }
  if (failedClaims.size > 20000) { failedClaims.clear(); }
  failedClaims.set(ip, e);
}

setInterval(() => {
  const now = Date.now();
  for (const [ip, e] of failedClaims) {
    if (e.windowEnd <= now && e.until <= now) { failedClaims.delete(ip); }
  }
}, 10 * 60 * 1000).unref();

// ---------- headers ----------
app.use((req, res, next) => {
  res.set("Cache-Control", "no-store, no-transform");
  res.set("X-Content-Type-Options", "nosniff");
  res.set("Referrer-Policy", "no-referrer");
  res.set("X-Frame-Options", "DENY");
  res.set("Cross-Origin-Opener-Policy", "same-origin");
  res.set("Cross-Origin-Resource-Policy", "same-origin");
  res.set("Permissions-Policy", "camera=(self), microphone=(), geolocation=()");
  res.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  // Alles komt van deze server: geen externe scripts, fonts of verbindingen.
  res.set("Content-Security-Policy", [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "font-src 'self'",
    "img-src 'self' data: blob:",
    "media-src 'self' blob:",
    "worker-src 'self' blob:",
    "child-src 'self' blob:",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
    "upgrade-insecure-requests"
  ].join("; "));
  next();
});

// ---------- doorgeefstation: CORS ----------
// /api/relay/* wordt aangeroepen door https://gerros.app/pair.html (ander domein)
// en door het horloge (geen Origin). Alleen deze paden krijgen CORS; de rest van
// de server blijft same-origin. Localhost alleen met RELAY_ALLOW_LOCALHOST=1 (test).
const RELAY_ORIGINS = ["https://gerros.app", "https://www.gerros.app"];
const RELAY_LOCAL = process.env.RELAY_ALLOW_LOCALHOST === "1";
const LOCAL_ORIGIN = /^http:\/\/(localhost|127\.0\.0\.1)(:\d{1,5})?$/;

app.use("/api/relay", (req, res, next) => {
  const origin = req.headers.origin;
  res.set("Vary", "Origin");
  if (origin) {
    const ok = RELAY_ORIGINS.indexOf(origin) !== -1 || (RELAY_LOCAL && LOCAL_ORIGIN.test(origin));
    if (!ok) { return res.status(403).json({ error: "origin" }); }
    res.set("Access-Control-Allow-Origin", origin);
    res.set("Cross-Origin-Resource-Policy", "cross-origin");
  }
  if (req.method === "OPTIONS") {
    res.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.set("Access-Control-Allow-Headers", "Content-Type");
    res.set("Access-Control-Max-Age", "600");
    return res.status(204).end();
  }
  next();
});

app.use(express.json({ limit: "64kb" }));
app.use(express.static(path.join(__dirname, "public"), {
  dotfiles: "ignore",
  index: "index.html",
  setHeaders: (res, filePath) => {
    // Vendor-bestanden en fonts mogen wél in de browsercache.
    if (filePath.indexOf(path.sep + "vendor" + path.sep) !== -1) {
      res.set("Cache-Control", "public, max-age=604800, immutable");
    }
  }
}));

// ---------- koppelen ----------

// Horloge vraagt eenmalig een token + korte koppelcode aan.
// Antwoord is platte tekst "TOKEN CODE" — makkelijk te parsen op de Garmin.
app.post("/api/pair", limiter(12, 60 * 60 * 1000), (req, res) => {
  if (codes.size >= MAX_CODES) { sweep(); }
  if (codes.size >= MAX_CODES) { return res.status(503).type("text/plain").send(""); }

  const token = randomString(TOKEN_LEN);
  let code = randomString(CODE_LEN);
  for (let i = 0; i < 5 && codes.has(code); i++) { code = randomString(CODE_LEN); }

  codes.set(code, { pushKey: pushKeyFor(token), expires: Date.now() + CODE_TTL_MS });
  res.type("text/plain").send(token + " " + code);
});

// Webapp ruilt de koppelcode eenmalig in voor een push-sleutel.
app.post("/api/claim", claimGuard, limiter(15, 10 * 60 * 1000), (req, res) => {
  const code = ((req.body && req.body.code) || "").toString().trim().toUpperCase();
  if (!isCode(code)) { noteFailedClaim(req.ip); return res.status(400).json({ error: "code ongeldig" }); }

  const entry = codes.get(code);
  if (!entry || entry.expires <= Date.now()) {
    codes.delete(code);
    noteFailedClaim(req.ip);
    return res.status(404).json({ error: "code onbekend of verlopen" });
  }
  codes.delete(code); // eenmalig bruikbaar
  res.json({ ok: true, key: entry.pushKey });
});

// ---------- kaarten ----------

// Webapp stuurt kaarten (pipe/newline-tekst) naar de gekoppelde push-sleutel.
app.post("/api/push", limiter(60, 60 * 60 * 1000), (req, res) => {
  const key = ((req.body && req.body.key) || "").toString().trim().toUpperCase();
  const cards = ((req.body && req.body.cards) || "").toString();
  if (!isIssuedKey(key)) { return res.status(400).json({ error: "niet gekoppeld" }); }
  if (cards.length > MAX_CARDS_CHARS) { return res.status(413).json({ error: "te veel data" }); }

  if (!pending.has(key) && pending.size >= MAX_PENDING) {
    sweep();
    if (pending.size >= MAX_PENDING) { return res.status(503).json({ error: "server vol, probeer later" }); }
  }
  pending.set(key, { cards: cards, expires: Date.now() + TTL_MS });
  res.json({ ok: true, count: cards.split("\n").filter((l) => l.trim().length).length });
});

// Horloge haalt zijn kaarten op. Antwoord is platte tekst (1 kaart per regel).
// Na het ophalen blijft de data nog kort staan zodat een mislukte overdracht
// nog eens geprobeerd kan worden; daarna is ze weg.
app.get("/api/pull", limiter(240, 60 * 60 * 1000), (req, res) => {
  const token = (req.query.code || req.query.token || "").toString().trim().toUpperCase();
  res.type("text/plain");
  if (!isToken(token)) { return res.status(400).send(""); }

  const key = pushKeyFor(token);
  const entry = pending.get(key);
  if (!entry || entry.expires <= Date.now()) { pending.delete(key); return res.send(""); }

  const grace = Date.now() + GRACE_MS;
  if (entry.expires > grace) { entry.expires = grace; }
  res.send(entry.cards);
});

// Horloge kan zijn data direct wissen (privacy).
app.post("/api/clear", limiter(60, 60 * 60 * 1000), (req, res) => {
  const body = req.body || {};
  const token = (body.code || body.token || "").toString().trim().toUpperCase();
  if (isToken(token)) { pending.delete(pushKeyFor(token)); }
  res.json({ ok: true });
});

// ---------- doorgeefstation (Domora: koppelen via QR) ----------
// De webpagina zet één versleuteld pakketje neer onder een code die het horloge
// zelf heeft bedacht; het horloge haalt het één keer op en dan is het weg.
// De sleutel staat alleen in de QR (achter de #) en komt hier nooit langs: de
// server ziet alleen base64 die hij niet kan lezen. Alleen in het geheugen,
// hooguit RELAY_TTL_MS, en de inhoud komt nooit in een log.
const RELAY_TTL_MS = 10 * 60 * 1000;
const MAX_RELAY = 2000;             // harde bovengrens op openstaande codes
const MAX_RELAY_CHARS = 4096;
const isRelayCode = (v) => typeof v === "string" && /^[a-z2-9]{10}$/.test(v);
const isRelayData = (v) => typeof v === "string" && v.length >= 44 && v.length <= MAX_RELAY_CHARS &&
  v.length % 4 === 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(v);

// code -> { data, expires }
const relay = new Map();

function sweepRelay() {
  const now = Date.now();
  for (const [k, e] of relay) { if (e.expires <= now) { relay.delete(k); } }
}
setInterval(sweepRelay, 30 * 1000).unref();

// Wekt een slapende server terwijl de gebruiker nog aan het inloggen is.
app.get("/api/relay/ping", limiter(120, 10 * 60 * 1000), (req, res) => res.json({ ok: true }));

app.post("/api/relay/put", limiter(30, 10 * 60 * 1000), (req, res) => {
  const body = req.body || {};
  if (!isRelayCode(body.code)) { return res.status(400).json({ error: "code" }); }
  if (!isRelayData(body.data)) { return res.status(400).json({ error: "data" }); }

  const now = Date.now();
  const old = relay.get(body.code);
  if (old && old.expires > now) { return res.status(409).json({ error: "taken" }); }
  if (!old && relay.size >= MAX_RELAY) {
    sweepRelay();
    if (relay.size >= MAX_RELAY) { return res.status(503).json({ error: "full" }); }
  }
  relay.set(body.code, { data: body.data, expires: now + RELAY_TTL_MS });
  res.json({ ok: true });
});

// Het horloge vraagt elke paar seconden of er iets klaarstaat. Eenmalig: na een
// 200 is de code leeg. Al het andere (onbekend, verlopen, ongeldig) is 404.
app.get("/api/relay/get", limiter(600, 10 * 60 * 1000), (req, res) => {
  const code = (req.query.code || "").toString();
  const entry = isRelayCode(code) ? relay.get(code) : null;
  if (!entry) { return res.status(404).json({ error: "none" }); }
  relay.delete(code);
  if (entry.expires <= Date.now()) { return res.status(404).json({ error: "none" }); }
  res.json({ data: entry.data });
});

app.get("/api/health", limiter(60, 60 * 1000), (req, res) => res.json({ ok: true }));

// Geen stack traces naar buiten (bv. bij kapotte JSON).
app.use((err, req, res, next) => {
  if (res.headersSent) { return next(err); }
  res.status(400).json({ error: "verzoek ongeldig" });
});

app.listen(PORT, () => console.log("CardVault sync op poort " + PORT));
