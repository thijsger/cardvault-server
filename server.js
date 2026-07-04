// CardVault sync-server.
// Koppelt de webapp aan het horloge via een korte code. Opslag is bewust
// vluchtig: kaarten staan max TTL_MS in het geheugen en worden daarna gewist.
// Geen database, geen logging van kaartinhoud.

const express = require("express");
const path = require("path");

const app = express();
// Garmin-vriendelijk: geen etag (voorkomt lege 304's) en geen transform
// (Cloudflare gzip breekt de Garmin JSON-parser).
app.set("etag", false);
app.disable("x-powered-by");
app.use((req, res, next) => {
  res.set("Cache-Control", "no-store, no-transform");
  next();
});
app.use(express.json({ limit: "256kb" }));
app.use(express.static(path.join(__dirname, "public")));

const PORT = process.env.PORT || 3000;
const TTL_MS = 30 * 60 * 1000; // 30 minuten

// code -> { cards: string, expires: number }
const store = new Map();

function sweep() {
  const now = Date.now();
  for (const [code, entry] of store) {
    if (entry.expires <= now) { store.delete(code); }
  }
}
setInterval(sweep, 60 * 1000).unref();

function validCode(c) {
  return typeof c === "string" && /^[A-Z0-9]{4,8}$/.test(c);
}

// Webapp stuurt kaarten naar een koppelcode.
// body: { code, cards }  waarbij cards de pipe/newline-tekst is (zoals in de app).
app.post("/api/push", (req, res) => {
  const code = (req.body && req.body.code || "").toString().toUpperCase();
  const cards = (req.body && req.body.cards || "").toString();
  if (!validCode(code)) { return res.status(400).json({ error: "code ongeldig" }); }
  if (cards.length > 20000) { return res.status(413).json({ error: "te veel data" }); }
  store.set(code, { cards: cards, expires: Date.now() + TTL_MS });
  res.json({ ok: true, count: cards.split("\n").filter(function (l) { return l.trim().length; }).length });
});

// Horloge haalt kaarten op voor zijn code. Antwoord is platte tekst (1 kaart
// per regel), zodat de Garmin-app het simpel kan parsen. Wordt na ophalen
// bewaard tot de TTL verloopt (zodat een retry werkt), daarna gewist.
app.get("/api/pull", (req, res) => {
  const code = (req.query.code || "").toString().toUpperCase();
  if (!validCode(code)) { return res.status(400).type("text/plain").send(""); }
  const entry = store.get(code);
  res.type("text/plain");
  res.send(entry ? entry.cards : "");
});

// Horloge kan zijn data expliciet wissen (privacy).
app.post("/api/clear", (req, res) => {
  const code = (req.body && req.body.code || "").toString().toUpperCase();
  if (validCode(code)) { store.delete(code); }
  res.json({ ok: true });
});

app.get("/api/health", (req, res) => res.json({ ok: true, pending: store.size }));

app.listen(PORT, () => console.log("CardVault sync op poort " + PORT));
