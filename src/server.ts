/**
 * server.ts — Express host for the multi-level MCPGoat.
 *
 *   GET  /                  -> control panel (pick level, scoreboard)
 *   GET  /api/state         -> { level, scoreboard }
 *   POST /control/level     -> set difficulty level
 *   POST /control/reset     -> reset scoreboard + collector
 *   POST /internal/collect  -> OOB collector sink (for blind challenges)
 *   GET  /internal/secret   -> internal-only service (SSRF demo target)
 *   ANY  /mcp               -> MCP over Streamable HTTP (session-managed)
 */

import express, { type Request, type Response } from "express";
import { randomUUID, createHash } from "node:crypto";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { createServer } from "./buildServer.js";
import { getLevel, setLevel, LEVELS, SELECTABLE_LEVELS, LEVEL_LABELS, LEVEL_BLURB, Level } from "./level.js";
import { scoreboardView, resetScoreboard, flag } from "./scoreboard.js";
import { resetChallengeState } from "./challenges.js";
import { collect, readCollector } from "./internal.js";

const PORT = Number(process.env.PORT ?? 7332);
const HOST = process.env.HOST ?? "127.0.0.1";

const app = express();
app.use(express.json());

/* ----------------------- control panel ------------------------------ */
app.get("/", (_req, res) => res.type("html").send(renderPanel()));

app.get("/api/state", (_req, res) =>
  // `port` is the server's own loopback port — used by clients to build
  // server-side OOB callback URLs that work under any host port mapping.
  res.json({ level: getLevel(), levels: LEVELS, port: PORT, scoreboard: scoreboardView() })
);

app.post("/control/level", (req, res) => {
  const level = setLevel(String(req.body?.level ?? ""));
  res.json({ level });
});

app.post("/control/reset", (_req, res) => {
  resetScoreboard();
  resetChallengeState();
  res.json({ ok: true });
});

/* ----------------------- internal services -------------------------- */
// OOB collector (blind command-injection / SSRF exfil land here).
app.post("/internal/collect", express.text({ type: () => true }), (req, res) => {
  collect(String(req.query.channel ?? "default"), String(req.body ?? ""));
  res.json({ ok: true });
});
app.get("/internal/collect", (req, res) => {
  collect(String(req.query.channel ?? "default"), String(req.query.d ?? ""));
  res.json({ ok: true });
});
app.get("/internal/collector/log", (_req, res) => res.json(readCollector()));
// "Internal-only" service for the curl/Burp SSRF demo.
app.get("/internal/secret", (_req, res) =>
  res.type("text/plain").send(`internal service ok\nflag: ${flag("ssrf", "easy")}\n`)
);

// Internal target for the XXE http-entity challenge (reached server-side by the parser).
app.get("/internal/xxe", (_req, res) => {
  const lvl = getLevel();
  if (lvl === "secure") return res.status(403).send("entities disabled");
  const f = flag("xxe", lvl);
  if (lvl === "difficult") collect("xxe", f); // blind XXE: deliver out-of-band
  res.type("text/plain").send(`xxe-internal ok\nflag: ${f}\n`);
});

/* ------------- Transport-layer challenges (F1 / F2 / C6) ------------ */
const SELF_ORIGINS = ["http://127.0.0.1:7332", "http://localhost:7332"];

// F1 — DNS rebinding / missing Origin validation.
app.get("/api/browser-bridge", (req, res) => {
  const lvl = getLevel();
  const origin = req.headers.origin as string | undefined;
  if (lvl === "secure") {
    // FIX: strict Origin allow-list; reject foreign and null origins.
    if (!origin || SELF_ORIGINS.includes(origin)) return res.json({ ok: true, note: "same-origin only" });
    return res.status(403).json({ ok: false, note: "origin not allowed" });
  }
  const foreign = !!origin && !SELF_ORIGINS.includes(origin);
  let accepted: boolean;
  if (lvl === "easy") accepted = true; // no Origin check at all
  else if (lvl === "moderate") accepted = !!origin && /localhost/i.test(origin); // substring check
  else accepted = !origin || origin === "null" || SELF_ORIGINS.includes(origin); // allows null Origin
  if (accepted && (foreign || origin === "null")) {
    res.json({ ok: true, flag: flag("dns-rebinding", lvl) });
  } else {
    res.status(403).json({ ok: false, note: "origin rejected / not cross-origin" });
  }
});

// F2 — CORS misconfiguration (reflects untrusted Origin with credentials).
app.get("/api/cors-data", (req, res) => {
  const lvl = getLevel();
  const origin = req.headers.origin as string | undefined;
  if (lvl === "secure") {
    // FIX: only echo an exact same-origin; never reflect arbitrary Origins with credentials.
    if (origin && SELF_ORIGINS.includes(origin)) res.setHeader("access-control-allow-origin", origin);
    return res.json({ ok: true, note: "no cross-origin reflection" });
  }
  let reflect: boolean;
  if (lvl === "easy") reflect = !!origin; // reflect anything
  else if (lvl === "moderate") reflect = !!origin && /trusted\.example/.test(origin); // unanchored
  else reflect = !!origin && origin.endsWith("trusted.example"); // suffix, no dot boundary
  if (reflect && origin) {
    res.setHeader("access-control-allow-origin", origin);
    res.setHeader("access-control-allow-credentials", "true");
    res.json({ ok: true, flag: flag("cors", lvl) });
  } else {
    res.json({ ok: false, note: "origin not reflected" });
  }
});

// C6 — predictable session IDs. (Secure ids are CSPRNG, not derivable.)
const SECURE_ADMIN_SESSION = randomUUID();
const SECURE_YOUR_SESSION = randomUUID();
const yourSession = (lvl: Level) =>
  lvl === "easy" ? "sess-0042"
  : lvl === "moderate" ? Buffer.from("session:42").toString("base64")
  : lvl === "secure" ? SECURE_YOUR_SESSION
  : createHash("sha256").update("alice").digest("hex").slice(0, 16);
const adminSession = (lvl: Level) =>
  lvl === "easy" ? "sess-0001"
  : lvl === "moderate" ? Buffer.from("session:1").toString("base64")
  : lvl === "secure" ? SECURE_ADMIN_SESSION
  : createHash("sha256").update("root_admin").digest("hex").slice(0, 16);
app.get("/api/session/me", (_req, res) => {
  const lvl = getLevel();
  res.json({ you: "alice", sessionId: yourSession(lvl), note: "issued just now" });
});
app.get("/api/session/:id", (req, res) => {
  const lvl = getLevel();
  if (req.params.id === adminSession(lvl)) {
    if (lvl === "secure") return res.json({ user: "root_admin", note: "session ok (no flag at secure)" });
    return res.json({ user: "root_admin", flag: flag("session-prediction", lvl) });
  }
  res.json({ user: "unknown", data: "(empty)" });
});

/* --------------------- MCP Streamable HTTP -------------------------- */
const transports: Record<string, StreamableHTTPServerTransport> = {};

app.post("/mcp", async (req: Request, res: Response) => {
  const sessionId = req.headers["mcp-session-id"] as string | undefined;
  let transport = sessionId ? transports[sessionId] : undefined;

  if (!transport) {
    if (sessionId || !isInitializeRequest(req.body)) {
      res.status(400).json({
        jsonrpc: "2.0",
        error: { code: -32000, message: "Bad Request: send initialize first." },
        id: null,
      });
      return;
    }
    transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      onsessioninitialized: (sid) => {
        transports[sid] = transport!;
      },
    });
    transport.onclose = () => {
      if (transport!.sessionId) delete transports[transport!.sessionId];
    };
    await createServer().connect(transport);
  }
  await transport.handleRequest(req, res, req.body);
});

async function sessionRequest(req: Request, res: Response) {
  const sessionId = req.headers["mcp-session-id"] as string | undefined;
  const transport = sessionId ? transports[sessionId] : undefined;
  if (!transport) {
    res.status(400).send("Invalid or missing session ID");
    return;
  }
  await transport.handleRequest(req, res);
}
app.get("/mcp", sessionRequest);
app.delete("/mcp", sessionRequest);

app.listen(PORT, HOST, () => {
  console.log(`\n  MCPGoat  →  http://${HOST}:${PORT}`);
  console.log(`  MCP endpoint:  http://${HOST}:${PORT}/mcp`);
  console.log(`  Difficulty:    ${getLevel()}  (change at the control panel or via mcpgoat_set_level)`);
  console.log(`  Authorized training use only.\n`);
});

/* ----------------------------- view --------------------------------- */
function renderPanel(): string {
  const lvl = getLevel();
  const radios = SELECTABLE_LEVELS.map((l: Level) => {
    const on = l === lvl;
    return `<label class="lvl ${on ? "on" : ""}">
      <input type="radio" name="level" value="${l}" ${on ? "checked" : ""}
             onclick="setLevel('${l}')"/>
      <b>${LEVEL_LABELS[l]}</b><span>${LEVEL_BLURB[l]}</span></label>`;
  }).join("");

  return `<!doctype html><html><head><meta charset="utf-8"/>
<title>MCPGoat</title><style>
  body{font:14px/1.5 system-ui,sans-serif;max-width:880px;margin:32px auto;padding:0 16px;color:#1a1a1a}
  h1{margin:0 0 4px} .warn{background:#fee;border:1px solid #f99;padding:8px 12px;border-radius:6px;color:#900}
  .lvl{display:block;border:1px solid #ccc;border-radius:8px;padding:10px 12px;margin:6px 0;cursor:pointer}
  .lvl.on{border-color:#2b6;background:#eafaf0} .lvl b{margin-right:8px} .lvl span{color:#555}
  code{background:#f3f3f3;padding:1px 5px;border-radius:4px}
  table{border-collapse:collapse;width:100%;margin-top:8px} th,td{border:1px solid #ddd;padding:5px 8px;text-align:left;font-size:13px}
  .ok{color:#2b6;font-weight:700} .no{color:#bbb} button{padding:6px 12px;border-radius:6px;border:1px solid #999;cursor:pointer;background:#fff}
  .badge{display:inline-block;background:#2b6;color:#fff;padding:2px 8px;border-radius:10px;font-size:12px}
</style></head><body>
<h1>MCPGoat <span class="badge" id="lvlBadge">${lvl}</span></h1>
<p class="warn">⚠️ Intentionally vulnerable. Authorized training only — keep it on <code>127.0.0.1</code>.</p>
<p>MCP endpoint: <code>http://${HOST}:${PORT}/mcp</code> &nbsp;·&nbsp; attack with the bundled client (<code>npm run attack</code>), MCP Inspector (<code>npm run inspect</code>), or curl.</p>
<h3>Difficulty level</h3>${radios}
<p style="color:#555">Tip: after changing level, <b>reconnect</b> your MCP client to refresh tool descriptions.</p>
<h3>Scoreboard &nbsp;<button onclick="resetAll()">Reset</button></h3>
<table id="sb"><thead><tr><th>ID</th><th>Challenge</th><th>Category</th><th>★</th><th>Easy</th><th>Mod</th><th>Diff</th></tr></thead><tbody></tbody></table>
<script>
async function refresh(){
  const s=await (await fetch('/api/state')).json();
  document.getElementById('lvlBadge').textContent=s.level;
  const tb=document.querySelector('#sb tbody');tb.innerHTML='';
  for(const c of s.scoreboard.challenges){
    const cell=v=>'<td class="'+(v?'ok':'no')+'">'+(v?'✓':'·')+'</td>';
    tb.insertAdjacentHTML('beforeend','<tr><td>'+c.id+'</td><td>'+c.title+'</td><td>'+c.category+'</td><td>'+'★'.repeat(c.stars)+'</td>'+cell(c.solved.easy)+cell(c.solved.moderate)+cell(c.solved.difficult)+'</tr>');
  }
}
async function setLevel(l){await fetch('/control/level',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({level:l})});refresh();}
async function resetAll(){await fetch('/control/reset',{method:'POST'});refresh();}
refresh();setInterval(refresh,3000);
</script></body></html>`;
}
