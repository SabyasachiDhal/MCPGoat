# MCPGoat

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
&nbsp;·&nbsp; open source, free to use and self-host.

**🌐 Website:** <https://sabyasachidhal.github.io/MCPGoat/>
&nbsp;·&nbsp; **Listed on [Glama](https://glama.ai/mcp/servers/SabyasachiDhal/MCPGoat)**

A deliberately insecure **Model Context Protocol** server for practicing MCP
penetration testing. Every challenge is implemented at **three difficulty levels
(Easy / Moderate / Difficult)** behind a tiered level switch, with a
capture-the-flag scoreboard. Runs over
**Streamable HTTP**; attack it with the bundled client, MCP Inspector, `curl`,
or Burp.

> ⚠️ **Authorized training use only.** Intentionally contains RCE, SSRF, SQLi,
> secret leakage, and more. Keep it on `127.0.0.1`; ideally run it in a
> container. Never expose it to a network you don't own.

> ℹ️ _MCPGoat is an independent project — **not affiliated with or endorsed by
> the WebGoat project, or any other similarly-named "vulnerable MCP"
> project**._

Implements the **Core set + three Extended batches** from
[`DESIGN_PROMPT.md`](DESIGN_PROMPT.md) — **26 challenges × 3 levels = 78
distinct flags**, exercising every major MCP primitive (tools, resources,
prompts, **sampling**) plus the HTTP **transport** layer. Each challenge also
has a 4th **Secure** level: the fixed, unexploitable reference where every
documented exploit fails (verify with `npm run attack -- … secure`).

---

## What it looks like

The **control panel** (`http://127.0.0.1:7332`) — pick a difficulty level and
track progress. This is config + progress
only; it is **not** the thing you attack.

![MCPGoat control panel](docs/img/control-panel.png)

The actual attack surface is the **MCP server itself** — its tools, resources,
prompts, and sampling calls. MCP servers have no human web UI; you interact as an
MCP **client**. Here it is in **MCP Inspector** (the bundled attacker client and
a real AI agent are the other two ways):

![MCP Inspector connected to the MCPGoat server](docs/img/mcp-inspector.png)

---

## Deploy

### Docker (recommended — one command, self-contained, RCE stays in the container)

```bash
cd mcpgoat
docker compose up --build            # → http://127.0.0.1:7332
# or:
docker build -t mcpgoat .
docker run --rm -p 127.0.0.1:7332:7332 mcpgoat
```

The image is **~202 MB** — a bare Alpine with just the `node` binary plus
`curl`/`ping` (for the RCE challenge); the server is esbuild-bundled to a single
~1.2 MB file, so the runtime carries **no `node_modules`, npm, or
package.json**. Runs as a non-root user. **Keep the `127.0.0.1:` in the port
mapping** — `-p 7332:7332` would expose the vulnerable server on every host
interface. Start at a level with `-e MCPGOAT_LEVEL=difficult`.

### Local Node (for development)

Requires **Node 18+** (tested on Node 22/23/24; uses the built-in `node:sqlite`).

```bash
npm install
npm start                 # serves http://127.0.0.1:7332   (tsx, no build step)
# or compiled:  npm run build && npm run serve
```

Open the **control panel** at <http://127.0.0.1:7332> to pick a level and watch
the scoreboard. Start at a level directly with `MCPGOAT_LEVEL=moderate npm start`.

---

## The difficulty model (pick your level, then pentest)

The *same* vulnerability hardens as you climb:

| | **Easy** | **Moderate** | **Difficult** |
|---|---|---|---|
| Auth | none | static token (leaked elsewhere) | OAuth-style / crypto / forged token |
| Filtering | none | bypassable blacklist | allowlist with a gap |
| Feedback | full output | partial | **blind / out-of-band** |
| Steps | 1 | 2–3 chained | multi-step, cross-primitive |
| Hints | in tool description | scoreboard only | none |

…and **Secure** — the fixed reference: strict validation, exact-match auth,
parameterized queries, no `eval`, Origin allow-lists, CSPRNG session IDs,
least-privilege tools. No flags here; the point is every attack fails. Confirm
with `npm run attack -- http://127.0.0.1:7332/mcp secure` (expect 22/22 blocked).

**Selecting a level** (any of these — all drive one shared state):
1. **Control panel** — radio buttons at <http://127.0.0.1:7332>
2. **MCP tool** — `mcpgoat_set_level({ level })`
3. **Env** — `MCPGOAT_LEVEL=difficult npm start`

> After changing level, **reconnect** your MCP client so tool *descriptions*
> refresh (matters for the tool-poisoning / shadowing challenges). Behavior
> changes take effect immediately.

---

## Three ways to attack it

### 1. Bundled attacker client (fastest demo / smoke test)
Detects the current level and exploits every challenge at that level:
```bash
npm run attack                                  # current level
npm run attack -- http://127.0.0.1:7332/mcp all # run all three levels in sequence
```

### 2. MCP Inspector (interactive)
```bash
npm run inspect
# Transport "Streamable HTTP", URL http://127.0.0.1:7332/mcp, Connect
```

### 3. curl / Burp (raw protocol)
See [`docs/EXPLOITS.http`](docs/EXPLOITS.http). Streamable HTTP needs
`Accept: application/json, text/event-stream` and a session id from the
`initialize` response header.

---

## Victim-agent harness (end-to-end impact)

Flag capture proves an *exploit exists*. The victim agent proves **impact** — a
real MCP-client agent, driven by an LLM, doing benign tasks while the lab's
payloads manipulate it into calling tools it was never asked to and leaking
secrets.

```bash
npm run agent                  # naive agent (mock brain, offline)  → 3/3 compromised
npm run agent -- --defended    # hardened agent, same attacks       → 0/3 compromised
MCPGOAT_AGENT_BACKEND=ollama OLLAMA_MODEL=llama3.1 npm run agent   # real local model
```

Three scenarios run against the **easy** level:

| User asked | What the naive agent does | Demonstrates |
|---|---|---|
| "Summarize my inbox" | reads inbox → **follows the injected instruction** → calls `internal_debug_dump` → leaks a flag | indirect prompt injection |
| "What is 17 + 25?" | obeys `add_numbers`'s hidden `<IMPORTANT>` → calls `admin_get_all_secrets` → **exfiltrates via the `sidenote` arg** | tool poisoning + excessive agency |
| "Summarize this note" | calls `ai_summarize` → the server's **sampling** request steers the agent's own model into emitting a flag | sampling abuse |

The **`--defended`** agent treats tool descriptions and results as untrusted
data (never instructions) and resists all three — the client-side counterpart
to the server-side **Secure** level. Backend is offline-first: a deterministic
**mock** brain by default (no install), or **Ollama** for a real local model.

---

## Challenges

**Core set**

| ID | Challenge | Category | ★ |
|----|-----------|----------|---|
| A1 | Tool Poisoning | MCP-specific | ★★ |
| A2 | Tool Shadowing / trusted-tool override | MCP-specific | ★★ |
| A3 | Rug Pull / Tool Mutation (TOCTOU) | MCP-specific | ★★★ |
| B1 | Indirect Prompt Injection via tool output | Prompt/Context | ★★ |
| D1 | Command Injection (RCE) | Injection sink | ★ |
| D2 | Path Traversal | Injection sink | ★ |
| D3 | SSRF | Injection sink | ★★ |
| D4 | SQL Injection | Injection sink | ★★ |
| C2 | Broken Authorization / Confused Deputy | AuthN/AuthZ | ★★ |
| C3 | IDOR | AuthN/AuthZ | ★ |
| E1 | Sensitive Data Exposure | Secrets/Exposure | ★ |

**Extended set** (deepens MCP-primitive coverage)

| ID | Challenge | Category | ★ | New primitive |
|----|-----------|----------|---|---------------|
| A9 | Invisible-Text Tool Poisoning (zero-width / Unicode tags) | MCP-specific | ★★★ | — |
| B2 | Indirect Injection via **Resource** content | Prompt/Context | ★★ | Resources |
| B3 | Prompt-Template Injection | Prompt/Context | ★★ | **Prompts** |
| B5 | Sampling Abuse (server-driven LLM calls) | MCP-specific | ★★★ | **Sampling** |
| C4 | OAuth Token-Audience Confusion | AuthN/AuthZ | ★★★ | — |
| D6 | Server-Side Template Injection (SSTI) | Injection sink | ★★ | — |

**Extended set — batch 2** (HTTP transport & resource abuse; solved via raw `fetch`/tools)

| ID | Challenge | Category | ★ |
|----|-----------|----------|---|
| F1 | DNS Rebinding / missing Origin validation | Transport | ★★★ |
| F2 | CORS Misconfiguration (reflected Origin + credentials) | Transport | ★★ |
| C6 | Predictable Session IDs (hijack) | Transport | ★★ |
| G1 | Unbounded Consumption (cost/DoS) | DoS/Cost | ★★ |
| G4 | Regular-Expression DoS (ReDoS) | DoS/Cost | ★★ |

**Extended set — batch 3** (more injection sinks & supply chain)

| ID | Challenge | Category | ★ |
|----|-----------|----------|---|
| D5 | NoSQL Injection (operator / `$where`) | Injection sink | ★★ |
| D7 | XML External Entity (XXE) | Injection sink | ★★★ |
| D8 | Insecure Deserialization (prototype pollution) | Injection sink | ★★★ |
| H1 | Supply Chain (typosquat / unsigned package) | Supply chain | ★★ |

Each `(challenge, level)` pair has a unique flag `FLAG{slug__level}`. Capture it,
submit with the `submit_flag` tool, track progress with `scoreboard` (or the
control panel). Per-level hints: the `list_challenges` tool.

Full per-level walkthroughs + fixes: [`docs/SOLUTIONS.md`](docs/SOLUTIONS.md).

---

## How the levels differ (a taste)

- **Command Injection** — Easy: no filter. Moderate: `;`/`&` blocked → use `|`.
  Difficult: most metacharacters blocked **and blind** → newline-chain a `curl`
  that exfiltrates to the OOB collector, then `read_collector`.
- **SSRF** — Easy: fetch anything. Moderate: `127.0.0.1`/`localhost` string-blocked
  → use `metadata.internal` / `[::1]`. Difficult: same, but **blind** → confirm via
  the collector.
- **SQL Injection** — Easy: `UNION`. Moderate: `UNION`/`--` blacklisted → `UnIoN`
  + quote-balancing. Difficult: **boolean-blind**, count-only → binary-search the
  flag out char by char.
- **Broken Auth** — Easy: open. Moderate: static token leaked by a resource.
  Difficult: `sha256(nonce + signing_secret)` challenge-response (secret leaks via
  a verbose error).

---

## Project layout

```
mcpgoat/
├── DESIGN_PROMPT.md          # the full build brief (Core + Extended catalog)
├── Dockerfile  docker-compose.yml   # one-command deploy
├── .github/workflows/ci.yml  # regression gate + Docker smoke test
├── src/
│   ├── server.ts             # Express host: control panel, MCP endpoint, OOB collector
│   ├── level.ts              # the Easy/Moderate/Difficult switch
│   ├── scoreboard.ts         # challenge catalog, per-level flags, scoreboard
│   ├── challenges.ts         # all 26 challenges × 4 levels (incl. secure)
│   ├── buildServer.ts  db.ts  state.ts  internal.ts
│   ├── attacker/client.ts    # level-aware exploitation client / smoke test
│   ├── agent/agent.ts        # victim-agent harness (naive vs --defended)
│   └── ci/check.ts           # regression gate (npm run ci)
├── workspace/  vault/        # path-traversal / RCE targets (per-level flag files)
└── docs/SOLUTIONS.md  docs/EXPLOITS.http
```

## Continuous regression

`npm run ci` boots an isolated server and asserts the whole lab still works —
**78/78** scored flags captured, **26/26** exploits blocked at the secure level,
and the victim agent **3/3** compromised (naive) / **0/3** (defended). Expected
counts derive from the catalog, so it can't drift; a broken challenge or a fix
that springs a leak fails the gate (non-zero exit). The bundled
[GitHub Actions workflow](.github/workflows/ci.yml) runs this plus a Docker
build + boot smoke-test on every push.

State is in-memory — **restart to reset**, or use the control panel's Reset
button / the `mcpgoat_reset` tool.

---

## Author / Connect

Built by **Sabyasachi Dhal**. If MCPGoat is useful to you — or you work on MCP /
AI-agent security — I'd love to connect:
**[linkedin.com/in/sabyasachidhal](https://www.linkedin.com/in/sabyasachidhal/)**

Issues, ideas, and pull requests are very welcome — see
[`CONTRIBUTING.md`](CONTRIBUTING.md). If this saved you time, a ⭐ on the repo
helps others find it.

---

## License

**MIT** — open source, free to use and self-host. You may use, copy, modify,
merge, publish, distribute, sublicense, and sell copies (including commercially),
as long as you keep the copyright and license notice. See [`LICENSE`](LICENSE).

© 2026 Sabyasachi Dhal.

> The MIT license is permissive and comes with **no warranty**. This software is
> **intentionally vulnerable** and provided for **authorized security training
> and education only**. You are responsible for running it safely (keep it on
> `127.0.0.1` / inside a container) and for how you use it — do not point its
> tools at systems you are not authorized to test.
