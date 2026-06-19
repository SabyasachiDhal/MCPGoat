# Design Prompt — MCPGoat
### A lightweight, multi-level vulnerable Model Context Protocol lab for penetration-testing practice

> Paste this whole document into a capable coding agent (or hand it to an
> engineer) as the build brief. It is written in imperative voice on purpose.

---

## 0. Mission (one sentence)

Build a **deliberately vulnerable MCP server** for the Model Context Protocol
— that a penetration tester can **deploy with one
command**, **select a difficulty level (Easy / Moderate / Difficult)**, and then
attack to practice the **full spectrum of MCP-specific and MCP-exposed
vulnerabilities**, with a scoreboard, flags, and per-challenge solutions.

---

## 1. Background & intent

- The **Model Context Protocol (MCP)** lets AI agents call external **tools**,
  read **resources**, expand **prompts**, request **sampling** (server-initiated
  LLM calls), and expose **roots**, over **stdio** or **Streamable HTTP**
  transports, optionally behind **OAuth 2.1**.
- MCP introduces *new* attack classes (tool poisoning, rug pulls, indirect
  prompt injection, cross-server shadowing) **and** re-exposes every classic
  appsec bug because each tool is a fresh, often unauthenticated, sink.
- There is no canonical, broad, multi-level vulnerable target for MCP the way
  deliberately-vulnerable training apps exist for the web. Build that.
- **Two design pillars:**
  - A **security-level switch** (entry → impossible). Each vulnerability is
    implemented at every level so testers learn how the same bug hardens and how
    to bypass each defense. We use **Easy / Moderate / Difficult** (+ optional
    **Secure** reference).
  - **Breadth** (cover everything), a **scoreboard** with per-challenge
    difficulty stars and categories, **flags**, and a gamified
    progress loop.
- **Authorized training / education only.** This is intentionally insecure
  software; safety guardrails (§13) are mandatory, not optional.

---

## 2. Primary users & how they'll use it

| User | Use |
|------|-----|
| Penetration testers / red teamers | Practice MCP attack TTPs on a safe range |
| AppSec engineers / MCP developers | Learn what to defend; see secure references |
| Trainers / CTF authors | Run workshops, set difficulty per cohort |
| Tool authors of MCP scanners | A stable target to test scanners against |

**Workflow:** deploy → open the control panel → **pick a difficulty level** →
attack via MCP Inspector, Burp, `curl`, a custom MCP client, or (stretch) a real
victim agent → capture `FLAG{...}` → submit to scoreboard → read the solution.

---

## 3. Design principles (hard constraints)

1. **Lightweight & one-command deploy.** `docker run …` (primary) or `npx …`
   (secondary). No external database, message broker, or cloud dependency.
2. **Self-contained & offline.** In-memory state + embedded SQLite. Must run with
   no internet access. No telemetry.
3. **Cross-platform.** Linux, macOS, Windows.
4. **Fast reset.** One action (restart, or a `reset` control) returns to a clean
   state. State lives in memory by default.
5. **Safe by default.** Bind `127.0.0.1`; loud warnings; no real secrets; the
   dangerous sinks (RCE, SSRF) are **contained** (run in the container; SSRF
   targets are simulated/internal, not the live internet). See §13.
6. **Attacker-tool agnostic.** Works with MCP Inspector, raw HTTP (Burp/curl),
   the official SDK clients, and stdio clients (Claude Desktop, Cursor).
7. **Small footprint.** Target a container image well under ~200 MB and a cold
   start under a few seconds.
8. **Difficulty is first-class.** Selecting Easy/Moderate/Difficult must be
   obvious, persistent, and visible at all times.

---

## 4. Recommended stack (rationale + allowed flexibility)

- **Primary: TypeScript + Node.js** with the official
  `@modelcontextprotocol/sdk`. Best SDK support for **all** primitives and both
  transports; trivial `npx` and Docker packaging.
- **Storage:** in-memory objects + **`node:sqlite`** (built-in, zero native
  deps) for the SQLi challenge.
- **HTTP host:** a minimal framework (Express/Fastify) for Streamable HTTP, the
  control panel, simulated-internal SSRF targets, and the OAuth lab.
- **Packaging:** multi-stage **Dockerfile** (primary), **`npx` bin** (secondary),
  optional single static binary (`bun build --compile` / `pkg`) as a stretch goal.
- **Allowed alternative:** Python + the official Python MCP SDK, if the builder
  prefers — but keep dependencies minimal and the one-command-deploy promise.
- Keep total dependencies small; every dependency must justify its weight against
  Principle #1.

---

## 5. Deployment & footprint requirements

- `docker run --rm -p 7332:7332 mcpgoat` → server live on `127.0.0.1:7332`.
- `npx mcpgoat` → same, without Docker.
- Optional `docker-compose.yml` that can also bring up the **stretch** victim-
  agent container and a second MCP server (for cross-server shadowing).
- Flags/env: `--level easy|moderate|difficult`, `--transport stdio|http|both`,
  `--port`, `--expose` (must be explicit to bind beyond loopback, with a printed
  warning), `--reset`.
- Provide **both transports**: `stdio` (for desktop-agent / client-trust attacks)
  and **Streamable HTTP** (for network attacks). Legacy HTTP+SSE optional.
- Document RAM/CPU expectations; enforce sane limits so DoS challenges can't take
  down the host.

---

## 6. MCP coverage — exercise the WHOLE protocol (not just tools)

Maximum coverage means hitting **every MCP primitive**, each as an attack
surface. The build must implement vulnerable scenarios across all of these and
fill in the **coverage matrix** below.

| MCP primitive / feature | Must demonstrate |
|---|---|
| **Tools** | Poisoning, shadowing, rug pull, hidden tools, injection sinks, excessive agency |
| **Resources** (static + templated) | Secret leakage, stored/indirect injection (RAG poisoning), path-templated traversal |
| **Prompts** (templates) | Prompt-template argument injection |
| **Sampling** (server→client LLM calls) | Context/secret exfiltration, attacker-controlled prompts, cost abuse |
| **Roots** | Over-broad filesystem roots → traversal/disclosure |
| **Completion** (argument autocomplete) | Injection / info leak via completion |
| **Logging** | Sensitive data in log notifications |
| **Notifications** (`listChanged`, progress) | Rug-pull signaling, notification flooding |
| **Transports** (stdio, Streamable HTTP, SSE) | Stdio injection, session hijack, SSE message injection, **DNS rebinding**, CORS |
| **Authorization** (OAuth 2.1) | Missing auth, audience confusion/token passthrough, redirect_uri/PKCE flaws |

> Deliverable: a filled **Primitive × Vulnerability coverage matrix** in the docs
> so reviewers can confirm nothing is missing.

---

## 7. Difficulty model (the core UX)

### 7.1 Selection mechanism (make it impossible to miss)

Provide **all** of these, all driving one shared "current level" state:

1. **Web control panel** at `GET /` — a level selector (Easy / Moderate /
   Difficult, plus optional **Secure**), current level badge, scoreboard link,
   reset button, and the MCP endpoint URL.
2. **MCP control tool** `mcpgoat_set_level({ level })` and `mcpgoat_get_level()` so
   the level can be changed from inside an MCP session.
3. **Startup config**: `--level` flag / `MCPGOAT_LEVEL` env.
4. **Per-request override** (optional): `X-MCPGoat-Level` header / per-session
   level for parallel testing.

The current level must be **persistent for the session** and **echoed
everywhere** (control panel badge, tool outputs, scoreboard). The
*same* vulnerability is implemented at every level — the tester sees the same
tool harden as they climb.

### 7.2 Level philosophy

- **Easy ("it's just there").** Single-step, no auth, no input filtering, verbose
  errors, inline hints in tool descriptions, the flag is returned directly.
  Teaches the **MCP mechanic** and the bug class. *(entry level.)*
- **Moderate ("naive defenses").** Light auth (static API key/token), **blacklist**
  input filtering that's bypassable (encoding, alternate payloads, case), 2–3 step
  **chaining**, semi-blind feedback, few hints. *(intermediate.)*
- **Difficult ("looks production-ish").** Strong-but-flawed defenses (an
  **allowlist with a gap**, OAuth with an **audience-validation** bug,
  parameterized everywhere **except one** path), **blind / time-based** only,
  multi-step chains **across primitives and/or servers**, no hints; requires
  recon and custom tooling. *(advanced.)*
- **(Optional) Secure ("Impossible").** The correct, unexploitable
  implementation, shipped as the **remediation reference** for each challenge.

### 7.3 General hardening ladder (apply per vulnerability)

| Dimension | Easy | Moderate | Difficult |
|---|---|---|---|
| Auth | none | static token (leakable) | OAuth/RBAC with a subtle flaw |
| Input filtering | none | blacklist (bypassable) | allowlist with a gap |
| Feedback | full output + errors | partial / reflected | blind / time-based |
| Steps to exploit | 1 | 2–3 chained | multi-step, cross-primitive |
| Hints | in description + scoreboard | scoreboard category only | none |
| Flag delivery | returned directly | requires assembling | requires full chain |

---

## 8. Vulnerability catalog (the meat — maximum test cases)

Implement the **Core set** first (a complete, shippable lab). Add the **Extended
set** for full breadth. Each challenge needs: a stable ID, a scoreboard entry
(category + difficulty stars), a `FLAG{...}`, the three level implementations,
and a solution + remediation doc.

### Category A — MCP-specific / agent-trust (the novel class)
| ID | Challenge | Primitive | What it tests | Set |
|----|-----------|-----------|---------------|-----|
| A1 | **Tool Poisoning** — hidden instructions in a tool description | Tools | Untrusted tool *metadata* steering the model | Core |
| A2 | **Tool Shadowing / cross-server override** — description redefines another server's tool | Tools | Trust between servers; name collision | Core |
| A3 | **Rug Pull / Tool Mutation (TOCTOU)** — benign at approval, hostile later | Tools + `listChanged` | Definition/behavior drift after consent | Core |
| A4 | **Line Jumping** — description poisons context *before* any tool is called | Tools | Pre-invocation context injection | Extended |
| A5 | **Confused Deputy** — server reuses its own privileged creds on attacker input | Tools/Auth | Authority confusion | Core |
| A6 | **Consent fatigue / "always allow" abuse** — silent re-scoping after approval | Tools | Approval-flow weakness | Extended |
| A7 | **Hidden / undocumented dangerous tool** — powerful tool absent from listings | Tools | Least-privilege / shadow surface | Core |
| A8 | **Parameter smuggling / exfil param** — extra "sidenote" arg exfiltrates context | Tools | Data exfiltration via schema | Core |
| A9 | **Invisible-text payloads** — Unicode/ANSI/zero-width hidden instructions | Tools/Resources | Steganographic injection | Extended |

### Category B — prompt & context manipulation
| ID | Challenge | Primitive | What it tests | Set |
|----|-----------|-----------|---------------|-----|
| B1 | **Indirect Prompt Injection via tool output** | Tools | Untrusted *data* driving actions | Core |
| B2 | **Indirect injection via resource content** | Resources | Stored injection in read content | Core |
| B3 | **Prompt-template injection** | Prompts | Args injected into a prompt template | Core |
| B4 | **Completion/autocomplete injection** | Completion | Injection/leak via argument completion | Extended |
| B5 | **Sampling abuse** — server-initiated LLM call exfiltrates context / runs attacker prompt | Sampling | The most-overlooked surface | Core |
| B6 | **System-prompt / context exfiltration** | Tools/Sampling | LLM07 system-prompt leakage | Core |
| B7 | **RAG / knowledge-base poisoning** | Resources | Poisoned retrieved content | Extended |

### Category C — authentication / authorization / OAuth
| ID | Challenge | Primitive | What it tests | Set |
|----|-----------|-----------|---------------|-----|
| C1 | **Missing authentication** on the MCP endpoint | Transport | Open privileged server | Core |
| C2 | **Broken authorization / no RBAC** on privileged tools | Tools | BFLA | Core |
| C3 | **IDOR** across tools/resources | Tools/Resources | BOLA | Core |
| C4 | **OAuth token audience confusion / passthrough** | Auth | MCP-specific token misuse | Core |
| C5 | **OAuth redirect_uri / PKCE / state flaws** | Auth | Classic OAuth bugs | Extended |
| C6 | **Session hijacking** — predictable Streamable-HTTP session IDs | Transport | Weak session generation | Core |
| C7 | **Session fixation** — session not bound to identity | Transport | Session binding | Extended |
| C8 | **Privilege escalation via tool chaining** | Tools | Compose low-priv tools → high-priv | Extended |

### Category D — injection into tool sinks (classic appsec, re-exposed)
| ID | Challenge | Primitive | What it tests | Set |
|----|-----------|-----------|---------------|-----|
| D1 | **Command Injection / RCE** | Tools | Shell sink | Core |
| D2 | **Path Traversal / arbitrary file read+write** | Tools/Roots | FS sink | Core |
| D3 | **SSRF** — internal services + simulated cloud metadata | Tools | Server-side fetch | Core |
| D4 | **SQL Injection** (UNION + blind) | Tools | DB sink | Core |
| D5 | **NoSQL injection** | Tools | Document-store sink | Extended |
| D6 | **SSTI** — server-side template injection | Tools | Template sink | Extended |
| D7 | **XXE** via XML resource parsing | Resources | XML parser | Extended |
| D8 | **Insecure deserialization** | Tools | Object sink | Extended |
| D9 | **XSS via tool output** rendered in a client UI | Tools | Output handling (LLM05) | Extended |

### Category E — secrets & data exposure
| ID | Challenge | Primitive | What it tests | Set |
|----|-----------|-----------|---------------|-----|
| E1 | **Secrets via resource** (env/config dump) | Resources | Sensitive disclosure (LLM02) | Core |
| E2 | **Hardcoded credentials** in tools | Tools | Embedded secrets | Extended |
| E3 | **Verbose errors** leak stack/paths/secrets | All | Info leak | Core |
| E4 | **Excessive data exposure** (over-returning) | Tools | BOPLA | Extended |
| E5 | **Sensitive data in logs / log notifications** | Logging | Log hygiene | Extended |

### Category F — transport & infrastructure
| ID | Challenge | Primitive | What it tests | Set |
|----|-----------|-----------|---------------|-----|
| F1 | **DNS Rebinding** — no `Origin` validation, binds 0.0.0.0 | Transport | Flagship local-MCP attack | Core |
| F2 | **CORS misconfiguration** | Transport | Browser-reachable server | Extended |
| F3 | **Cleartext transport / no TLS** | Transport | Eavesdropping | Extended |
| F4 | **Stdio message injection** | Transport (stdio) | Local IPC trust | Extended |
| F5 | **SSE / Streamable-HTTP message injection** | Transport | Stream tampering | Extended |

### Category G — DoS / cost / resource abuse
| ID | Challenge | Primitive | What it tests | Set |
|----|-----------|-----------|---------------|-----|
| G1 | **Unbounded tool loop / recursion** | Tools | Excessive agency (LLM06) | Core |
| G2 | **Token/cost amplification** via sampling or huge outputs | Sampling/Tools | Unbounded consumption (LLM10) | Core |
| G3 | **Memory exhaustion** — large read / zip bomb | Tools/Resources | Decompression bomb | Extended |
| G4 | **ReDoS** | Tools | Catastrophic regex | Extended |
| G5 | **No rate limiting / notification flooding** | Transport | Availability | Extended |

### Category H — supply chain / integrity
| ID | Challenge | Primitive | What it tests | Set |
|----|-----------|-----------|---------------|-----|
| H1 | **Typosquatted / malicious server package** (simulated) | Install | Supply chain (LLM03) | Extended |
| H2 | **Unsigned / unpinned tool definitions** — integrity not verified | Tools | Definition integrity | Extended |
| H3 | **Remote-fetch-on-install code execution** (npx-style, simulated) | Install | Install-time RCE | Extended |

**Core set ≈ 22 challenges; full catalog ≈ 45.** Ship Core first as a complete
experience, then layer Extended.

---

## 9. Worked difficulty-scaling examples (build to this pattern)

**D1 Command Injection**
- *Easy:* `network_ping` runs `ping -c1 ${host}` in a shell, full output. Payload
  `127.0.0.1; cat /flag`.
- *Moderate:* blacklist strips `;` and `&&`; bypass with `$(...)`, newline, or
  `|`. Output partially reflected.
- *Difficult:* allowlist permits only `[a-z0-9.-]` **but** the value is later used
  unquoted in a second `eval`-like path; **blind** — exfil via time delay or
  out-of-band to the simulated internal collector.

**D3 SSRF**
- *Easy:* `fetch_url` fetches anything; hit `http://127.0.0.1/internal` or
  `169.254.169.254`.
- *Moderate:* blocks `127.0.0.1`/`localhost` by string; bypass with
  `2130706433`, `[::1]`, `0.0.0.0`, or a `metadata.internal` alias.
- *Difficult:* resolves+checks the host against a denylist **once**, then
  re-fetches → **DNS-rebinding** TOCTOU; **blind** SSRF confirmed only via the
  internal collector's callback log.

**A1 Tool Poisoning**
- *Easy:* the `<IMPORTANT>` block is plainly in the description.
- *Moderate:* payload hidden in a less-read field (annotations / a nested schema
  `description`).
- *Difficult:* payload is **zero-width/Unicode-encoded** and only *activates*
  under a trigger phrase (conditional poisoning) — must diff raw bytes.

**C2/C4 Broken Auth**
- *Easy:* admin tool exposed, no token.
- *Moderate:* static admin token, but it's leaked by the env **resource** (cross-
  challenge chain).
- *Difficult:* OAuth-gated, but the server **doesn't validate token `aud`** →
  replay a token minted for another resource (token passthrough / confused deputy).

---

## 10. Scoreboard, flags & progress

- **Scoreboard** page + an MCP tool `scoreboard()`: lists every challenge with
  **category**, **difficulty stars**, **solved/unsolved**, and the **current
  level**. Filter by category/level. Hints togglable per level (§7.3).
- **Flags:** format `FLAG{...}`, unique per challenge. A `submit_flag(flag)` tool
  validates, records, and returns updated progress. (For challenges where the
  "win" is an action, accept a proof artifact instead of a static string.)
- **Reset:** `mcpgoat_reset()` control tool + control-panel button.
- **Optional CTF mode:** timer, points weighted by difficulty, exportable JSON
  results for a class/leaderboard.

---

## 11. Architecture & repository layout

```
mcpgoat/
├── Dockerfile  docker-compose.yml  package.json  README.md
├── src/
│   ├── server.ts              # transports (stdio + Streamable HTTP), control panel
│   ├── level.ts               # current-level state + selection plumbing
│   ├── scoreboard.ts          # flags, progress, reset
│   ├── primitives/            # registration per MCP primitive
│   │   ├── tools.ts  resources.ts  prompts.ts  sampling.ts  roots.ts
│   ├── challenges/            # ONE module per challenge ID (A1, B5, D3, …)
│   │   └── <id>.ts            # exports easy()/moderate()/difficult()/secure()
│   ├── internal/             # simulated SSRF targets, metadata, OOB collector
│   └── oauth/                # the OAuth lab (authz server + protected resource)
├── attacker/                 # reference exploit client per challenge (also the smoke test)
├── data/ workspace/ vault/   # seed data + planted secrets
└── docs/
    ├── PLAYER_GUIDE.md  SOLUTIONS.md  REMEDIATION.md
    ├── COVERAGE_MATRIX.md   # primitive × vuln × level, all filled
    └── MAPPINGS.md          # LLM / API / MITRE ATLAS / CWE
```

Each challenge module exposing `easy/moderate/difficult/secure` is the key
abstraction — it makes the level switch a per-challenge dispatch and keeps the
secure reference next to the vulnerable code.

---

## 12. Documentation deliverables

1. **Player guide** — deploy, pick a level, connect each tool (Inspector/curl/
   client/stdio), challenge list with hints, scoreboard.
2. **Solutions** — per challenge **per level**: exploit + payloads + expected flag.
3. **Remediation** — the secure pattern for each (tie to the Secure level).
4. **Coverage matrix** — primitive × vulnerability × level, fully filled.
5. **Framework mappings** — see §16.
6. **Deployment guide** — Docker/npx/binary, flags, isolation guidance.

---

## 13. Safety, ethics & guardrails (mandatory)

- **Bind `127.0.0.1` by default.** Exposing beyond loopback requires an explicit
  `--expose` flag **and** prints a bold warning banner.
- **Contain the dangerous sinks.** RCE/file-write challenges must be designed to
  run inside the **container**; document "run in Docker, not on bare metal."
- **No live-internet SSRF.** SSRF/fetch targets are **simulated internal**
  services and a fake metadata endpoint, not arbitrary outbound to the real web
  (or gate real outbound behind an explicit opt-in flag).
- **No real secrets.** All planted credentials/keys are obviously fake.
- **Loud "intentionally vulnerable" banners** on the control panel, README, and
  server startup; an authorized-use notice.
- **Reset & ephemerality.** Default state is in-memory; nothing persists secrets
  to the host.
- **No auto-exploitation of third parties.** The reference attacker client only
  targets the lab's own endpoint.

---

## 14. Acceptance criteria (definition of done)

- [ ] **One-command deploy** works on Linux/macOS/Windows (`docker run` and `npx`).
- [ ] **Both transports** (stdio + Streamable HTTP) functional.
- [ ] **Level switch** works from control panel, control tool, and env/flag, and
      is reflected everywhere; the *same* challenge visibly hardens across levels.
- [ ] **Core set** challenges all implemented at **all three levels** with flags.
- [ ] **Every MCP primitive** in §6 has at least one challenge (matrix filled).
- [ ] **Scoreboard + submit_flag + reset** work.
- [ ] Works with **MCP Inspector**, **curl/Burp**, the **SDK client**, and a
      **stdio** client.
- [ ] **Reference attacker client** auto-solves the Core set (doubles as CI
      regression).
- [ ] **Docs** (player, solutions, remediation, coverage, mappings) complete.
- [ ] **Guardrails** in §13 all present.

---

## 15. Stretch goals

- **Victim-agent harness** — a real LLM agent wired to the lab so testers can
  *prove* prompt-injection / excessive-agency impact end-to-end (not just read a
  flag). Ship with a local/free model option to keep it offline.
- **Multi-server scenario** — a second MCP server so **cross-server tool
  shadowing** (A2) is real, not simulated.
- **Full OAuth lab** — standalone authz server + protected resource for C4/C5.
- **Single static binary** distribution.
- **Progressive hint system** and **leaderboard/CTF export**.
- **"Secure/Impossible" level** completed for every challenge.

---

## 16. Framework mappings (include in docs)

- **Top 10 for LLM Applications (2025):** LLM01 Prompt Injection (A1–A9,
  B*), LLM02 Sensitive Information Disclosure (E*), LLM03 Supply Chain (H*),
  LLM04 Data/Model Poisoning (B2/B7), LLM05 Improper Output Handling (D9),
  LLM06 Excessive Agency (A5–A7, C8, G1), LLM07 System-Prompt Leakage (B6),
  LLM08 Vector/Embedding Weaknesses (B7), LLM10 Unbounded Consumption (G*).
- **API Security Top 10 (2023):** API1 BOLA (C3), API2 Broken Auth (C1/C6/
  C7), API3 BOPLA (E4), API5 BFLA (C2), API7 SSRF (D3), API8 Misconfiguration
  (F2/F3).
- **MITRE ATLAS** — map each prompt-injection/exfiltration challenge to the
  relevant ATLAS tactics/techniques.
- **CWE** — tag each challenge (e.g., CWE-78 D1, CWE-22 D2, CWE-918 D3, CWE-89
  D4, CWE-94 H3, CWE-200 E*, CWE-639 C3).

---

### One-paragraph summary to lead the build with
> Build "MCPGoat": a single-command, offline, localhost-bound MCP
> server in TypeScript (official SDK, stdio + Streamable HTTP) that re-implements
> ~22 core (and up to ~45 total) MCP vulnerabilities — spanning tool poisoning,
> rug pulls, indirect prompt injection, sampling abuse, OAuth/token confusion,
> RCE/SSRF/SQLi/path-traversal tool sinks, DNS rebinding, secret-leaking
> resources, and DoS/cost abuse — each implemented at **Easy / Moderate /
> Difficult** (plus an optional Secure reference) behind a tiered level
> switch, with a capture-the-flag scoreboard, flags, a reference attacker client
> that auto-solves the core set, full per-primitive coverage, mandatory safety
> guardrails, and complete player/solution/remediation/coverage/mapping docs.
