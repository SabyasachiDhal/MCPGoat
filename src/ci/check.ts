/**
 * ci/check.ts — regression gate.
 *
 * Boots the server on an isolated port, then asserts:
 *   • attacker `all`     captures every scored flag   (CHALLENGES × 3)
 *   • attacker `secure`  blocks every exploit          (CHALLENGES, 0 leaked)
 *   • agent  (naive)     is compromised in every scenario
 *   • agent  --defended  is compromised in none
 *
 * Expected counts derive from the catalog, so adding a challenge can't silently
 * leave the gate asserting a stale number — but a challenge that STOPS working
 * (or a fix that springs a leak) fails the gate. Exit code is non-zero on any
 * failure.  Run:  npm run ci
 */

import { spawn, type ChildProcess } from "node:child_process";
import { CHALLENGES } from "../scoreboard.js";

const PORT = Number(process.env.CI_PORT ?? 7399);
const BASE = `http://127.0.0.1:${PORT}`;
const MCP = `${BASE}/mcp`;
const SCORED = CHALLENGES.length * 3;
const BLOCKED = CHALLENGES.length;

const failures: string[] = [];
function check(name: string, ok: boolean, detail: string) {
  console.log(`  ${ok ? "✓ PASS" : "✗ FAIL"}  ${name.padEnd(18)} — ${detail}`);
  if (!ok) failures.push(name);
}

function run(args: string[]): Promise<{ code: number; out: string }> {
  return new Promise((resolve) => {
    const p = spawn("npx", ["tsx", ...args], {
      env: { ...process.env, NODE_NO_WARNINGS: "1" },
    });
    let out = "";
    p.stdout?.on("data", (d) => (out += d));
    p.stderr?.on("data", (d) => (out += d));
    p.on("close", (code) => resolve({ code: code ?? 0, out }));
  });
}

async function waitForServer(ms = 25000): Promise<boolean> {
  const start = Date.now();
  while (Date.now() - start < ms) {
    try {
      const r = await fetch(`${BASE}/api/state`, { signal: AbortSignal.timeout(1500) });
      if (r.ok) return true;
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 300));
  }
  return false;
}

async function main() {
  console.log(`MCPGoat regression gate — expecting scored=${SCORED}, blocked=${BLOCKED}\n`);
  const server: ChildProcess = spawn("npx", ["tsx", "src/server.ts"], {
    detached: true, // own process group, so we can kill npx→tsx→node together
    env: { ...process.env, PORT: String(PORT), HOST: "127.0.0.1", NODE_NO_WARNINGS: "1", MCPGOAT_LEVEL: "easy" },
  });
  let serverLog = "";
  server.stdout?.on("data", (d) => (serverLog += d));
  server.stderr?.on("data", (d) => (serverLog += d));

  try {
    if (!(await waitForServer())) {
      console.error("server did not start:\n" + serverLog);
      process.exit(1);
    }

    // 1) scored levels — every flag captured (read the authoritative scoreboard).
    await run(["src/attacker/client.ts", MCP, "all"]);
    const state: any = await (await fetch(`${BASE}/api/state`)).json();
    check("attacker all", state?.scoreboard?.solved === SCORED, `solved ${state?.scoreboard?.solved}/${SCORED}`);

    // 2) secure level — everything blocked, nothing leaks. (This resets the scoreboard.)
    const sec = await run(["src/attacker/client.ts", MCP, "secure"]);
    const ms = sec.out.match(/LEVEL SECURE:\s*(\d+)\/(\d+) attacks BLOCKED/);
    const leaked = /leaked/.test(sec.out);
    check(
      "attacker secure",
      !!ms && ms[1] === String(BLOCKED) && ms[2] === String(BLOCKED) && !leaked,
      ms ? `${ms[1]}/${ms[2]} blocked${leaked ? "  (LEAK!)" : ""}` : "no summary line"
    );

    // 3) victim agent (naive) — compromised in every scenario.
    const naive = await run(["src/agent/agent.ts", "--url", MCP]);
    const mn = naive.out.match(/RESULT:\s*(\d+)\/(\d+) scenarios compromised the NAIVE/);
    check("agent naive", !!mn && +mn[1] > 0 && mn[1] === mn[2], mn ? `${mn[1]}/${mn[2]} compromised` : "no summary line");

    // 4) victim agent (defended) — compromised in none.
    const def = await run(["src/agent/agent.ts", "--url", MCP, "--defended"]);
    const md = def.out.match(/RESULT:\s*(\d+)\/(\d+) scenarios compromised the DEFENDED/);
    check("agent defended", !!md && md[1] === "0", md ? `${md[1]}/${md[2]} compromised` : "no summary line");
  } finally {
    // Kill the whole process group (npx → tsx → node), not just the npx parent.
    if (server.pid) {
      try {
        process.kill(-server.pid, "SIGKILL");
      } catch {
        server.kill("SIGKILL");
      }
    }
  }

  console.log("");
  if (failures.length) {
    console.error(`REGRESSION GATE FAILED: ${failures.join(", ")}`);
    process.exit(1);
  }
  console.log("REGRESSION GATE PASSED ✓");
  process.exit(0);
}

main().catch((e) => {
  console.error("ci error:", e);
  process.exit(1);
});
