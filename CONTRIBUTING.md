# Contributing to MCPGoat

Thanks for your interest! Contributions — new challenges, fixes, docs, better
tooling — are very welcome. By contributing, you agree that your work is licensed
under the project's [MIT License](LICENSE).

## Setup

```bash
npm install
npm start                                          # http://127.0.0.1:7332
npm run attack -- http://127.0.0.1:7332/mcp all    # solve every challenge
npm run ci                                         # the regression gate
```

## Ground rules

- **Keep `npm run ci` green.** It asserts every challenge works at every level
  (78/78), the secure level blocks everything (26/26), and the victim agent is
  3/3 (naive) / 0/3 (defended). Run it before opening a PR.
- **`npx tsc --noEmit` must pass** — no type errors.
- Match the existing style: small, dependency-light, TypeScript + the official
  MCP SDK. No new heavy dependencies without a good reason.

## Adding a challenge

1. Add an entry to `src/scoreboard.ts` (`CHALLENGES`) — id, slug, category,
   stars, and per-level hints.
2. Implement the tool(s)/resource(s) in `src/challenges.ts` at **all four**
   levels: `easy`, `moderate`, `difficult`, and a **`secure`** reference where
   the exploit must fail.
3. Add a solver to `src/attacker/client.ts` so the CI gate covers it.
4. Document the exploit + the fix in `docs/SOLUTIONS.md`.

## Good first issues

- Extended challenges from [`DESIGN_PROMPT.md`](DESIGN_PROMPT.md) not yet built
  (line jumping, consent fatigue, completion injection, a full OAuth lab).
- A `stdio` transport build (for Claude Desktop / Cursor client-trust testing).
- More victim-agent scenarios, or additional local LLM backends.

## Reporting

- Bugs in the **harness** (not the deliberate challenges): see
  [`SECURITY.md`](SECURITY.md).
- Ideas and questions: open a GitHub issue.
