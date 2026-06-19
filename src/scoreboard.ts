/**
 * scoreboard.ts — challenge catalog, per-(challenge,level) flags, and the
 * capture-the-flag scoreboard that tracks what's been captured.
 *
 * Every challenge is implemented at three levels (easy/moderate/difficult);
 * each (challenge, level) pair has its own unique flag, so the scoreboard
 * tracks progress per level.
 */

import { ScoredLevel, LEVELS } from "./level.js";

/** Deterministic, unique flag for a (challenge, level) pair. */
export function flag(slug: string, level: ScoredLevel): string {
  return `FLAG{${slug}__${level}}`;
}

export interface ChallengeMeta {
  id: string; // catalog id, e.g. "A1"
  slug: string;
  title: string;
  category: string;
  stars: 1 | 2 | 3; // intrinsic difficulty rating
  /** Non-spoiler hint per level. Difficult is intentionally terse/empty. */
  hints: Record<ScoredLevel, string>;
}

export const CHALLENGES: ChallengeMeta[] = [
  {
    id: "A1",
    slug: "tool-poisoning",
    title: "Tool Poisoning",
    category: "MCP-specific",
    stars: 2,
    hints: {
      easy: "Dump the RAW tool descriptions. add_numbers hides more than math.",
      moderate: "The payload moved somewhere the human reviewer reads even less than the description.",
      difficult: "",
    },
  },
  {
    id: "A2",
    slug: "tool-shadowing",
    title: "Tool Shadowing / Trusted-Tool Override",
    category: "MCP-specific",
    stars: 2,
    hints: {
      easy: "Read send_email's full description — it tries to govern other tools.",
      moderate: "The override policy is split across the tool's metadata fields.",
      difficult: "",
    },
  },
  {
    id: "A3",
    slug: "rug-pull",
    title: "Rug Pull / Tool Mutation (TOCTOU)",
    category: "MCP-specific",
    stars: 3,
    hints: {
      easy: "get_weather is friendly at first. Keep calling it.",
      moderate: "It only betrays a city it has seen before.",
      difficult: "",
    },
  },
  {
    id: "B1",
    slug: "indirect-prompt-injection",
    title: "Indirect Prompt Injection via Tool Output",
    category: "Prompt/Context",
    stars: 2,
    hints: {
      easy: "read_inbox returns untrusted data. One message tells the agent what to do next.",
      moderate: "The injected instruction includes a token you must echo back.",
      difficult: "",
    },
  },
  {
    id: "D1",
    slug: "command-injection",
    title: "Command Injection (RCE)",
    category: "Injection sink",
    stars: 1,
    hints: {
      easy: "network_ping shells out with no filtering.",
      moderate: "';' and '&' are filtered. Other shells metacharacters are not.",
      difficult: "",
    },
  },
  {
    id: "D2",
    slug: "path-traversal",
    title: "Path Traversal / Arbitrary File Read",
    category: "Injection sink",
    stars: 1,
    hints: {
      easy: "read_project_file is rooted at ./workspace. The vault is one dir up.",
      moderate: "'../' is stripped — once.",
      difficult: "",
    },
  },
  {
    id: "D3",
    slug: "ssrf",
    title: "Server-Side Request Forgery",
    category: "Injection sink",
    stars: 2,
    hints: {
      easy: "fetch_url will fetch internal services and cloud metadata.",
      moderate: "It blocks 'localhost'/'127.0.0.1'/'169.254' as strings. An internal alias (metadata.internal) or IPv6 (::1) still reaches inside.",
      difficult: "",
    },
  },
  {
    id: "D4",
    slug: "sql-injection",
    title: "SQL Injection",
    category: "Injection sink",
    stars: 2,
    hints: {
      easy: "search_products concatenates input into a LIKE clause. UNION away.",
      moderate: "'UNION' (exact case) and '--' are blacklisted.",
      difficult: "",
    },
  },
  {
    id: "C2",
    slug: "broken-authorization",
    title: "Broken Authorization / Confused Deputy",
    category: "AuthN/AuthZ",
    stars: 2,
    hints: {
      easy: "admin_get_all_secrets is exposed with no real check.",
      moderate: "It wants a token that is leaked elsewhere in the lab.",
      difficult: "",
    },
  },
  {
    id: "C3",
    slug: "idor",
    title: "Insecure Direct Object Reference",
    category: "AuthN/AuthZ",
    stars: 1,
    hints: {
      easy: "get_invoice never checks ownership. Try id 1003.",
      moderate: "It now trusts a user_id you supply.",
      difficult: "",
    },
  },
  {
    id: "E1",
    slug: "secrets-exposure",
    title: "Sensitive Data Exposure",
    category: "Secrets/Exposure",
    stars: 1,
    hints: {
      easy: "List MCP resources and read the server environment.",
      moderate: "Values are redacted — but not in every resource.",
      difficult: "",
    },
  },
  {
    id: "A9",
    slug: "invisible-text",
    title: "Invisible-Text Tool Poisoning",
    category: "MCP-specific",
    stars: 3,
    hints: {
      easy: "format_text's description hides a payload past a wall of whitespace.",
      moderate: "Normalize the description — zero-width characters are splitting the flag.",
      difficult: "",
    },
  },
  {
    id: "B2",
    slug: "resource-injection",
    title: "Indirect Injection via Resource Content",
    category: "Prompt/Context",
    stars: 2,
    hints: {
      easy: "Read the mcpgoat://notes/shared resource — its content tells the agent what to do.",
      moderate: "The injected instruction carries a confirmation token to echo.",
      difficult: "",
    },
  },
  {
    id: "B3",
    slug: "prompt-injection-template",
    title: "Prompt-Template Injection",
    category: "Prompt/Context",
    stars: 2,
    hints: {
      easy: "The triage_ticket prompt trusts your argument. Inject an [[admin]] marker.",
      moderate: "Try a markdown-style role header inside the argument.",
      difficult: "",
    },
  },
  {
    id: "B5",
    slug: "sampling-abuse",
    title: "Sampling Abuse (server-driven LLM calls)",
    category: "MCP-specific",
    stars: 3,
    hints: {
      easy: "ai_summarize makes the SERVER call your model via MCP sampling. Inspect what it sends.",
      moderate: "The payload rides in the sampling request's system prompt.",
      difficult: "",
    },
  },
  {
    id: "C4",
    slug: "token-audience",
    title: "OAuth Token-Audience Confusion",
    category: "AuthN/AuthZ",
    stars: 3,
    hints: {
      easy: "call_partner_api forwards your bearer with no checks at all.",
      moderate: "It never validates the token's audience — present one minted for another service.",
      difficult: "",
    },
  },
  {
    id: "D6",
    slug: "ssti",
    title: "Server-Side Template Injection",
    category: "Injection sink",
    stars: 2,
    hints: {
      easy: "render_template evaluates {{ expressions }}. A `config` object is in scope.",
      moderate: "'config' is filtered. Build the property name another way.",
      difficult: "",
    },
  },
  {
    id: "F1",
    slug: "dns-rebinding",
    title: "DNS Rebinding / Missing Origin Validation",
    category: "Transport",
    stars: 3,
    hints: {
      easy: "GET /api/browser-bridge with an Origin header — the local server doesn't check who's calling.",
      moderate: "It allows any Origin containing 'localhost'. Register a domain that does.",
      difficult: "",
    },
  },
  {
    id: "F2",
    slug: "cors",
    title: "CORS Misconfiguration",
    category: "Transport",
    stars: 2,
    hints: {
      easy: "GET /api/cors-data — it reflects any Origin with credentials. Check the ACAO header.",
      moderate: "It reflects Origins matching 'trusted.example' — but the match isn't anchored.",
      difficult: "",
    },
  },
  {
    id: "C6",
    slug: "session-prediction",
    title: "Predictable Session IDs (hijack)",
    category: "Transport",
    stars: 2,
    hints: {
      easy: "GET /api/session/me to see your id scheme, then GET /api/session/<id>. The admin's is guessable.",
      moderate: "Your session id decodes to a counter. The admin came first.",
      difficult: "",
    },
  },
  {
    id: "G1",
    slug: "unbounded-consumption",
    title: "Unbounded Consumption (cost/DoS)",
    category: "DoS/Cost",
    stars: 2,
    hints: {
      easy: "compute_report has no limit on how much work you can ask for.",
      moderate: "Some fields are capped — but not all of them.",
      difficult: "",
    },
  },
  {
    id: "G4",
    slug: "redos",
    title: "Regular-Expression DoS (ReDoS)",
    category: "DoS/Cost",
    stars: 2,
    hints: {
      easy: "validate_pattern uses a catastrophic-backtracking regex. Feed it input that won't match.",
      moderate: "Still backtracks — a different vulnerable pattern.",
      difficult: "",
    },
  },
  {
    id: "D5",
    slug: "nosql-injection",
    title: "NoSQL Injection",
    category: "Injection sink",
    stars: 2,
    hints: {
      easy: "user_lookup takes a raw JSON filter. Operators like {\"$ne\":\"\"} aren't strings.",
      moderate: "$ne / $gt are blacklisted. Other operators match everything too.",
      difficult: "",
    },
  },
  {
    id: "D7",
    slug: "xxe",
    title: "XML External Entity (XXE)",
    category: "Injection sink",
    stars: 3,
    hints: {
      easy: "parse_invoice_xml resolves DOCTYPE entities. SYSTEM can read a local file.",
      moderate: "Local file URIs are blocked — but an http SYSTEM entity still fires server-side.",
      difficult: "",
    },
  },
  {
    id: "D8",
    slug: "deserialization",
    title: "Insecure Deserialization (prototype pollution)",
    category: "Injection sink",
    stars: 3,
    hints: {
      easy: "load_session merges your token into an object. Pollute the prototype with __proto__.",
      moderate: "__proto__ is filtered. constructor.prototype reaches the same place.",
      difficult: "",
    },
  },
  {
    id: "H1",
    slug: "supply-chain",
    title: "Supply Chain (typosquat / unsigned package)",
    category: "Supply chain",
    stars: 2,
    hints: {
      easy: "install_plugin verifies nothing. Install a typosquatted package.",
      moderate: "It checks a signature — but the scheme is a guessable md5(name).",
      difficult: "",
    },
  },
];

const META_BY_SLUG = new Map(CHALLENGES.map((c) => [c.slug, c]));

export function metaFor(slug: string): ChallengeMeta | undefined {
  return META_BY_SLUG.get(slug);
}

/** Reverse a flag string back to its (slug, level). */
export function identifyFlag(value: string): { slug: string; level: ScoredLevel } | undefined {
  const m = value.trim().match(/^FLAG\{(.+?)__(.+?)\}$/);
  if (!m) return undefined;
  const [, slug, level] = m;
  if (!META_BY_SLUG.has(slug) || !(LEVELS as string[]).includes(level)) return undefined;
  return { slug, level: level as ScoredLevel };
}

/* --------------------------- scoreboard state ----------------------- */

const captured = new Set<string>(); // keys: `${slug}:${level}`
const key = (slug: string, level: ScoredLevel) => `${slug}:${level}`;

export function captureFlag(slug: string, level: ScoredLevel): void {
  captured.add(key(slug, level));
}
export function isCaptured(slug: string, level: ScoredLevel): boolean {
  return captured.has(key(slug, level));
}
export function resetScoreboard(): void {
  captured.clear();
}

/** Full scoreboard view, optionally focused on one level. */
export function scoreboardView(level?: ScoredLevel) {
  const levels = level ? [level] : LEVELS;
  const rows = CHALLENGES.map((c) => ({
    id: c.id,
    slug: c.slug,
    title: c.title,
    category: c.category,
    stars: c.stars,
    solved: Object.fromEntries(levels.map((l) => [l, isCaptured(c.slug, l)])),
  }));
  const total = CHALLENGES.length * levels.length;
  const solved = rows.reduce(
    (n, r) => n + Object.values(r.solved).filter(Boolean).length,
    0
  );
  return { focusScoredLevel: level ?? "all", solved, total, challenges: rows };
}
