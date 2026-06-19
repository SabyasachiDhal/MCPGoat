/**
 * db.ts — in-memory SQLite for the SQL-injection challenge, level-aware.
 *
 *   easy      -> string-built query, rows + verbose errors returned (UNION)
 *   moderate  -> naive blacklist (UNION / -- / ; / comments), still injectable
 *   difficult -> boolean-blind: only a match COUNT is returned, no rows/errors
 *
 * Uses Node's built-in node:sqlite (no native deps); degrades gracefully if
 * the runtime lacks it.
 */

import { ScoredLevel } from "./level.js";
import { flag } from "./scoreboard.js";

type Row = Record<string, unknown>;

interface Handle {
  all(sql: string): Row[];
  safeSearch(term: string): Row[];
}

let handle: Handle | null = null;
let initError: string | null = null;

try {
  const { DatabaseSync } = await import("node:sqlite");
  const db = new DatabaseSync(":memory:");
  db.exec(`
    CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL);
    CREATE TABLE secrets  (id INTEGER PRIMARY KEY, name TEXT, secret TEXT);
  `);
  const ip = db.prepare("INSERT INTO products (id,name,price) VALUES (?,?,?)");
  ip.run(1, "Blue Widget", 9.99);
  ip.run(2, "Red Widget", 14.5);
  ip.run(3, "Green Gadget", 29.0);
  ip.run(4, "Yellow Gizmo", 4.25);
  const is = db.prepare("INSERT INTO secrets (id,name,secret) VALUES (?,?,?)");
  is.run(1, "db_root_password", "hunter2-do-not-share");
  is.run(2, "ctf_flag_easy", flag("sql-injection", "easy"));
  is.run(3, "ctf_flag_moderate", flag("sql-injection", "moderate"));
  is.run(4, "ctf_flag_difficult", flag("sql-injection", "difficult"));
  handle = {
    all: (sql) => db.prepare(sql).all() as Row[],
    // Parameterized — the secure reference. Only ever returns products.
    safeSearch: (term) =>
      db.prepare("SELECT id, name, price FROM products WHERE name LIKE ?").all(`%${term}%`) as Row[],
  };
} catch (err) {
  initError =
    "node:sqlite unavailable (need Node 22.5+). " + (err as Error).message;
}

const BLACKLIST = [/UNION/, /--/, /;/, /\/\*/]; // case-sensitive on purpose

export interface SearchResult {
  level: ScoredLevel;
  sql?: string;
  rows?: Row[];
  count?: number;
  blocked?: boolean;
  error?: string;
}

export function searchProducts(term: string, level: ScoredLevel): SearchResult {
  if (!handle) return { level, error: initError ?? "db unavailable" };

  if (level === "difficult") {
    // Boolean-blind: only the match count comes back; errors are swallowed so
    // true/false is the ONLY signal.
    const sql = `SELECT count(*) AS n FROM products WHERE name LIKE '%${term}%'`;
    try {
      const n = Number((handle.all(sql)[0]?.n as number) ?? 0);
      return { level, count: n };
    } catch {
      return { level, count: 0 };
    }
  }

  if (level === "moderate" && BLACKLIST.some((re) => re.test(term))) {
    return { level, blocked: true, error: "input rejected by WAF" };
  }

  const sql = `SELECT id, name, price FROM products WHERE name LIKE '%${term}%'`;
  try {
    return { level, sql, rows: handle.all(sql) };
  } catch (err) {
    // Verbose errors (easy/moderate) are themselves a leak.
    return { level, sql, error: `SQL error: ${(err as Error).message}` };
  }
}

/** Secure reference: parameterized, returns only products, never secrets. */
export function searchProductsSafe(term: string): { secure: true; rows?: Row[]; error?: string } {
  if (!handle) return { secure: true, error: initError ?? "db unavailable" };
  return { secure: true, rows: handle.safeSearch(term) };
}
