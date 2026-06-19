/**
 * state.ts — seed data and constants shared by the challenges.
 * (Difficulty logic lives in challenges.ts; scoreboard/flags in scoreboard.ts.)
 */

import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const LAB_ROOT = path.resolve(__dirname, "..");
export const WORKSPACE_DIR = path.join(LAB_ROOT, "workspace");
export const VAULT_DIR = path.join(LAB_ROOT, "vault");

/** Static admin token (Moderate authz). Leaked by the env resource. */
export const ADMIN_TOKEN = "adm_7f3c1e9a-leaked-via-env-resource";
/** HMAC-ish secret for the Difficult challenge-response authz. Leaked via a debug resource. */
export const AUTHZ_SIGNING_SECRET = "s1gn1ng-secret-rotate-me";

export interface User {
  id: number;
  username: string;
  role: "user" | "admin";
}
export interface Invoice {
  id: number;
  ownerId: number;
  amount: number;
  memo: string;
}

/** The notional caller. Low privilege on purpose. */
export const CURRENT_USER: User = { id: 1001, username: "alice", role: "user" };

export const USERS: User[] = [
  { id: 1001, username: "alice", role: "user" },
  { id: 1002, username: "bob", role: "user" },
  { id: 1003, username: "root_admin", role: "admin" },
];

export const INVOICES: Invoice[] = [
  { id: 1001, ownerId: 1001, amount: 42.5, memo: "Alice: coffee subscription" },
  { id: 1002, ownerId: 1002, amount: 19.99, memo: "Bob: parking" },
  { id: 1003, ownerId: 1003, amount: 999999, memo: "root_admin: offsite payroll" },
];

/**
 * Difficult-IDOR per-object capability token. Looks opaque, is actually just
 * base64("inv:<id>") — a predictable "direct object reference" the attacker
 * can forge for any invoice id.
 */
export function invoiceAccessToken(id: number): string {
  return Buffer.from(`inv:${id}`).toString("base64");
}
