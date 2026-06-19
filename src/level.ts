/**
 * level.ts — the tiered difficulty switch.
 *
 * Four selectable levels. The first three are *scored* (each challenge has a
 * flag); "secure" is the fixed, unexploitable reference where every documented
 * exploit should fail — there are no flags to capture there.
 */

export type Level = "easy" | "moderate" | "difficult" | "secure";
/** The three attackable/scored levels (secure has no flags). */
export type ScoredLevel = Exclude<Level, "secure">;

export const LEVELS: ScoredLevel[] = ["easy", "moderate", "difficult"];
export const SELECTABLE_LEVELS: Level[] = ["easy", "moderate", "difficult", "secure"];

export const LEVEL_LABELS: Record<Level, string> = {
  easy: "Easy",
  moderate: "Moderate",
  difficult: "Difficult",
  secure: "Secure",
};

export const LEVEL_BLURB: Record<Level, string> = {
  easy: "No auth, no filtering, single step, verbose output. Learn the mechanic.",
  moderate: "Light auth, bypassable blacklists, 2–3 step chains. Bypass naive defenses.",
  difficult: "Strong-but-flawed defenses, blind/OOB feedback, multi-step chains. No hints.",
  secure: "The fixed reference implementation. Every attack here should fail.",
};

function coerce(value: string | undefined): Level {
  const v = (value ?? "").toLowerCase().trim();
  return (SELECTABLE_LEVELS as string[]).includes(v) ? (v as Level) : "easy";
}

let current: Level = coerce(process.env.MCPGOAT_LEVEL);

export function getLevel(): Level {
  return current;
}

export function setLevel(next: string): Level {
  current = coerce(next);
  return current;
}

export function isLevel(value: string): value is Level {
  return (SELECTABLE_LEVELS as string[]).includes(value);
}
