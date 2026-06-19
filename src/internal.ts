/**
 * internal.ts — the simulated "internal network" the attacker can only reach
 * through the server (SSRF), plus an out-of-band (OOB) collector used by the
 * blind Difficult challenges to receive exfiltrated data.
 */

export interface CollectorEntry {
  channel: string;
  data: string;
  seq: number;
}

let seq = 0;
const entries: CollectorEntry[] = [];

/** Record an exfiltrated value (from command-injection / blind SSRF). */
export function collect(channel: string, data: string): void {
  seq += 1;
  entries.push({ channel, data, seq });
}

/** Read captured OOB data, optionally filtered by channel. */
export function readCollector(channel?: string): CollectorEntry[] {
  return channel ? entries.filter((e) => e.channel === channel) : [...entries];
}

export function clearCollector(): void {
  entries.length = 0;
  seq = 0;
}

/**
 * Normalize the many spellings of an IP/host to a canonical token, so the
 * Moderate SSRF filter (which only blocks literal strings) can be bypassed
 * with decimal/hex/short forms — deterministically, without real DNS.
 */
export function normalizeHost(host: string): string {
  const h = host.toLowerCase().replace(/^\[|\]$/g, "");
  const loopback = new Set([
    "localhost",
    "127.0.0.1",
    "127.1",
    "127.0.1",
    "0.0.0.0",
    "0",
    "::1",
    "2130706433", // decimal 127.0.0.1
    "0x7f000001", // hex 127.0.0.1
    "017700000001", // octal-ish
  ]);
  if (loopback.has(h)) return "loopback";
  if (
    ["169.254.169.254", "metadata.internal", "metadata.google.internal"].includes(h)
  ) {
    return "metadata";
  }
  return h;
}
