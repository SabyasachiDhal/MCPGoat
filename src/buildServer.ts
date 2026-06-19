/**
 * buildServer.ts — assembles a fresh McpServer with all challenges registered.
 * One server is created per MCP session; the difficulty level is snapshotted
 * for descriptions at this point (see challenges.ts).
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerChallenges } from "./challenges.js";
import { getLevel } from "./level.js";

export function createServer(): McpServer {
  const server = new McpServer(
    { name: "mcpgoat", version: "2.0.0" },
    {
      instructions:
        `MCPGoat (level: ${getLevel()}). Intentionally insecure, ` +
        "for authorized training only. Call list_challenges to begin; change " +
        "difficulty with mcpgoat_set_level.",
    }
  );
  registerChallenges(server);
  return server;
}
