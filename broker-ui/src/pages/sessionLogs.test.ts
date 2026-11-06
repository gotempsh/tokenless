// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { describe, expect, test } from "bun:test";
import type { AuditEvent } from "../api";
import { logRows } from "./sessionLogs";

function event(id: string, action: string, outcome: string, detail: Record<string, string>): AuditEvent {
  return { id, at: "2026-01-01T00:00:00Z", actor: "node:n", action, outcome, detail };
}

const request = { method: "GET", host: "api.example.com:443", path: "/v1/items" };

describe("logRows", () => {
  test("joins a decision with the API's answer", () => {
    const rows = logRows([
      event("2", "proxy.response", "success", { ...request, request_id: "r1", status: "404", duration_ms: "12" }),
      event("1", "proxy.inject", "success", { ...request, request_id: "r1", substituted: "__KEY__1" }),
    ]);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      outcome: "brokered",
      status: 404,
      durationMs: 12,
      request: "GET api.example.com:443 /v1/items",
      substituted: "__KEY__1",
    });
  });

  test("keeps a response whose decision is on another page", () => {
    const rows = logRows([event("2", "proxy.response", "failure", { ...request, request_id: "r9", status: "502", reason: "upstream request failed: reset" })]);
    expect(rows[0]).toMatchObject({ outcome: "error", status: 502, reason: "upstream request failed: reset" });
  });

  test("names the MCP call", () => {
    const rows = logRows([
      event("1", "proxy.deny", "denied", { ...request, mcp_method: "tools/call", mcp_tool: "drop_table" }),
      event("2", "proxy.inject", "success", { ...request, request_id: "r3", mcp_method: "tools/list" }),
    ]);
    expect(rows.map((r) => r.mcp)).toEqual(["tools/call drop_table", "tools/list"]);
  });

  test("labels denials and tunnels", () => {
    const rows = logRows([
      event("3", "proxy.deny", "denied", { ...request, reason: "no rule" }),
      event("4", "proxy.tunnel", "success", { host: "registry.example.org:443", reason: "always-reachable host" }),
      event("5", "proxy.connect_denied", "denied", { host: "x.example.org:443" }),
    ]);
    expect(rows.map((r) => r.outcome)).toEqual(["blocked", "passthrough", "blocked"]);
  });

  test("an injected request still waiting for its answer has no status", () => {
    const rows = logRows([event("1", "proxy.inject", "success", { ...request, request_id: "r2" })]);
    expect(rows[0]).toMatchObject({ outcome: "brokered", status: undefined });
  });
});
