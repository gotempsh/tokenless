// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { describe, expect, test } from "bun:test";
import type { AuditEvent } from "../api";
import { logRows, outcomeLabel, outcomeSentence, requestUsage, sessionLog } from "./sessionLogs";

function event(id: string, action: string, outcome: string, detail: Record<string, string>, target?: string): AuditEvent {
  return { id, at: "2026-01-01T00:00:00Z", actor: "node:n", action, outcome, detail, target };
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
      request: "GET api.example.com/v1/items",
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

describe("sessionLog", () => {
  test("interleaves requests with what was done to the session, each event once", () => {
    const log = sessionLog([
      event("4", "session.revoke", "success", {}),
      event("3", "proxy.response", "success", { ...request, request_id: "r1", status: "200" }),
      event("2", "proxy.inject", "success", { ...request, request_id: "r1" }),
      event("1", "session.mint", "success", { bundle: "code-review" }),
    ]);
    expect(log.map((l) => (l.kind === "request" ? `request ${l.row.status}` : l.event.action))).toEqual([
      "session.revoke",
      "request 200",
      "session.mint",
    ]);
    const req = log[1];
    expect(req?.kind === "request" ? req.row.events.map((e) => e.id) : []).toEqual(["2", "3"]);
  });

  test("shows a refused MCP call as blocked", () => {
    const log = sessionLog([event("1", "proxy.gateway_denied", "denied", { ...request, mcp_tool: "drop_table" })]);
    expect(log[0]).toMatchObject({ kind: "request", row: { outcome: "blocked", mcp: "tools/call drop_table" } });
  });
});

describe("outcome words", () => {
  const rows = logRows([
    event("1", "proxy.response", "success", { ...request, request_id: "r1", status: "401", duration_ms: "40" }, "rule:ru1"),
    event("2", "proxy.inject", "success", { ...request, request_id: "r1" }, "rule:ru1"),
    event("3", "proxy.deny", "denied", { ...request, reason: "no rule" }),
    event("4", "proxy.tunnel", "success", { host: "registry.example.org:443" }),
    event("5", "proxy.response", "failure", { ...request, request_id: "r5", status: "502" }, "rule:ru2"),
  ]);

  test("say what the proxy did, not its internal name", () => {
    expect(rows.map(outcomeLabel)).toEqual(["Credential added · 401", "Blocked", "No credential", "Failed · 502"]);
  });

  test("name the rule that added the credential", () => {
    expect(rows[0]?.ruleId).toBe("ru1");
    expect(rows[1]?.ruleId).toBeUndefined();
    expect(outcomeSentence(rows[0]!, "github-read")).toBe(
      "The proxy added the credential of github-read and the API answered 401 after 40 ms.",
    );
    expect(outcomeSentence(rows[3]!)).toBe("The proxy added a credential, but the request failed.");
  });
});

describe("requestUsage", () => {
  test("counts against the limit and flags the last fifth", () => {
    expect(requestUsage(12, 100)).toEqual({ text: "12 of 100 used", near: false });
    expect(requestUsage(80, 100)).toEqual({ text: "80 of 100 used", near: true });
    expect(requestUsage(1500, null)).toEqual({ text: "1,500 so far, no limit", near: false });
  });
});
