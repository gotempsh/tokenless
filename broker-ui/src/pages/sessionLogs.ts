// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Turns proxy audit events (a session's, or a service's) into one row per
// request: the decision a proxy records before forwarding (`proxy.inject`)
// joined with what the API answered (`proxy.response`, same `request_id`).

import type { AuditEvent } from "../api";
import { hostOnly } from "../audit";

export type LogOutcome = "brokered" | "blocked" | "passthrough" | "error";

export interface LogRow {
  key: string;
  at: string;
  outcome: LogOutcome;
  /** The API's status, when one came back. */
  status?: number;
  durationMs?: number;
  request: string;
  /** Why it was blocked, failed or tunnelled. */
  reason?: string;
  /** Placeholders the proxy filled in. */
  substituted?: string;
  /** Why the body was not searched for placeholders. */
  bodySkipped?: string;
  /** The MCP call, e.g. "tools/call search_issues". */
  mcp?: string;
  /** The rule that matched, from the decision's `rule:` target. */
  ruleId?: string;
  /** The session that made the request, named by its `name` label then. */
  session?: { id: string; name?: string };
  /** The audit events behind the row: the decision, then the answer. */
  events: AuditEvent[];
}

/** The rule an event names as its target, if any. */
function ruleOf(e: AuditEvent | undefined): string | undefined {
  return e?.target?.startsWith("rule:") ? e.target.slice(5) : undefined;
}

/** The row's result in words: "Credential added · 200", "Blocked". */
export function outcomeLabel(row: LogRow): string {
  const status = row.status !== undefined ? ` · ${row.status}` : "";
  switch (row.outcome) {
    case "brokered":
      return `Credential added${status}`;
    case "blocked":
      return "Blocked";
    case "passthrough":
      return "No credential";
    case "error":
      return `Failed${status}`;
  }
}

/** What happened to the request, as a sentence. `rule` names the matching rule. */
export function outcomeSentence(row: LogRow, rule?: string): string {
  const by = rule ? `the credential of ${rule}` : "a credential";
  const took = row.durationMs !== undefined ? ` after ${row.durationMs} ms` : "";
  switch (row.outcome) {
    case "brokered":
      return row.status !== undefined
        ? `The proxy added ${by} and the API answered ${row.status}${took}.`
        : `The proxy added ${by} and sent it on.`;
    case "blocked":
      return "The proxy refused it, so it never reached the API.";
    case "passthrough":
      return "None of the session's rules covers this host, so the proxy sent it on without a credential.";
    case "error":
      return `The proxy added ${by}, but the request failed${took}.`;
  }
}

function sessionOf(e: AuditEvent): LogRow["session"] {
  const id = e.detail.session_id;
  return id ? { id, name: e.detail["label.name"] } : undefined;
}

function mcpCall(e: AuditEvent | undefined): string | undefined {
  if (!e) return undefined;
  const tool = e.detail.mcp_tool;
  return tool ? `tools/call ${tool}` : e.detail.mcp_method;
}

const BLOCKED = new Set(["proxy.deny", "proxy.connect_denied", "proxy.egress_blocked", "proxy.gateway_denied"]);

/** `GET api.example.com/v1/items`: the port only when it isn't 443. */
function request(e: AuditEvent): string {
  const target = e.detail.host ? `${hostOnly(e.detail.host)}${e.detail.path ?? ""}` : e.detail.path;
  return [e.detail.method, target].filter(Boolean).join(" ");
}

function number(value: string | undefined): number | undefined {
  if (value === undefined) return undefined;
  const n = Number(value);
  return Number.isFinite(n) ? n : undefined;
}

/** Rows in the order the events came (newest first). */
export function logRows(events: AuditEvent[]): LogRow[] {
  const responses = new Map<string, AuditEvent>();
  const decided = new Set<string>();
  for (const e of events) {
    const id = e.detail.request_id;
    if (!id) continue;
    if (e.action === "proxy.response") responses.set(id, e);
    if (e.action === "proxy.inject") decided.add(id);
  }
  const rows: LogRow[] = [];
  for (const e of events) {
    const id = e.detail.request_id;
    if (e.action === "proxy.response") {
      // Shown with its decision when that is on the same page.
      if (id && decided.has(id)) continue;
      rows.push({
        key: e.id,
        at: e.at,
        outcome: e.outcome === "success" ? "brokered" : "error",
        status: number(e.detail.status),
        durationMs: number(e.detail.duration_ms),
        request: request(e),
        reason: e.detail.reason,
        ruleId: ruleOf(e),
        session: sessionOf(e),
        events: [e],
      });
    } else if (e.action === "proxy.inject") {
      const response = id ? responses.get(id) : undefined;
      rows.push({
        key: e.id,
        at: e.at,
        outcome: response && response.outcome !== "success" ? "error" : "brokered",
        status: number(response?.detail.status),
        durationMs: number(response?.detail.duration_ms),
        request: request(e),
        reason: response?.detail.reason,
        substituted: e.detail.substituted,
        bodySkipped: e.detail.body_not_substituted,
        mcp: mcpCall(e),
        ruleId: ruleOf(e),
        session: sessionOf(e),
        events: response ? [e, response] : [e],
      });
    } else if (BLOCKED.has(e.action)) {
      rows.push({
        key: e.id,
        at: e.at,
        outcome: "blocked",
        request: request(e),
        reason: e.detail.reason,
        mcp: mcpCall(e),
        ruleId: ruleOf(e),
        session: sessionOf(e),
        events: [e],
      });
    } else if (e.action === "proxy.tunnel") {
      rows.push({
        key: e.id,
        at: e.at,
        outcome: "passthrough",
        request: request(e),
        reason: e.detail.reason,
        session: sessionOf(e),
        events: [e],
      });
    }
  }
  return rows;
}

/** One line of a session's log: a request it made, or something done to it. */
export type SessionLogEntry = { kind: "request"; row: LogRow } | { kind: "event"; event: AuditEvent };

/**
 * Everything recorded about a session, in the order given (newest first):
 * its requests, each joined with the API's answer, and every other event
 * such as being created, relabelled or revoked.
 */
export function sessionLog(events: AuditEvent[]): SessionLogEntry[] {
  const rows = logRows(events);
  const byKey = new Map(rows.map((r) => [r.key, r]));
  const shown = new Set(rows.flatMap((r) => r.events.map((e) => e.id)));
  const out: SessionLogEntry[] = [];
  for (const e of events) {
    const row = byKey.get(e.id);
    if (row) out.push({ kind: "request", row });
    else if (!shown.has(e.id)) out.push({ kind: "event", event: e });
  }
  return out;
}

/**
 * Requests a session has had a credential added to, against its limit.
 * Proxies count each node separately, so this is the total the broker
 * recorded, not what any one proxy will refuse at.
 */
export function requestUsage(used: number, limit: number | null): { text: string; near: boolean } {
  const n = used.toLocaleString("en-US");
  if (limit === null) return { text: `${n} so far, no limit`, near: false };
  return { text: `${n} of ${limit.toLocaleString("en-US")} used`, near: used >= limit * 0.8 };
}
