// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Turns a session's proxy audit events into one row per request: the
// decision a proxy records before forwarding (`proxy.inject`) joined with
// what the API answered (`proxy.response`, same `request_id`).

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
}

function mcpCall(e: AuditEvent | undefined): string | undefined {
  if (!e) return undefined;
  const tool = e.detail.mcp_tool;
  return tool ? `tools/call ${tool}` : e.detail.mcp_method;
}

const BLOCKED = new Set(["proxy.deny", "proxy.connect_denied", "proxy.egress_blocked"]);

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
      });
    } else if (BLOCKED.has(e.action)) {
      rows.push({ key: e.id, at: e.at, outcome: "blocked", request: request(e), reason: e.detail.reason, mcp: mcpCall(e) });
    } else if (e.action === "proxy.tunnel") {
      rows.push({ key: e.id, at: e.at, outcome: "passthrough", request: request(e), reason: e.detail.reason });
    }
  }
  return rows;
}
