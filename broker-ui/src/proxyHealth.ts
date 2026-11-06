// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Whether the proxies need someone's attention, and why. Proxies poll for
// policy every few seconds, so one that has not been heard from in two
// minutes is not serving agents.

import type { NodeInfo } from "./api";

export const CONNECTED_WITHIN_MS = 2 * 60 * 1000;

export type ProxyState = "healthy" | "offline" | "never_connected" | "certificate_expired" | "revoked";

export function proxyState(n: NodeInfo, now: Date): ProxyState {
  if (n.revoked_at) return "revoked";
  if (new Date(n.cert_not_after) <= now) return "certificate_expired";
  if (!n.last_seen_at) return "never_connected";
  if (now.getTime() - new Date(n.last_seen_at).getTime() > CONNECTED_WITHIN_MS) return "offline";
  return "healthy";
}

export type Attention =
  /** Nothing enrolled yet: a setup step, not an outage. */
  | { level: "warning"; kind: "none_enrolled" }
  /** Enrolled, but none is serving: every agent request fails. */
  | { level: "critical"; kind: "none_connected"; problems: NodeInfo[] }
  /** Some serve, some don't. */
  | { level: "warning"; kind: "some_down"; problems: NodeInfo[] }
  | { level: "ok" };

export function proxyAttention(nodes: NodeInfo[], now: Date): Attention {
  const active = nodes.filter((n) => !n.revoked_at);
  if (active.length === 0) return { level: "warning", kind: "none_enrolled" };
  const problems = active.filter((n) => proxyState(n, now) !== "healthy");
  if (problems.length === active.length) return { level: "critical", kind: "none_connected", problems };
  if (problems.length > 0) return { level: "warning", kind: "some_down", problems };
  return { level: "ok" };
}
