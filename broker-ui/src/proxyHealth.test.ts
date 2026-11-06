// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { describe, expect, test } from "bun:test";
import type { NodeInfo } from "./api";
import { proxyAttention, proxyState } from "./proxyHealth";

const now = new Date("2026-11-06T12:00:00Z");
const iso = (offsetSecs: number) => new Date(now.getTime() + offsetSecs * 1000).toISOString();

function node(name: string, patch: Partial<NodeInfo> = {}): NodeInfo {
  return {
    id: `${name}-id`,
    name,
    seal_public_key: "k",
    cert_serial: "s",
    cert_not_after: iso(24 * 3600),
    enrolled_at: iso(-3600),
    last_seen_at: iso(-5),
    revoked_at: null,
    ...patch,
  };
}

describe("proxy health", () => {
  test("each proxy's state", () => {
    expect(proxyState(node("a"), now)).toBe("healthy");
    expect(proxyState(node("a", { last_seen_at: iso(-600) }), now)).toBe("offline");
    expect(proxyState(node("a", { last_seen_at: null }), now)).toBe("never_connected");
    expect(proxyState(node("a", { cert_not_after: iso(-1) }), now)).toBe("certificate_expired");
    expect(proxyState(node("a", { revoked_at: iso(-60), last_seen_at: iso(-600) }), now)).toBe("revoked");
  });

  test("what needs attention", () => {
    expect(proxyAttention([], now)).toEqual({ level: "warning", kind: "none_enrolled" });
    expect(proxyAttention([node("a", { revoked_at: iso(-60) })], now)).toEqual({ level: "warning", kind: "none_enrolled" });
    const down = node("b", { last_seen_at: iso(-600) });
    expect(proxyAttention([down], now)).toEqual({ level: "critical", kind: "none_connected", problems: [down] });
    expect(proxyAttention([node("a"), down], now)).toEqual({ level: "warning", kind: "some_down", problems: [down] });
    expect(proxyAttention([node("a")], now)).toEqual({ level: "ok" });
  });
});
