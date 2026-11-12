// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { describe, expect, test } from "bun:test";
import type { Alert, AuditDestination } from "./api";
import {
  alertDestinations,
  bannerTitle,
  DEFAULT_REFUSALS,
  lastRaised,
  parseRefusalKey,
  refusalKey,
  refusalOptions,
} from "./alerts";

function destination(over: Partial<AuditDestination> & { prefixes?: string[]; outcomes?: ("success" | "denied" | "failure")[] }): AuditDestination {
  return {
    id: "d1",
    name: "siem",
    url: "https://siem.example.test/in",
    format: "json",
    auth_header_name: null,
    has_auth_header: false,
    filter: { action_prefixes: over.prefixes ?? [], outcomes: over.outcomes ?? [], vault_ids: [] },
    paused: over.paused ?? false,
    status: "up_to_date",
    behind: 0,
    last_success_at: null,
    last_attempt_at: null,
    failing_since: null,
    last_error: null,
    consecutive_failures: 0,
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
  };
}

const alert = (kind: Alert["kind"]): Alert => ({
  id: "a1",
  kind,
  summary: "s",
  vault_id: null,
  session_id: null,
  node_id: null,
  detail: {},
  raised_at: "2026-01-01T00:00:00Z",
  acknowledged_at: null,
  acknowledged_by: null,
});

describe("alerts", () => {
  test("threshold keys round-trip and a custom one is offered", () => {
    expect(parseRefusalKey(refusalKey(DEFAULT_REFUSALS))).toEqual(DEFAULT_REFUSALS);
    const labels = refusalOptions(DEFAULT_REFUSALS).map((o) => o.label);
    expect(labels).toContain("10 refusals in 5 minutes (default)");
    expect(labels).toHaveLength(4);
    const custom = refusalOptions({ refusals: 7, window_secs: 90 });
    expect(custom.at(-1)).toEqual({ value: "7/90", label: "7 refusals in 90 seconds" });
  });

  test("a webhook gets alerts when its filter lets alert.raised through", () => {
    expect(alertDestinations([destination({})])).toHaveLength(1);
    expect(alertDestinations([destination({ prefixes: ["alert."] })])).toHaveLength(1);
    expect(alertDestinations([destination({ prefixes: ["al"] })])).toHaveLength(1);
    expect(alertDestinations([destination({ prefixes: ["proxy.", "session."] })])).toHaveLength(0);
    expect(alertDestinations([destination({ outcomes: ["denied"] })])).toHaveLength(0);
    expect(alertDestinations([destination({ paused: true })])).toHaveLength(0);
  });

  test("the banner names one alert and counts several", () => {
    expect(bannerTitle(1, alert("quarantine"))).toBe("Session cut off");
    expect(bannerTitle(3, alert("refusals"))).toBe("3 open alerts");
  });

  test("last raised is per kind, null when it never fired", () => {
    const summary = { open: 0, latest: null, last_raised: [{ kind: "refusals" as const, at: "2026-01-02T00:00:00Z" }] };
    expect(lastRaised(summary, "refusals")).toBe("2026-01-02T00:00:00Z");
    expect(lastRaised(summary, "new_proxy")).toBeNull();
    expect(lastRaised(undefined, "refusals")).toBeNull();
  });
});
