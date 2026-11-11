// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { describe, expect, test } from "bun:test";
import type { AuditEvent } from "./api";
import {
  AUDIT_CATEGORIES,
  actionPhrase,
  actorLabel,
  actorName,
  hostOnly,
  serviceHistoryPhrase,
  sessionHistoryPhrase,
} from "./audit";

const event = (over: Partial<AuditEvent>): AuditEvent => ({
  id: "e1",
  at: "2026-01-01T00:00:00Z",
  actor: "user:00000000-0000-0000-0000-000000000001",
  action: "auth.login",
  outcome: "success",
  detail: {},
  ...over,
});

describe("actorLabel", () => {
  test("names the signed-in person You and others by username, never by id", () => {
    const names = { meId: "00000000-0000-0000-0000-000000000001", users: new Map([["u2", "sam"]]) };
    expect(actorLabel(event({}), names)).toBe("You");
    expect(actorLabel(event({ actor: "user:u2" }), names)).toBe("sam");
  });

  test("falls back to the login's username, then a short id", () => {
    expect(actorLabel(event({ actor: "user:u3", detail: { username: "kim" } }), {})).toBe("kim");
    expect(actorLabel(event({ actor: "user:abcdef0123456789" }), {})).toBe("Person abcdef01");
  });

  test("names keys, proxies and agents", () => {
    expect(actorLabel(event({ actor: "api_key:tk_ab12" }), { apiKeys: new Map([["tk_ab12", "ci"]]) })).toBe("API key ci");
    expect(actorLabel(event({ actor: "node:n1" }), { nodes: new Map([["n1", "edge-1"]]) })).toBe("Proxy edge-1");
    expect(actorLabel(event({ actor: "session:s1" }), {})).toBe("An agent");
    expect(actorLabel(event({ actor: "anonymous" }), {})).toBe("Someone");
  });
});

describe("actionPhrase", () => {
  test("reads as the rest of a sentence, with the record's name when the event has it", () => {
    expect(actionPhrase(event({}))).toBe("signed in");
    expect(actionPhrase(event({ action: "bundle.update", detail: { name: "code-review" } }))).toBe("changed bundle code-review");
    expect(actionPhrase(event({ action: "rule.delete" }))).toBe("deleted a rule");
  });

  test("alerts say what happened and which one was seen", () => {
    expect(
      actionPhrase(event({ action: "alert.raised", actor: "node:n1", detail: { kind: "refusals", summary: "Session 3f9c2a1b was refused 10 times within 300s." } })),
    ).toBe("raised an alert: Session 3f9c2a1b was refused 10 times within 300s.");
    expect(actionPhrase(event({ action: "alert.acknowledge", detail: { kind: "new_proxy" } }))).toBe(
      "acknowledged a second-proxy alert",
    );
    expect(actionPhrase(event({ action: "alert.acknowledge" }))).toBe("acknowledged an alert");
  });

  test("audit export changes name the webhook", () => {
    expect(actionPhrase(event({ action: "audit_export.create", detail: { name: "SIEM" } }))).toBe("added audit webhook SIEM");
    expect(actionPhrase(event({ action: "audit_export.skip", detail: { name: "SIEM", skipped: "12" } }))).toBe(
      "skipped 12 events for audit webhook SIEM",
    );
    expect(actionPhrase(event({ action: "audit_export.test", outcome: "failure", detail: { name: "SIEM" } }))).toBe(
      "failed to send a test to audit webhook SIEM",
    );
  });

  test("a refused sign-in says who it tried to be", () => {
    expect(actionPhrase(event({ action: "auth.login", outcome: "denied", detail: { username: "kim" } }))).toBe(
      "failed to sign in as kim",
    );
  });

  test("agent requests show the method, host and path", () => {
    const detail = { host: "api.example.com:443", method: "GET", path: "/v1/items" };
    expect(actionPhrase(event({ action: "proxy.inject", detail }))).toBe("added a credential to GET api.example.com/v1/items");
    expect(actionPhrase(event({ action: "proxy.deny", detail }))).toBe("refused GET api.example.com/v1/items");
  });

  test("an unknown action is shown as recorded", () => {
    expect(actionPhrase(event({ action: "future.thing" }))).toBe("future.thing");
  });

  test("single sign-on, sign-in and account changes read as sentences", () => {
    expect(actionPhrase(event({ action: "identity_provider.update", detail: { slug: "keycloak" } }))).toBe(
      "changed single sign-on provider keycloak",
    );
    expect(actionPhrase(event({ action: "settings.sign_in", detail: { password_sign_in: "admins_only" } }))).toBe(
      "limited password sign-in to local admins",
    );
    expect(
      actionPhrase(event({ action: "user.create", actor: "system", detail: { username: "kim", provider: "keycloak" } })),
    ).toBe("created kim's account at their first sign-in with keycloak");
    expect(actionPhrase(event({ action: "auth.totp_disable", outcome: "denied" }))).toBe(
      "tried to remove their authenticator app",
    );
    expect(
      actionPhrase(event({ action: "proxy.tunnel_cut", detail: { host: "api.example.com:443", reason: "the session was revoked" } })),
    ).toBe("cut an open connection to api.example.com: the session was revoked");
  });

  test("rate-limited requests read as one refusal with a count", () => {
    expect(
      actionPhrase(event({ action: "proxy.rate_limited", detail: { refused: "37", host: "api.example.com:443", per_sec: "20" } })),
    ).toBe("refused 37 requests to api.example.com: the session went past 20 a second");
  });

  test("a tripwire's trip reads as a cut-off", () => {
    expect(
      actionPhrase(event({ action: "proxy.tripwire", detail: { tripwire: "build-runner", host: "api.github.com:443" } })),
    ).toBe("cut off a session that sent tripwire build-runner to api.github.com");
    expect(sessionHistoryPhrase(event({ action: "session.revoke", detail: { reason: "tripwire", tripwire: "build-runner" } }))).toBe(
      "revoked the session after it sent tripwire build-runner",
    );
  });

  // Every action the control plane and the proxies record. A new one goes
  // here, with a phrase in audit.ts, so the log never shows a raw name.
  const RECORDED = [
    "alert.acknowledge", "alert.raised",
    "api_key.create", "api_key.revoke",
    "audit_export.create", "audit_export.delete", "audit_export.pause", "audit_export.resume",
    "audit_export.rotate_secret", "audit_export.skip", "audit_export.test", "audit_export.update",
    "auth.login", "auth.logout", "auth.setup", "auth.sign_in_revoke", "auth.sign_out_elsewhere", "auth.step_up",
    "auth.totp_disable", "auth.totp_enable",
    "bundle.create", "bundle.delete", "bundle.update",
    "credential.create", "credential.delete", "credential.rotate", "credential.update_headers",
    "credential.update_substitutions", "credential.validate",
    "identity_provider.create", "identity_provider.delete", "identity_provider.update",
    "launcher_key.create", "launcher_key.revoke",
    "node.enroll", "node.join_token.create", "node.register_embedded", "node.renew", "node.revoke",
    "proxy.connect_denied", "proxy.deny", "proxy.egress_blocked", "proxy.gateway_denied", "proxy.inject",
    "proxy.quarantine", "proxy.rate_limited", "proxy.tripwire",
    "proxy.response", "proxy.tunnel", "proxy.tunnel_cut",
    "rule.create", "rule.delete", "rule.update",
    "session.mint", "session.revoke", "session.update_labels",
    "settings.sign_in", "settings.update",
    "template.approve", "template.import",
    "tripwire.create", "tripwire.delete",
    "user.create", "user.invite", "user.invite.accept", "user.invite.revoke", "user.password_change",
    "user.password_reset", "user.sign_ins_revoke", "user.update",
    "variable.create", "variable.delete", "variable.update",
    "vault.create", "vault.delete",
  ];

  test("every recorded action reads as a sentence, never its raw name", () => {
    for (const action of RECORDED) {
      for (const outcome of ["success", "denied"] as const) {
        expect(actionPhrase(event({ action, outcome }))).not.toBe(action);
      }
    }
  });

  test("every recorded action can be found with the filter", () => {
    const categories = AUDIT_CATEGORIES.filter((c) => c.prefix !== "");
    for (const action of RECORDED) {
      expect(categories.some((c) => action.startsWith(c.prefix))).toBe(true);
    }
  });
});

test("hostOnly drops only the default HTTPS port", () => {
  expect(hostOnly("api.example.com:443")).toBe("api.example.com");
  expect(hostOnly("api.example.com:8443")).toBe("api.example.com:8443");
});

describe("a session's history", () => {
  test("names who created a session the way events name their actor", () => {
    expect(actorName("user:me", { meId: "me" })).toBe("You");
    expect(actorName("api_key:cbk_ci", { apiKeys: new Map([["cbk_ci", "ci"]]) })).toBe("API key ci");
  });

  test("says what was done to the session", () => {
    expect(sessionHistoryPhrase(event({ action: "session.mint", detail: { bundle: "code-review" } }))).toBe(
      "created the session from code-review",
    );
    expect(
      sessionHistoryPhrase(event({ action: "session.revoke", actor: "node:n1", detail: { reason: "quarantine", refusals: "20" } })),
    ).toBe("revoked the session after it was refused 20 times");
    expect(actionPhrase(event({ action: "proxy.quarantine", detail: { refusals: "20", window_secs: "300" } }))).toBe(
      "cut off a session after 20 refusals in 300s",
    );
    expect(sessionHistoryPhrase(event({ action: "session.revoke", detail: { already_revoked: "false" } }))).toBe(
      "revoked the session",
    );
    expect(
      sessionHistoryPhrase(event({ action: "session.revoke", detail: { by: "session token", already_revoked: "false" } })),
    ).toBe("ended the session with its own token");
    expect(
      sessionHistoryPhrase(event({ action: "session.update_labels", detail: { "label.name": "laptop", "label.ticket": "T-1" } })),
    ).toBe("set the labels to name=laptop, ticket=T-1");
    expect(sessionHistoryPhrase(event({ action: "session.update_labels" }))).toBe("removed the labels");
  });
});

describe("serviceHistoryPhrase", () => {
  test("says what was done to the service, without naming it again", () => {
    expect(serviceHistoryPhrase(event({ action: "credential.create", detail: { name: "github" } }))).toBe(
      "added the service",
    );
    expect(serviceHistoryPhrase(event({ action: "credential.rotate", detail: { name: "github" } }))).toBe(
      "replaced the secret",
    );
    expect(serviceHistoryPhrase(event({ action: "credential.update_headers" }))).toBe("changed the custom headers");
    expect(serviceHistoryPhrase(event({ action: "credential.validate", detail: { status: "200" } }))).toBe(
      "tested the service: it worked (200)",
    );
    expect(
      serviceHistoryPhrase(event({ action: "credential.validate", outcome: "failure", detail: { status: "none" } })),
    ).toBe("tested the service: it failed");
  });

  test("falls back to the general phrase for its rules", () => {
    expect(serviceHistoryPhrase(event({ action: "rule.create", detail: { hosts: "api.github.com" } }))).toBe(
      "added a rule for api.github.com",
    );
  });
});
