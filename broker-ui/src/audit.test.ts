// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { describe, expect, test } from "bun:test";
import type { AuditEvent } from "./api";
import { actionPhrase, actorLabel, actorName, hostOnly, serviceHistoryPhrase, sessionHistoryPhrase } from "./audit";

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
