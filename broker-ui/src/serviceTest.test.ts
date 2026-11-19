// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { describe, expect, test } from "bun:test";
import type { CredentialTest, NodeInfo, TestOutcome } from "./api";
import {
  canRetest,
  keyHint,
  nextSteps,
  runCommand,
  testAdvice,
  testFix,
  testTitle,
  testTone,
  type StepFacts,
} from "./serviceTest";

const now = new Date("2026-11-19T12:00:00Z");

function result(outcome: TestOutcome, status: number | null = null): CredentialTest {
  return {
    outcome,
    ok: outcome === "accepted",
    host: "api.openai.com",
    method: "GET",
    path: "/v1/models",
    status,
    detail: `detail for ${outcome}`,
    tested_at: now.toISOString(),
    tested_by: "user:someone",
  };
}

function node(lastSeen: string | null): NodeInfo {
  return {
    id: "n1",
    name: "laptop",
    seal_public_key: "",
    cert_serial: "",
    cert_not_after: "2027-01-01T00:00:00Z",
    enrolled_at: "2026-11-01T00:00:00Z",
    last_seen_at: lastSeen,
    revoked_at: null,
  };
}

function facts(over: Partial<StepFacts> = {}): StepFacts {
  return {
    vaultId: "v1",
    vaultName: "personal",
    credentialId: "c1",
    test: result("accepted", 200),
    bundles: [{ id: "b1", name: "my-agent" }],
    proxies: [node("2026-11-19T11:59:30Z")],
    now,
    ...over,
  };
}

describe("test results", () => {
  test("each outcome reads differently and names the host and status", () => {
    const titles = new Set(
      (
        [
          ["accepted", 200],
          ["rejected", 401],
          ["unexpected_status", 503],
          ["unreachable", null],
          ["blocked", null],
          ["timed_out", null],
          ["no_probe", null],
          ["unavailable", null],
          ["rate_limited", null],
          ["error", null],
        ] as const
      ).map(([o, s]) => testTitle(result(o, s))),
    );
    expect(titles.size).toBe(10);
    expect(testTitle(result("rejected", 403))).toBe("api.openai.com rejected the credential (403)");
    expect(testTitle(result("unexpected_status", 503))).toBe("api.openai.com answered 503");
    expect(testTitle({ ...result("accepted", 200), host: "git.example.com:443" })).toBe(
      "git.example.com accepted the credential",
    );
  });

  test("only a pass is green; a service with nothing to test is neither", () => {
    expect(testTone(result("accepted", 200))).toBe("success");
    expect(testTone(result("rejected", 401))).toBe("warning");
    expect(testTone(result("timed_out"))).toBe("warning");
    expect(testTone(result("no_probe"))).toBe("neutral");
  });

  test("the fix sits next to the problem", () => {
    expect(testFix(result("rejected", 401), "#/vaults/v1/services/c1")).toEqual({
      label: "Replace the secret",
      href: "#/vaults/v1/services/c1",
    });
    expect(testFix(result("blocked"), "x")?.href).toBe("#/settings");
    expect(testFix(result("unreachable"), "x")).toBeNull();
    expect(canRetest(result("rejected", 401))).toBe(true);
    expect(canRetest(result("no_probe"))).toBe(false);
    expect(canRetest(null)).toBe(true);
  });
});

describe("next steps", () => {
  test("all in place: every step done, and the agent link goes to the bundle", () => {
    const steps = nextSteps(facts());
    expect(steps.map((s) => [s.id, s.state])).toEqual([
      ["tested", "done"],
      ["bundle", "done"],
      ["proxy", "done"],
      ["use", "pending"],
    ]);
    expect(steps[3]?.detail).toBe("Ready");
    expect(steps[3]?.action?.href).toBe("#/bundles/b1/connect");
  });

  test("each missing step links straight to its fix", () => {
    const steps = nextSteps(facts({ test: result("rejected", 401), bundles: [], proxies: [] }));
    const by = Object.fromEntries(steps.map((s) => [s.id, s]));
    expect(by.tested?.state).toBe("pending");
    expect(by.tested?.action).toEqual({ label: "Replace the secret", href: "#/vaults/v1/services/c1" });
    expect(by.bundle?.action?.href).toBe("#/bundles/new?vault=v1&back=vaults%2Fv1%2Fbundles");
    expect(by.proxy?.detail).toBe("No proxy enrolled");
    expect(by.proxy?.action?.href).toBe("#/proxies");
    expect(by.use?.action).toBeUndefined();
  });

  test("a service with no test request is never ticked", () => {
    const steps = nextSteps(facts({ test: result("no_probe") }));
    expect(steps[0]?.state).toBe("pending");
    expect(steps[0]?.detail).toBe("Not tested");
    expect(steps[0]?.action).toBeUndefined();
    // Untested is not unusable: with a bundle and a proxy, it is ready.
    expect(steps[3]?.detail).toBe("Ready");
  });

  test("an error is not 'tests are off': it says so and offers another test", () => {
    const failed = { ...result("error"), detail: "the test could not be completed: store unavailable" };
    expect(testTitle(failed)).toBe("The test could not be completed");
    expect(testAdvice(failed)).toContain("store unavailable");
    expect(testTone(failed)).toBe("warning");
    expect(canRetest(failed)).toBe(true);
  });

  test("a test that could not run says why, not that none is defined", () => {
    const none = { ...result("no_probe"), detail: "not tested: no test request defined for this service" };
    expect(testAdvice(none)).toBe("No test request defined for this service.");
    const wildcard = {
      ...result("no_probe"),
      detail: "not tested: the service only has wildcard hosts, so there is no host to send a test to",
    };
    expect(testAdvice(wildcard)).toContain("wildcard hosts");
    expect(testAdvice({ ...result("no_probe"), detail: "" })).toContain("No test request is defined");
  });

  test("proxies that stopped, or that only an admin can see", () => {
    const stale = nextSteps(facts({ proxies: [node("2026-11-19T10:00:00Z")] }));
    expect(stale[2]?.state).toBe("pending");
    expect(stale[2]?.detail).toBe("Enrolled, but none is connected");
    expect(nextSteps(facts({ proxies: "hidden" }))[2]?.state).toBe("unknown");
    expect(nextSteps(facts({ proxies: undefined }))[2]?.state).toBe("unknown");
    // A list that failed to load is not an empty one.
    const failed = nextSteps(facts({ proxies: "error" }))[2];
    expect(failed?.state).toBe("unknown");
    expect(failed?.detail).not.toContain("No proxy enrolled");
  });
});

describe("using it", () => {
  test("the run command is filled with the real vault and bundle", () => {
    expect(runCommand("personal", "my-agent")).toBe("tokenless run --vault personal --bundle my-agent -- <command>");
    expect(runCommand("my vault", "code-review", "claude")).toBe(
      "tokenless run --vault 'my vault' --bundle code-review -- claude",
    );
  });

  test("a placeholder beats a dummy value", () => {
    expect(keyHint("OPENAI_API_KEY", [])).toContain("OPENAI_API_KEY=tokenless");
    expect(
      keyHint("OPENAI_API_KEY", [
        { placeholder: "__OPENAI_API_KEY__", field: "api_key", env: "OPENAI_API_KEY", locations: ["header"] },
      ]),
    ).toBe("OPENAI_API_KEY is set to __OPENAI_API_KEY__ for you; the proxy swaps in the key.");
    expect(keyHint(null, [])).toBeNull();
  });
});
