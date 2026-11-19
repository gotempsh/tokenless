// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import type { CredentialTest, TestOutcome } from "../api";
import { nextSteps, runCommand } from "../serviceTest";
import { NextSteps, TestResult } from "./ServiceTest";

const DUMMY_KEY = "sk-tokenless-test-dummy-0000";

function result(outcome: TestOutcome, status: number | null = null): CredentialTest {
  return {
    outcome,
    ok: outcome === "accepted",
    host: "api.openai.com",
    method: "GET",
    path: "/v1/models",
    status,
    detail: `detail for ${outcome}`,
    tested_at: "2026-11-19T12:00:00Z",
    tested_by: "user:someone",
  };
}

const href = "#/vaults/v1/services/c1";
const render = (t: CredentialTest, retest = true) =>
  renderToStaticMarkup(<TestResult test={t} serviceHref={href} onRetest={retest ? () => {} : undefined} />);

describe("TestResult", () => {
  test("a pass names the host, the request and its status", () => {
    const html = render(result("accepted", 200));
    expect(html).toContain('data-outcome="accepted"');
    expect(html).toContain("api.openai.com accepted the credential");
    expect(html).toContain("GET /v1/models answered 200.");
    expect(html).not.toContain("Replace the secret");
  });

  test("a rejected key links to replacing it and offers another test", () => {
    const html = render(result("rejected", 401));
    expect(html).toContain("rejected the credential (401)");
    expect(html).toContain(`href="${href}"`);
    expect(html).toContain("Replace the secret");
    expect(html).toContain("Test again");
  });

  test("a blocked host links to the egress settings", () => {
    const html = render(result("blocked"));
    expect(html).toContain('href="#/settings"');
  });

  test("no test request is said plainly, never as a pass, with nothing to retry", () => {
    const html = render(result("no_probe"));
    expect(html).toContain("Not tested");
    expect(html).not.toContain("accepted");
    expect(html).not.toContain("Test again");
  });

  test("the response body or a secret has no place to show", () => {
    const t = { ...result("rejected", 401), detail: "[redacted]" };
    const html = render(t);
    expect(html).not.toContain(DUMMY_KEY);
  });
});

describe("NextSteps", () => {
  test("each step shows its state, a pending one its fix, the last the command", () => {
    const steps = nextSteps({
      vaultId: "v1",
      vaultName: "personal",
      credentialId: "c1",
      test: result("accepted", 200),
      bundles: [{ id: "b1", name: "my-agent" }],
      proxies: [],
      now: new Date("2026-11-19T12:00:00Z"),
    });
    const command = runCommand("personal", "my-agent", "claude");
    const html = renderToStaticMarkup(
      <NextSteps steps={steps} agentCommand={command} runCommand={runCommand("personal", "my-agent")} keyHint="hint" />,
    );
    expect(html).toContain('data-step="tested" data-state="done"');
    expect(html).toContain('data-step="bundle" data-state="done"');
    expect(html).toContain('data-step="proxy" data-state="pending"');
    expect(html).toContain('href="#/proxies"');
    expect(html).toContain("tokenless run --vault personal --bundle my-agent -- claude");
    expect(html).toContain('href="#/bundles/b1/connect"');
    expect(html).toContain("hint");
    // A done step carries no button.
    expect(html).not.toContain("Add to a bundle");
  });

  test("a service in no bundle links to adding it to one and has no command yet", () => {
    const steps = nextSteps({
      vaultId: "v1",
      vaultName: "personal",
      credentialId: "c1",
      test: result("accepted", 200),
      bundles: [],
      proxies: "hidden",
      now: new Date(),
    });
    const html = renderToStaticMarkup(<NextSteps steps={steps} />);
    expect(html).toContain("Add to a bundle");
    expect(html).toContain('data-step="proxy" data-state="unknown"');
    expect(html).not.toContain("tokenless run");
  });
});
