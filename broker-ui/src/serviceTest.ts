// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// How a service's credential test went, in words a person acts on, and
// the short checklist from "service added" to "an agent is using it".

import type { CredentialTest, NodeInfo, Substitution } from "./api";
import { signedInRunCommand } from "./bundleConnect";
import { bundleFormHref } from "./bundleForm";
import { proxyAttention } from "./proxyHealth";

export type TestTone = "success" | "warning" | "neutral";

/** `api.example.com:443` reads as `api.example.com`. */
function host(test: CredentialTest): string {
  const h = test.host ?? "the service";
  return h.endsWith(":443") ? h.slice(0, -4) : h;
}

/** The headline for a test, naming the host and status where there is one. */
export function testTitle(test: CredentialTest): string {
  switch (test.outcome) {
    case "accepted":
      return `${host(test)} accepted the credential`;
    case "rejected":
      return `${host(test)} rejected the credential (${test.status ?? "?"})`;
    case "unexpected_status":
      return `${host(test)} answered ${test.status ?? "?"}`;
    case "unreachable":
      return `Couldn't reach ${host(test)}`;
    case "blocked":
      return `${host(test)} is blocked by the egress policy`;
    case "timed_out":
      return `${host(test)} didn't answer in time`;
    case "no_probe":
      return "Not tested";
    case "unavailable":
      return "Tests are off on this server";
    case "rate_limited":
      return "Not tested: too many tests";
  }
}

/** What the person should do, when the detail alone does not say it. */
export function testAdvice(test: CredentialTest): string {
  switch (test.outcome) {
    case "accepted":
      return `${test.method ?? "GET"} ${test.path ?? "/"} answered ${test.status ?? "2xx"}.`;
    case "rejected":
      return "The key is wrong, expired or missing the scopes this request needs. Replace it, then test again.";
    case "unexpected_status":
      return "That says neither that the key works nor that it doesn't. Test again later.";
    case "unreachable":
    case "timed_out":
      return test.detail;
    case "blocked":
      return "Its address is private. Allow the range under Settings → Private addresses, then test again.";
    case "no_probe":
      return "No test request is defined for this service, so its key can't be checked from here.";
    case "unavailable":
      return "This server makes no outbound test requests.";
    case "rate_limited":
      return test.detail;
  }
}

export function testTone(test: CredentialTest): TestTone {
  if (test.outcome === "accepted") return "success";
  if (test.outcome === "no_probe" || test.outcome === "unavailable") return "neutral";
  return "warning";
}

/** Whether testing again could give another answer. */
export function canRetest(test: CredentialTest | null | undefined): boolean {
  return !test || !(test.outcome === "no_probe" || test.outcome === "unavailable");
}

/** The page that fixes what the test found, if one does. */
export function testFix(
  test: CredentialTest,
  serviceHref: string,
): { label: string; href: string } | null {
  if (test.outcome === "rejected") return { label: "Replace the secret", href: serviceHref };
  if (test.outcome === "blocked") return { label: "Open Settings", href: "#/settings" };
  return null;
}

export function serviceHref(vaultId: string, credentialId: string): string {
  return `#/vaults/${vaultId}/services/${credentialId}`;
}

// ----- next steps ------------------------------------------------------------

export type StepState = "done" | "pending" | "unknown";

export interface Step {
  id: "tested" | "bundle" | "proxy" | "use";
  label: string;
  state: StepState;
  detail: string;
  /** Where the person fixes it. */
  action?: { label: string; href: string };
}

export interface StepFacts {
  vaultId: string;
  vaultName: string;
  credentialId: string;
  test: CredentialTest | null | undefined;
  /** The bundles holding the service's rule. */
  bundles: readonly { id: string; name: string }[];
  /**
   * The proxies: undefined while loading, "hidden" when this person may not
   * see them (they are an admin's).
   */
  proxies: readonly NodeInfo[] | "hidden" | undefined;
  now: Date;
}

export function nextSteps(f: StepFacts): Step[] {
  const service = serviceHref(f.vaultId, f.credentialId);
  const steps: Step[] = [];
  const t = f.test;
  steps.push(
    !t
      ? { id: "tested", label: "Credential tested", state: "pending", detail: "Not tested yet", action: { label: "Test it", href: service } }
      : t.outcome === "accepted"
        ? { id: "tested", label: "Credential tested", state: "done", detail: testTitle(t) }
        : {
            id: "tested",
            label: "Credential tested",
            state: "pending",
            detail: testTitle(t),
            action: testFix(t, service) ?? (canRetest(t) ? { label: "Test again", href: service } : undefined),
          },
  );
  const [first] = f.bundles;
  steps.push(
    first
      ? {
          id: "bundle",
          label: "In an access bundle",
          state: "done",
          detail: f.bundles.map((b) => b.name).join(", "),
        }
      : {
          id: "bundle",
          label: "In an access bundle",
          state: "pending",
          detail: "Agents start from a bundle",
          action: {
            label: "Add to a bundle",
            href: bundleFormHref({ vault: f.vaultId, back: `vaults/${f.vaultId}/bundles` }),
          },
        },
  );
  if (f.proxies === undefined) {
    steps.push({ id: "proxy", label: "Proxy connected", state: "unknown", detail: "Checking…" });
  } else if (f.proxies === "hidden") {
    steps.push({
      id: "proxy",
      label: "Proxy connected",
      state: "unknown",
      detail: "Only an admin can see proxies; tokenless status checks this machine's",
    });
  } else {
    const attention = proxyAttention([...f.proxies], f.now);
    const live = f.proxies.filter((n) => !n.revoked_at).length;
    steps.push(
      attention.level === "ok" || attention.kind === "some_down"
        ? { id: "proxy", label: "Proxy connected", state: "done", detail: `${live} enrolled, serving agents` }
        : attention.kind === "none_enrolled"
          ? {
              id: "proxy",
              label: "Proxy connected",
              state: "pending",
              detail: "No proxy enrolled",
              action: { label: "Add a proxy", href: "#/proxies" },
            }
          : {
              id: "proxy",
              label: "Proxy connected",
              state: "pending",
              detail: "Enrolled, but none is connected",
              action: { label: "Open Proxies", href: "#/proxies" },
            },
    );
  }
  const ready = steps.every((s) => s.state === "done");
  steps.push({
    id: "use",
    label: "Start an agent behind it",
    state: "pending",
    detail: first ? (ready ? "Ready" : "Once the steps above are done") : "Once it is in an access bundle",
    action: first ? { label: "Run an agent", href: `#/bundles/${first.id}/connect` } : undefined,
  });
  return steps;
}

/** `tokenless run --vault … --bundle … -- <command>`, filled in. */
export function runCommand(vaultName: string, bundleName: string, command = "<command>"): string {
  return signedInRunCommand(bundleName, command, vaultName);
}

/**
 * What to give a tool that will not start without the key: the
 * placeholder when the service has one, else any dummy value.
 */
export function keyHint(variable: string | null | undefined, substitutions: readonly Substitution[]): string | null {
  const exported = substitutions.find((s) => s.env);
  if (exported) return `${exported.env} is set to ${exported.placeholder} for you; the proxy swaps in the key.`;
  const [placeholder] = substitutions;
  if (placeholder) return `Send ${placeholder.placeholder} where the key goes; the proxy swaps in the key.`;
  if (variable)
    return `A tool that insists on ${variable} gets any dummy value (${variable}=tokenless); the proxy puts the key in.`;
  return null;
}
