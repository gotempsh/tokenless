// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { describe, expect, test } from "bun:test";
import type { AuditDestination } from "./api";
import {
  deliveryStatus,
  destinationForm,
  destinationFormProblem,
  destinationInput,
  failingDestinations,
  newDestinationForm,
  type DestinationForm,
} from "./auditExport";

function destination(patch: Partial<AuditDestination> = {}): AuditDestination {
  return {
    id: "audit_destination_1",
    name: "SIEM",
    url: "https://siem.example.com/ingest",
    format: "json",
    auth_header_name: "Authorization",
    has_auth_header: true,
    filter: { action_prefixes: ["credential."], outcomes: ["denied"], vault_ids: [] },
    paused: false,
    status: "up_to_date",
    behind: 0,
    last_success_at: null,
    last_attempt_at: null,
    failing_since: null,
    last_error: null,
    consecutive_failures: 0,
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
    ...patch,
  };
}

function form(patch: Partial<DestinationForm> = {}): DestinationForm {
  return { ...newDestinationForm(), name: "SIEM", url: "https://siem.example.com/ingest", ...patch };
}

describe("destination form", () => {
  test("accepts https, and http only to this machine", () => {
    expect(destinationFormProblem(form(), null)).toBeNull();
    expect(destinationFormProblem(form({ url: "http://127.0.0.1:9000/hook" }), null)).toBeNull();
    expect(destinationFormProblem(form({ url: "http://localhost/hook" }), null)).toBeNull();
    expect(destinationFormProblem(form({ url: "http://siem.example.com/ingest" }), null)).toContain("https");
    expect(destinationFormProblem(form({ url: "not a url" }), null)).toContain("not valid");
  });

  test("keeps tokens out of the URL", () => {
    expect(destinationFormProblem(form({ url: "https://user:token@siem.example.com/" }), null)).toContain("auth header");
    expect(destinationFormProblem(form({ url: "https://siem.example.com/#x" }), null)).toContain("fragment");
  });

  test("needs a name within the server's limit", () => {
    expect(destinationFormProblem(form({ name: "  " }), null)).toContain("name");
    expect(destinationFormProblem(form({ name: "x".repeat(61) }), null)).toContain("60");
  });

  test("an auth header needs a name, a value, and not one tokenless sets", () => {
    expect(destinationFormProblem(form({ auth_header_value: "secret" }), null)).toContain("Name the header");
    expect(destinationFormProblem(form({ auth_header_name: "Authorization" }), null)).toContain("Enter the value");
    expect(destinationFormProblem(form({ auth_header_name: "Bad Header", auth_header_value: "v" }), null)).toContain(
      "not a valid header",
    );
    expect(destinationFormProblem(form({ auth_header_name: "Webhook-Id", auth_header_value: "v" }), null)).toContain(
      "itself",
    );
    expect(destinationFormProblem(form({ auth_header_name: "Host", auth_header_value: "v" }), null)).toContain("itself");
  });

  test("rejects an action filter the server would", () => {
    expect(destinationFormProblem(form({ action_prefixes: "credential.\nproxy.inject" }), null)).toBeNull();
    expect(destinationFormProblem(form({ action_prefixes: "Credential.*" }), null)).toContain("not an action");
  });
});

describe("what the form sends", () => {
  test("a new destination with a header and a filter", () => {
    const input = destinationInput(
      form({
        auth_header_name: " Authorization ",
        auth_header_value: " Bearer abc ",
        action_prefixes: "credential.\n, proxy.inject ",
        outcomes: ["denied"],
        vault_ids: "vault_1",
      }),
      null,
    );
    expect(input).toEqual({
      name: "SIEM",
      url: "https://siem.example.com/ingest",
      format: "json",
      auth_header_name: "Authorization",
      auth_header_value: "Bearer abc",
      filter: { action_prefixes: ["credential.", "proxy.inject"], outcomes: ["denied"], vault_ids: ["vault_1"] },
    });
  });

  test("editing keeps the stored header without sending its value", () => {
    const current = destination();
    const f = destinationForm(current);
    expect(destinationFormProblem(f, current)).toBeNull();
    const input = destinationInput(f, current);
    expect(input.auth_header_name).toBe("Authorization");
    expect(input).not.toHaveProperty("auth_header_value");
  });

  test("renaming the header needs its value again", () => {
    const current = destination();
    const f = { ...destinationForm(current), auth_header_name: "X-Token" };
    expect(destinationFormProblem(f, current)).toContain("Enter the value");
  });

  test("clearing or emptying the header removes it", () => {
    const current = destination();
    expect(destinationInput({ ...destinationForm(current), clear_auth_header: true }, current)).toMatchObject({
      auth_header_name: null,
      clear_auth_header: true,
    });
    const emptied = destinationInput({ ...destinationForm(current), auth_header_name: "" }, current);
    expect(emptied.auth_header_name).toBeNull();
    expect(emptied).not.toHaveProperty("clear_auth_header");
  });

  test("the form round-trips a destination's filter", () => {
    const current = destination({ filter: { action_prefixes: ["a.", "b"], outcomes: ["failure"], vault_ids: ["v1", "v2"] } });
    expect(destinationInput(destinationForm(current), current).filter).toEqual(current.filter);
  });
});

describe("delivery status", () => {
  test("reads at a glance", () => {
    expect(deliveryStatus({ status: "up_to_date", behind: 0 })).toEqual({ label: "Up to date", tone: "success" });
    expect(deliveryStatus({ status: "sending", behind: 1 }).label).toBe("Sending, 1 event behind");
    expect(deliveryStatus({ status: "sending", behind: 1200 }).label).toBe("Sending, 1,200 events behind");
    expect(deliveryStatus({ status: "failing", behind: 3 }).tone).toBe("destructive");
    expect(deliveryStatus({ status: "retrying", behind: 3 }).tone).toBe("warning");
  });

  test("the Audit page warns about failing destinations only", () => {
    const list = [destination({ id: "a", status: "failing" }), destination({ id: "b", status: "retrying" })];
    expect(failingDestinations(list).map((d) => d.id)).toEqual(["a"]);
  });
});
