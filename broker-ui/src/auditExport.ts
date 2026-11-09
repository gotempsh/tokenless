// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Audit export in the console: the destination form, what it sends, and how
// a destination's delivery reads at a glance.

import type { AuditDestination, AuditDestinationInput, AuditOutcome, DeliveryStatus, PayloadFormat } from "./api";

/** The server's limits, checked here so the form can say so before sending. */
export const NAME_MAX = 60;
const ACTION_PREFIX = /^[a-z0-9._]{1,64}$/;
const HEADER_NAME = /^[A-Za-z0-9!#$%&'*+\-.^_`|~]{1,64}$/;
const RESERVED_HEADERS = ["connection", "content-length", "content-type", "host", "transfer-encoding", "user-agent"];

export type StartAt = "now" | "oldest";

export interface DestinationForm {
  name: string;
  url: string;
  format: PayloadFormat;
  auth_header_name: string;
  /** Empty keeps the stored value while the header's name is unchanged. */
  auth_header_value: string;
  clear_auth_header: boolean;
  /** One per line or comma-separated. */
  action_prefixes: string;
  outcomes: AuditOutcome[];
  vault_ids: string;
  /** Only when adding: send the log so far, or only what happens next. */
  start_at: StartAt;
}

export function newDestinationForm(): DestinationForm {
  return {
    name: "",
    url: "",
    format: "json",
    auth_header_name: "",
    auth_header_value: "",
    clear_auth_header: false,
    action_prefixes: "",
    outcomes: [],
    vault_ids: "",
    start_at: "now",
  };
}

export function destinationForm(d: AuditDestination): DestinationForm {
  return {
    name: d.name,
    url: d.url,
    format: d.format,
    auth_header_name: d.auth_header_name ?? "",
    auth_header_value: "",
    clear_auth_header: false,
    action_prefixes: d.filter.action_prefixes.join("\n"),
    outcomes: [...d.filter.outcomes],
    vault_ids: d.filter.vault_ids.join("\n"),
    start_at: "now",
  };
}

function items(text: string): string[] {
  return text
    .split(/[\n,]/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function isLoopback(host: string): boolean {
  return host === "localhost" || host === "[::1]" || /^127\.\d+\.\d+\.\d+$/.test(host);
}

/** Whether the stored auth header stays as it is when the form is saved. */
function keepsStoredHeader(form: DestinationForm, current: AuditDestination | null): boolean {
  return (
    !form.clear_auth_header &&
    !form.auth_header_value.trim() &&
    current !== null &&
    current.has_auth_header &&
    current.auth_header_name === form.auth_header_name.trim()
  );
}

/** What would stop the server accepting the form, before sending it. */
export function destinationFormProblem(form: DestinationForm, current: AuditDestination | null): string | null {
  const name = form.name.trim();
  if (!name) return "Give the destination a name.";
  if ([...name].length > NAME_MAX) return `The name takes at most ${NAME_MAX} characters.`;
  const raw = form.url.trim();
  if (!raw) return "Enter the URL that receives the events.";
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return "The URL is not valid.";
  }
  if (url.protocol !== "https:" && !(url.protocol === "http:" && isLoopback(url.hostname)))
    return "The URL must use https (http only to localhost).";
  if (url.username || url.password) return "Put the receiver's token in the auth header, not the URL.";
  if (url.hash) return "The URL cannot have a #fragment.";
  if (!form.clear_auth_header) {
    const header = form.auth_header_name.trim();
    const value = form.auth_header_value.trim();
    if (value && !header) return "Name the header the value is sent in.";
    if (header) {
      if (!HEADER_NAME.test(header)) return `'${header}' is not a valid header name.`;
      const lower = header.toLowerCase();
      if (RESERVED_HEADERS.includes(lower) || lower.startsWith("webhook-"))
        return `tokenless sets ${header} itself; use another header.`;
      if (!value && !keepsStoredHeader(form, current)) return `Enter the value sent in ${header}.`;
    }
  }
  for (const prefix of items(form.action_prefixes)) {
    if (!ACTION_PREFIX.test(prefix))
      return `'${prefix}' is not an action: use a-z, 0-9, '.' and '_', such as credential. or proxy.inject.`;
  }
  return null;
}

export function destinationInput(form: DestinationForm, current: AuditDestination | null): AuditDestinationInput {
  const filter = {
    action_prefixes: items(form.action_prefixes),
    outcomes: form.outcomes,
    vault_ids: items(form.vault_ids),
  };
  const base = { name: form.name.trim(), url: form.url.trim(), format: form.format, filter };
  if (form.clear_auth_header) return { ...base, auth_header_name: null, clear_auth_header: true };
  const header = form.auth_header_name.trim();
  if (!header) return { ...base, auth_header_name: null };
  if (keepsStoredHeader(form, current)) return { ...base, auth_header_name: header };
  return { ...base, auth_header_name: header, auth_header_value: form.auth_header_value.trim() };
}

/** How a destination's delivery reads in a list. */
export function deliveryStatus(d: Pick<AuditDestination, "status" | "behind">): {
  label: string;
  tone: "success" | "warning" | "destructive" | "neutral";
} {
  const status: DeliveryStatus = d.status;
  switch (status) {
    case "up_to_date":
      return { label: "Up to date", tone: "success" };
    case "sending":
      return { label: `Sending, ${behindText(d.behind)}`, tone: "neutral" };
    case "retrying":
      return { label: "Retrying", tone: "warning" };
    case "failing":
      return { label: "Failing", tone: "destructive" };
    case "paused":
      return { label: "Paused", tone: "neutral" };
  }
}

export function behindText(behind: number): string {
  return behind === 1 ? "1 event behind" : `${behind.toLocaleString("en-US")} events behind`;
}

/** Destinations that need someone to look at them, for the Audit page. */
export function failingDestinations(list: AuditDestination[]): AuditDestination[] {
  return list.filter((d) => d.status === "failing");
}
