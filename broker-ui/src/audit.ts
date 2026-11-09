// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import type { AuditEvent } from "./api";

/** The audit filter: what a person looks for, mapped to an action prefix. */
export interface AuditCategory {
  label: string;
  prefix: string;
}

export const ALL_EVENTS: AuditCategory = { label: "All events", prefix: "" };

export const AUDIT_CATEGORIES: AuditCategory[] = [
  ALL_EVENTS,
  { label: "Agent requests", prefix: "proxy." },
  { label: "Sessions", prefix: "session." },
  { label: "Sign-ins", prefix: "auth." },
  { label: "Services", prefix: "credential." },
  { label: "Rules", prefix: "rule." },
  { label: "Bundles", prefix: "bundle." },
  { label: "Variables", prefix: "variable." },
  { label: "Vaults", prefix: "vault." },
  { label: "People", prefix: "user." },
  { label: "API keys", prefix: "api_key." },
  { label: "Proxies", prefix: "node." },
  { label: "Templates", prefix: "template." },
  { label: "Settings", prefix: "settings." },
  { label: "Audit export", prefix: "audit_export." },
];

/** Names for the identifiers an actor can carry, from lists the page loaded. */
export interface ActorNames {
  meId?: string;
  users?: Map<string, string>;
  apiKeys?: Map<string, string>;
  nodes?: Map<string, string>;
}

const short = (id: string) => id.slice(0, 8);

/** Who did it, in words: "You", a username, "API key ci-runner", "Proxy edge-1". */
export function actorLabel(event: AuditEvent, names: ActorNames): string {
  return actorName(event.actor, names, event.detail.username);
}

/** {@link actorLabel} for an actor recorded outside an event, such as a session's creator. */
export function actorName(actor: string, names: ActorNames, username?: string): string {
  const [kind, id = ""] = splitOnce(actor, ":");
  switch (kind) {
    case "user":
      if (id === names.meId) return "You";
      return names.users?.get(id) ?? username ?? `Person ${short(id)}`;
    case "api_key":
      return `API key ${names.apiKeys?.get(id) ?? id}`;
    case "node":
      return `Proxy ${names.nodes?.get(id) ?? short(id)}`;
    case "session":
      return "An agent";
    case "anonymous":
      return "Someone";
    case "system":
      return "tokenless";
    default:
      return actor;
  }
}

/** What happened, as the rest of a sentence that starts with the actor. */
export function actionPhrase(event: AuditEvent): string {
  const d = event.detail;
  const named = (noun: string, name = d.name) => (name ? `${noun} ${name}` : `a ${noun}`);
  const request = [d.method, `${hostOnly(d.host)}${d.path ?? ""}`].filter(Boolean).join(" ");
  switch (event.action) {
    case "auth.login":
      return event.outcome === "success" ? "signed in" : `failed to sign in${d.username ? ` as ${d.username}` : ""}`;
    case "auth.logout":
      return "signed out";
    case "auth.setup":
      return "set up this console";
    case "auth.step_up":
      return "confirmed their sign-in";
    case "credential.create":
      return `added ${named("service")}`;
    case "credential.rotate":
      return `replaced the secret of ${named("service")}`;
    case "credential.validate":
      return `tested a service${tested(event)}`;
    case "credential.update_headers":
      return `changed the headers of ${named("service")}`;
    case "credential.update_substitutions":
      return `changed the placeholders of ${named("service")}`;
    case "credential.delete":
      return `deleted ${named("service")}`;
    case "rule.create":
      return `added a rule${d.hosts ? ` for ${d.hosts}` : ""}`;
    case "rule.update":
      return "changed a rule";
    case "rule.delete":
      return "deleted a rule";
    case "bundle.create":
      return `created ${named("bundle")}`;
    case "bundle.update":
      return `changed ${named("bundle")}`;
    case "bundle.delete":
      return `deleted ${named("bundle")}`;
    case "session.mint":
      return d.bundle ? `started a session with ${d.bundle}` : "started a session";
    case "session.revoke":
      return "ended a session";
    case "session.update_labels":
      return "relabelled a session";
    case "vault.create":
      return `created ${named("vault")}`;
    case "vault.delete":
      return `deleted ${named("vault")}`;
    case "variable.create":
      return `added ${named("variable")}`;
    case "variable.update":
      return `replaced ${named("variable")}`;
    case "variable.delete":
      return `deleted ${named("variable")}`;
    case "user.invite":
      return d.role ? `invited someone as ${d.role}` : "invited someone";
    case "user.invite.accept":
      return "accepted an invite";
    case "user.invite.revoke":
      return "withdrew an invite";
    case "user.update":
      return `changed ${d.username ? `${d.username}'s account` : "an account"}`;
    case "api_key.create":
      return `created ${named("API key")}`;
    case "api_key.revoke":
      return `revoked ${named("API key")}`;
    case "node.join_token.create":
      return "created a proxy join token";
    case "node.enroll":
      return event.outcome === "success" ? `enrolled ${named("proxy")}` : "tried to enroll a proxy";
    case "node.renew":
      return "renewed its certificate";
    case "node.revoke":
      return `revoked ${named("proxy")}`;
    case "template.import":
      return `imported ${named("template")}`;
    case "template.approve":
      return `approved ${named("template")}`;
    case "settings.update":
      return "changed the settings";
    case "audit_export.create":
      return `added ${named("audit webhook")}`;
    case "audit_export.update":
      return `changed ${named("audit webhook")}`;
    case "audit_export.delete":
      return `deleted ${named("audit webhook")}`;
    case "audit_export.pause":
      return `paused ${named("audit webhook")}`;
    case "audit_export.resume":
      return `resumed ${named("audit webhook")}`;
    case "audit_export.rotate_secret":
      return `made a new signing secret for ${named("audit webhook")}`;
    case "audit_export.skip":
      return `skipped ${d.skipped === "1" ? "1 event" : `${d.skipped ?? "the"} events`} for ${named("audit webhook")}`;
    case "audit_export.test":
      return event.outcome === "success" ? `sent a test to ${named("audit webhook")}` : `failed to send a test to ${named("audit webhook")}`;
    case "proxy.inject":
      return `added a credential to ${request}`;
    case "proxy.response":
      return `got ${d.status ? `a ${d.status}` : "an answer"} for ${request}`;
    case "proxy.deny":
      return `refused ${request}`;
    case "proxy.connect_denied":
      return `refused a connection to ${hostOnly(d.host)}`;
    case "proxy.gateway_denied":
      return `refused an MCP call to ${hostOnly(d.host)}`;
    case "proxy.egress_blocked":
      return `blocked a connection to ${hostOnly(d.host)}, a private address`;
    case "proxy.tunnel":
      return `passed a connection to ${hostOnly(d.host)} through untouched`;
    default:
      return event.action;
  }
}

/** {@link actionPhrase}, said of "the session" since the page is about one. */
export function sessionHistoryPhrase(e: AuditEvent): string {
  const labels = Object.entries(e.detail)
    .filter(([k]) => k.startsWith("label."))
    .map(([k, v]) => `${k.slice(6)}=${v}`)
    .join(", ");
  switch (e.action) {
    case "session.mint":
      return e.detail.bundle ? `created the session from ${e.detail.bundle}` : "created the session";
    case "session.revoke":
      if (e.detail.already_revoked === "true") return "revoked the session again";
      return e.detail.by === "session token" ? "ended the session with its own token" : "revoked the session";
    case "session.update_labels":
      return labels ? `set the labels to ${labels}` : "removed the labels";
    default:
      return actionPhrase(e);
  }
}

/** {@link actionPhrase}, said of "the service" since the page is about one. */
export function serviceHistoryPhrase(e: AuditEvent): string {
  switch (e.action) {
    case "credential.create":
      return "added the service";
    case "credential.rotate":
      return "replaced the secret";
    case "credential.validate":
      return `tested the service${tested(e)}`;
    case "credential.update_headers":
      return "changed the custom headers";
    case "credential.update_substitutions":
      return "changed the placeholders";
    default:
      return actionPhrase(e);
  }
}

/** How a service test went: ": it worked (200)", ": it failed (401)". */
function tested(e: AuditEvent): string {
  const status = e.detail.status && e.detail.status !== "none" ? ` (${e.detail.status})` : "";
  return e.outcome === "success" ? `: it worked${status}` : `: it failed${status}`;
}

/** `api.example.com:443` reads as `api.example.com`; other ports stay. */
export function hostOnly(host: string | undefined): string {
  if (!host) return "a host";
  return host.endsWith(":443") ? host.slice(0, -4) : host;
}

function splitOnce(value: string, sep: string): [string, string?] {
  const i = value.indexOf(sep);
  return i < 0 ? [value] : [value.slice(0, i), value.slice(i + 1)];
}
