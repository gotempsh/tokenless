// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Single sign-on in the console: the links that send the browser to an
// identity provider, the error it comes back with, and the provider form.

import type { OidcProvider, OidcProviderInput, RoleMapping } from "./api";

/** The server's limit on where a sign-in may return to. */
const MAX_RETURN_TO = 512;

export const CALLBACK_PATH = "/api/v1/auth/oidc/callback";

/** The redirect URI to register at the provider for this instance. */
export function callbackUri(origin: string): string {
  return `${origin.replace(/\/+$/, "")}${CALLBACK_PATH}`;
}

/** This page, as the place to come back to after the provider. */
export function returnToHere(location: { pathname: string; hash: string }): string {
  const here = `${location.pathname || "/"}${location.hash}`;
  return here.startsWith("/") && !here.startsWith("//") && here.length <= MAX_RETURN_TO ? here : "/";
}

/** Where to send the browser to sign in, or to prove it is them again. */
export function ssoStartHref(slug: string, returnTo: string, purpose: "login" | "step_up" = "login"): string {
  const query = new URLSearchParams({ return_to: returnTo });
  if (purpose === "step_up") query.set("purpose", "step_up");
  return `/api/v1/auth/oidc/${encodeURIComponent(slug)}/start?${query.toString()}`;
}

/**
 * The reason a sign-in or step-up failed, which the server puts in
 * `sso_error`, and the query string without it.
 */
export function readSsoError(search: string): { error: string | null; search: string } {
  const query = new URLSearchParams(search);
  const error = query.get("sso_error");
  if (error === null) return { error: null, search };
  query.delete("sso_error");
  const rest = query.toString();
  return { error: error.trim() || "Single sign-on failed.", search: rest ? `?${rest}` : "" };
}

/**
 * A step-up at the provider happens in a popup, so the page that asked
 * keeps its state (a half-filled form). The popup comes back to this
 * console route, which reports on {@link STEP_UP_CHANNEL} and closes.
 */
export const STEP_UP_DONE_ROUTE = "step-up-done";
export const STEP_UP_CHANNEL = "tokenless-step-up";

export interface StepUpMessage {
  ok: boolean;
  error: string | null;
}

/** Reads `sso_error` once and takes it out of the address bar. */
export function takeSsoError(): string | null {
  const { error, search } = readSsoError(window.location.search);
  if (error !== null) {
    window.history.replaceState(null, "", `${window.location.pathname}${search}${window.location.hash}`);
  }
  return error;
}

export interface ProviderForm {
  name: string;
  slug: string;
  issuer: string;
  client_id: string;
  /** Empty keeps the stored secret when editing. */
  client_secret: string;
  clear_client_secret: boolean;
  redirect_uri: string;
  /** Space- or comma-separated; `openid` is always asked for. */
  scopes: string;
  groups_claim: string;
  username_claim: string;
  role_mappings: RoleMapping[];
  enabled: boolean;
}

export function newProviderForm(origin: string): ProviderForm {
  return {
    name: "",
    slug: "",
    issuer: "",
    client_id: "",
    client_secret: "",
    clear_client_secret: false,
    redirect_uri: callbackUri(origin),
    scopes: "profile email",
    groups_claim: "groups",
    username_claim: "preferred_username",
    role_mappings: [{ group: "", role: "viewer" }],
    enabled: true,
  };
}

export function providerForm(p: OidcProvider): ProviderForm {
  return {
    name: p.name,
    slug: p.slug,
    issuer: p.issuer,
    client_id: p.client_id,
    client_secret: "",
    clear_client_secret: false,
    redirect_uri: p.redirect_uri,
    scopes: p.scopes.join(" "),
    groups_claim: p.groups_claim,
    username_claim: p.username_claim,
    role_mappings: p.role_mappings.length ? p.role_mappings.map((m) => ({ ...m })) : [{ group: "", role: "viewer" }],
    enabled: p.enabled,
  };
}

/** What the server accepts as a slug. */
export const SLUG_MAX = 32;
const SLUG = /^[a-z0-9][a-z0-9-]{1,31}$/;

/** A slug for the sign-in URL, from the provider's name. */
export function slugFromName(name: string): string {
  return name
    .toLowerCase()
    .normalize("NFKD")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+/, "")
    .slice(0, SLUG_MAX)
    .replace(/-+$/, "");
}

function mappings(form: ProviderForm): RoleMapping[] {
  return form.role_mappings
    .map((m) => ({ group: m.group.trim(), role: m.role }))
    .filter((m) => m.group !== "");
}

/** What would stop the server accepting the form, before sending it. */
export function providerFormProblem(form: ProviderForm): string | null {
  if (!form.name.trim()) return "Give the provider a name for the sign-in button.";
  if (!form.slug.trim()) return "Give the provider a slug for its sign-in URL.";
  if (!SLUG.test(form.slug.trim()))
    return `The slug takes 2-${SLUG_MAX} characters of a-z, 0-9 and '-', not starting with '-'.`;
  if (!form.issuer.trim()) return "Enter the issuer URL from the provider.";
  if (!form.client_id.trim()) return "Enter the client ID the provider gave this instance.";
  const rows = mappings(form);
  if (rows.length === 0) return "Map at least one group to a role: nobody can sign in without one.";
  const seen = new Set<string>();
  for (const { group } of rows) {
    if (seen.has(group)) return `The group '${group}' is mapped twice.`;
    seen.add(group);
  }
  return null;
}

export function providerInput(form: ProviderForm): OidcProviderInput {
  const secret = form.client_secret.trim();
  return {
    name: form.name.trim(),
    slug: form.slug.trim(),
    issuer: form.issuer.trim(),
    client_id: form.client_id.trim(),
    ...(secret ? { client_secret: secret } : {}),
    clear_client_secret: !secret && form.clear_client_secret,
    redirect_uri: form.redirect_uri.trim(),
    scopes: form.scopes.split(/[\s,]+/).filter((s) => s !== "" && s !== "openid"),
    groups_claim: form.groups_claim.trim(),
    username_claim: form.username_claim.trim(),
    role_mappings: mappings(form),
    enabled: form.enabled,
  };
}
