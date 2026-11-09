// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { describe, expect, test } from "bun:test";
import type { OidcProvider } from "./api";
import {
  callbackUri,
  newProviderForm,
  providerForm,
  providerFormProblem,
  providerInput,
  readSsoError,
  returnToHere,
  slugFromName,
  ssoStartHref,
} from "./sso";

describe("sign-in links", () => {
  test("start at the provider and come back to this page", () => {
    expect(ssoStartHref("corp", "/#/vaults")).toBe("/api/v1/auth/oidc/corp/start?return_to=%2F%23%2Fvaults");
    expect(ssoStartHref("corp", "/", "step_up")).toBe("/api/v1/auth/oidc/corp/start?return_to=%2F&purpose=step_up");
    expect(ssoStartHref("a b", "/")).toContain("/oidc/a%20b/start");
  });

  test("come back to a path on this instance only", () => {
    expect(returnToHere({ pathname: "/", hash: "#/settings" })).toBe("/#/settings");
    expect(returnToHere({ pathname: "", hash: "" })).toBe("/");
    expect(returnToHere({ pathname: "//elsewhere.example", hash: "" })).toBe("/");
    expect(returnToHere({ pathname: "/", hash: `#/${"x".repeat(600)}` })).toBe("/");
  });

  test("the redirect URI is this instance's callback", () => {
    expect(callbackUri("https://broker.example/")).toBe("https://broker.example/api/v1/auth/oidc/callback");
  });
});

describe("errors coming back from the provider", () => {
  test("are read and taken out of the query", () => {
    expect(readSsoError("?sso_error=no+mapped+group")).toEqual({ error: "no mapped group", search: "" });
    expect(readSsoError("?a=1&sso_error=x")).toEqual({ error: "x", search: "?a=1" });
    expect(readSsoError("?sso_error=")).toEqual({ error: "Single sign-on failed.", search: "" });
    expect(readSsoError("?a=1")).toEqual({ error: null, search: "?a=1" });
  });
});

describe("the provider form", () => {
  const filled = () => ({
    ...newProviderForm("https://broker.example"),
    name: "Corp",
    slug: "corp",
    issuer: "https://idp.example",
    client_id: "tokenless",
    role_mappings: [
      { group: " broker-admins ", role: "admin" as const },
      { group: "", role: "viewer" as const },
    ],
  });

  test("starts with this instance's redirect URI and the usual claims", () => {
    const form = newProviderForm("https://broker.example");
    expect(form.redirect_uri).toBe("https://broker.example/api/v1/auth/oidc/callback");
    expect(form.groups_claim).toBe("groups");
    expect(form.username_claim).toBe("preferred_username");
  });

  test("sends trimmed fields, drops empty mapping rows and openid", () => {
    const input = providerInput({ ...filled(), scopes: "openid profile, email  groups" });
    expect(input.scopes).toEqual(["profile", "email", "groups"]);
    expect(input.role_mappings).toEqual([{ group: "broker-admins", role: "admin" }]);
    expect("client_secret" in input).toBe(false);
    expect(input.clear_client_secret).toBe(false);
  });

  test("a new secret replaces the stored one; removing needs no new one", () => {
    expect(providerInput({ ...filled(), client_secret: " s3 ", clear_client_secret: true })).toMatchObject({
      client_secret: "s3",
      clear_client_secret: false,
    });
    expect(providerInput({ ...filled(), clear_client_secret: true }).clear_client_secret).toBe(true);
  });

  test("says what is missing", () => {
    expect(providerFormProblem(filled())).toBeNull();
    expect(providerFormProblem({ ...filled(), issuer: " " })).toContain("issuer");
    expect(providerFormProblem({ ...filled(), role_mappings: [{ group: "", role: "viewer" }] })).toContain(
      "at least one group",
    );
    expect(
      providerFormProblem({
        ...filled(),
        role_mappings: [
          { group: "ops", role: "viewer" },
          { group: "ops ", role: "admin" },
        ],
      }),
    ).toContain("'ops' is mapped twice");
  });

  test("editing shows the provider but never a secret", () => {
    const p: OidcProvider = {
      id: "p1",
      slug: "corp",
      name: "Corp",
      issuer: "https://idp.example",
      client_id: "tokenless",
      has_client_secret: true,
      redirect_uri: "https://broker.example/api/v1/auth/oidc/callback",
      scopes: ["profile", "email"],
      groups_claim: "groups",
      username_claim: "email",
      role_mappings: [],
      enabled: false,
      created_at: "2026-01-01T00:00:00Z",
      updated_at: "2026-01-01T00:00:00Z",
    };
    const form = providerForm(p);
    expect(form.client_secret).toBe("");
    expect(form.scopes).toBe("profile email");
    expect(form.role_mappings).toEqual([{ group: "", role: "viewer" }]);
    expect(form.enabled).toBe(false);
  });

  test("slugs come from the name, within what the server accepts", () => {
    expect(slugFromName("Corp Login (EU)")).toBe("corp-login-eu");
    expect(slugFromName("  ")).toBe("");
    const long = slugFromName("Example Corporate Identity Provider");
    expect(long).toBe("example-corporate-identity-provi");
    expect(long.length).toBeLessThanOrEqual(32);
    // A cut that lands on a separator leaves none at the end.
    expect(slugFromName("Example Corporate Identity Ab Cd")).toBe("example-corporate-identity-ab-cd");
    expect(slugFromName("Example Corporate Identity Abcd Efg")).toBe("example-corporate-identity-abcd");
    expect(providerFormProblem({ ...filled(), slug: long })).toBeNull();
  });

  test("a slug the server would refuse is caught first", () => {
    for (const slug of ["x", "-corp", "Corp", "corp_eu", "a".repeat(33)]) {
      expect(providerFormProblem({ ...filled(), slug })).toContain("slug");
    }
  });
});
