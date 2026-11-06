// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { describe, expect, test } from "bun:test";
import type { CredentialMeta, Substitution } from "./api";
import { envFile, envReferences, execCommand, runAgentCommand, shellQuote } from "./bundleConnect";

const at = "2026-01-01T00:00:00Z";

function credential(name: string, template: string, substitutions: Substitution[]): CredentialMeta {
  return {
    id: name,
    vault_id: "v1",
    name,
    template_id: template,
    template_version: 1,
    host_override: [],
    field_names: substitutions.map((s) => s.field),
    custom_headers: [],
    variable_refs: [],
    substitutions,
    created_by: "u",
    created_at: at,
    updated_at: at,
  };
}

const sub = (field: string, env?: string): Substitution => ({
  placeholder: `__${field.toUpperCase()}__`,
  field,
  env,
  locations: ["header"],
});

describe("bundle connect commands", () => {
  test("quotes only what the shell would split", () => {
    expect(shellQuote("code-review")).toBe("code-review");
    expect(shellQuote("cb://github/token")).toBe("cb://github/token");
    expect(shellQuote("cb://Work GitHub/token")).toBe("'cb://Work GitHub/token'");
    expect(shellQuote("it's")).toBe(`'it'\\''s'`);
  });

  test("references are named after the placeholder's variable, first one wins", () => {
    const refs = envReferences([
      credential("Work GitHub", "github", [sub("token", "GITHUB_TOKEN")]),
      credential("Mail", "smtp", [sub("user"), sub("password")]),
      credential("Other GitHub", "github", [sub("token", "GITHUB_TOKEN")]),
    ]);
    expect(refs.map((r) => [r.name, r.reference])).toEqual([
      ["GITHUB_TOKEN", "cb://Work GitHub/token"],
      ["SMTP_USER", "cb://Mail/user"],
      ["SMTP_PASSWORD", "cb://Mail/password"],
    ]);
  });

  test("commands and the env file carry the references", () => {
    const refs = envReferences([credential("Work GitHub", "github", [sub("token", "GITHUB_TOKEN")])]);
    expect(runAgentCommand("code-review", "claude", "main vault")).toBe(
      "credential-broker run --vault 'main vault' --bundle code-review -- claude",
    );
    expect(execCommand("code-review", refs)).toBe(
      "credential-broker exec --bundle code-review \\\n  GITHUB_TOKEN='cb://Work GitHub/token' \\\n  -- ./script.sh",
    );
    expect(envFile(refs)).toBe('# References, not secrets: safe to commit.\nGITHUB_TOKEN="cb://Work GitHub/token"\n');
  });
});
