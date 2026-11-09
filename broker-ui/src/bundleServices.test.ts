// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { describe, expect, test } from "bun:test";
import type { AccessBundle, CredentialMeta, Rule, StoredTemplate } from "./api";
import { bundleRules, ruleServices, templateOf } from "./bundleServices";

const rule = (id: string, credential: string, enabled = true) =>
  ({ id, name: `rule-${id}`, credential_id: credential, enabled }) as Rule;
const credential = (id: string, name: string, template: string, version = 1) =>
  ({ id, name, template_id: template, template_version: version }) as CredentialMeta;
const template = (id: string, version: number, logo?: string) =>
  ({ template: { id, version, kind: "http", logo } }) as unknown as StoredTemplate;

describe("bundle services", () => {
  test("a credential's template is the one at its version", () => {
    const templates = [template("github", 1, "old"), template("github", 2, "new")];
    expect(templateOf(templates, credential("c", "gh", "github", 2))?.logo).toBe("new");
    expect(templateOf(templates, credential("c", "gh", "github", 3))).toBeUndefined();
  });

  test("each rule is named after its credential and shows its template's logo", () => {
    const services = ruleServices(
      [rule("r1", "c1"), rule("r2", "c2", false)],
      [credential("c1", "work-github", "github"), credential("c2", "stripe-test", "stripe")],
      [template("github", 1), template("stripe", 1)],
    );
    expect(services.map((s) => [s.name, s.logo?.id, s.off])).toEqual([
      ["work-github", "github", false],
      ["stripe-test", "stripe", true],
    ]);
  });

  test("a rule whose credential did not load keeps its own name and a generic logo", () => {
    const [s] = ruleServices([rule("r1", "gone")], [], []);
    expect(s).toMatchObject({ name: "rule-r1", logo: { id: "", kind: "http" } });
  });

  test("a bundle's rules in its order, without the ones not found", () => {
    const byId = new Map([rule("a", "c"), rule("b", "c")].map((r) => [r.id, r]));
    const b = { rule_ids: ["b", "missing", "a"] } as AccessBundle;
    expect(bundleRules(b, byId).map((r) => r.id)).toEqual(["b", "a"]);
  });
});
