// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { describe, expect, test } from "bun:test";
import type { AccessBundle } from "./api";
import { bundleChoices, chosenIn, ruleCount } from "./bundleChoice";

function bundle(name: string, rules = 1, description = ""): AccessBundle {
  return {
    id: `b-${name}`,
    vault_id: "v",
    name,
    description,
    rule_ids: Array.from({ length: rules }, (_, i) => `r${i}`),
    created_by: "user:u",
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
  };
}

const names = (c: { shown: AccessBundle[] }) => c.shown.map((b) => b.name);

describe("bundle choices", () => {
  test("a few bundles are all listed, with no filter", () => {
    const c = bundleChoices([bundle("billing-agent", 4), bundle("code-review")], "", "");
    expect(names(c)).toEqual(["billing-agent", "code-review"]);
    expect(c).toMatchObject({ hidden: 0, filterable: false });
  });

  test("past the limit, the rest wait for a filter", () => {
    const many = Array.from({ length: 9 }, (_, i) => bundle(`bundle-${i}`));
    const c = bundleChoices(many, "", "", 6);
    expect(c.shown).toHaveLength(6);
    expect(c).toMatchObject({ hidden: 3, filterable: true });
  });

  test("the filter matches names and descriptions, ignoring case", () => {
    const list = [bundle("billing-agent"), bundle("code-review", 1, "Reviews pull requests"), bundle("deploy")];
    expect(names(bundleChoices(list, "BILL", ""))).toEqual(["billing-agent"]);
    expect(names(bundleChoices(list, "pull", ""))).toEqual(["code-review"]);
    expect(bundleChoices(list, "nothing", "").shown).toEqual([]);
  });

  test("the chosen bundle stays listed when the filter or the limit leaves it out", () => {
    const many = Array.from({ length: 9 }, (_, i) => bundle(`bundle-${i}`));
    const c = bundleChoices(many, "", "b-bundle-8", 6);
    expect(names(c)[0]).toBe("bundle-8");
    expect(c.shown).toHaveLength(6);
    expect(c.hidden).toBe(3);
    expect(names(bundleChoices(many, "bundle-1", "b-bundle-8", 6))).toEqual(["bundle-8", "bundle-1"]);
  });

  test("the only bundle is chosen; with several, nothing is until someone picks", () => {
    expect(chosenIn([bundle("code-review")], "")).toBe("b-code-review");
    expect(chosenIn([bundle("a"), bundle("b")], "")).toBe("");
    expect(chosenIn([bundle("a"), bundle("b")], "b-b")).toBe("b-b");
    expect(chosenIn([], "")).toBe("");
  });

  test("a bundle chosen in another vault is not chosen here", () => {
    expect(chosenIn([bundle("a"), bundle("b")], "b-elsewhere")).toBe("");
    expect(chosenIn([bundle("only")], "b-elsewhere")).toBe("b-only");
  });

  test("rule counts read naturally", () => {
    expect(ruleCount(bundle("a", 1))).toBe("1 rule");
    expect(ruleCount(bundle("a", 4))).toBe("4 rules");
  });
});
