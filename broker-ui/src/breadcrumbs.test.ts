// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { describe, expect, test } from "bun:test";
import { backCrumbs, trail } from "./breadcrumbs";

describe("trail", () => {
  test("a page without its own trail shows its section", () => {
    expect(trail("Vaults", null)).toEqual([{ label: "Vaults" }]);
    expect(trail("Vaults", [])).toEqual([{ label: "Vaults" }]);
  });

  test("the current page never links", () => {
    expect(
      trail("Vaults", [
        { label: "Vaults", href: "#/vaults" },
        { label: "ui-check", href: "#/vaults/v1/credentials" },
      ]),
    ).toEqual([{ label: "Vaults", href: "#/vaults" }, { label: "ui-check" }]);
  });
});

describe("backCrumbs", () => {
  test("a vault page names the vault", () => {
    expect(backCrumbs("vaults/v1/bundles", { vault: "work" })).toEqual([
      { label: "Vaults", href: "#/vaults" },
      { label: "work", href: "#/vaults/v1/bundles" },
    ]);
  });

  test("a name still loading is null, not an ID", () => {
    expect(backCrumbs("bundles/b1", {})).toEqual([
      { label: "Access bundles", href: "#/bundles" },
      { label: null, href: "#/bundles/b1" },
    ]);
  });

  test("section lists and unknown paths", () => {
    expect(backCrumbs("bundles", {})).toEqual([{ label: "Access bundles", href: "#/bundles" }]);
    expect(backCrumbs("templates", {})).toEqual([{ label: "Templates", href: "#/templates" }]);
    expect(backCrumbs(undefined, {})).toEqual([]);
    expect(backCrumbs("settings", {})).toEqual([]);
  });
});
