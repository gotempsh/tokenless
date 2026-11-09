// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { describe, expect, test } from "bun:test";
import { bundleFormHref, parseBundleFormContext } from "./bundleForm";

/** Splits a hash link the way the router does: route parts and query. */
function route(href: string): { parts: string[]; query: URLSearchParams } {
  const [path = "", qs = ""] = href.replace(/^#\//, "").split("?");
  return { parts: path.split("/"), query: new URLSearchParams(qs) };
}

describe("bundleFormHref", () => {
  test("a new bundle carries its vault and the way back", () => {
    expect(bundleFormHref({ vault: "v1", back: "vaults/v1/bundles" })).toBe(
      "#/bundles/new?vault=v1&back=vaults%2Fv1%2Fbundles",
    );
    expect(bundleFormHref()).toBe("#/bundles/new");
  });

  test("editing names the bundle and ignores a vault", () => {
    expect(bundleFormHref({ bundle: "b1", vault: "v1" })).toBe("#/bundles/b1/edit");
  });
});

describe("parseBundleFormContext", () => {
  test("reads back what the link wrote", () => {
    const create = route(bundleFormHref({ vault: "v1", back: "bundles" }));
    expect(parseBundleFormContext(undefined, create.query)).toEqual({ bundle: undefined, vault: "v1", back: "bundles" });
    const edit = route(bundleFormHref({ bundle: "b1", back: "bundles/b1" }));
    expect(parseBundleFormContext(edit.parts[1], edit.query)).toEqual({ bundle: "b1", vault: undefined, back: "bundles/b1" });
  });

  test("refuses a way back that leaves the console", () => {
    const q = new URLSearchParams({ back: "https://elsewhere.example/" });
    expect(parseBundleFormContext(undefined, q).back).toBeUndefined();
  });
});
