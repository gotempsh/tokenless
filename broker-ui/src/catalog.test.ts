// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { describe, expect, test } from "bun:test";
import type { StoredTemplate, TemplateCategory } from "./api";
import { activeShelf, catalogShelves, shelfItems } from "./catalog";

function tpl(
  id: string,
  category: TemplateCategory,
  opts: { popular?: boolean; pending?: boolean } = {},
): StoredTemplate {
  return {
    template: {
      id,
      version: 1,
      name: id,
      description: "",
      category,
      kind: "http",
      popular: opts.popular,
      hosts: [],
      allow: { paths: [], methods: [] },
      credential_fields: [],
      injection: { method: "bearer", field: "token" },
      host_override: { allowed: false, required: false },
    },
    yaml: "",
    source: opts.pending ? "imported" : "builtin",
    status: opts.pending ? "pending_approval" : "approved",
    imported_by: null,
    approved_by: null,
    created_at: "2026-01-01T00:00:00Z",
  };
}

const list = [
  tpl("acme-llm", "llm_providers", { popular: true }),
  tpl("beta-llm", "llm_providers"),
  tpl("generic-bearer", "custom"),
  tpl("pager", "monitoring", { popular: true }),
  tpl("imported-tool", "developer_tools", { pending: true }),
];

describe("shelfItems", () => {
  test("popular puts the custom bearer template first", () => {
    expect(shelfItems(list, "popular").map((t) => t.template.id)).toEqual(["generic-bearer", "acme-llm", "pager"]);
  });

  test("a category and all leave pending imports out", () => {
    expect(shelfItems(list, "llm_providers").map((t) => t.template.id)).toEqual(["acme-llm", "beta-llm"]);
    expect(shelfItems(list, "developer_tools")).toEqual([]);
    expect(shelfItems(list, "all")).toHaveLength(4);
  });

  test("pending holds only imports awaiting approval", () => {
    expect(shelfItems(list, "pending").map((t) => t.template.id)).toEqual(["imported-tool"]);
  });
});

describe("catalogShelves", () => {
  test("counts each shelf and drops empty categories", () => {
    expect(catalogShelves(list)).toEqual([
      { key: "pending", label: "Waiting for approval", count: 1 },
      { key: "popular", label: "Popular", count: 3 },
      { key: "all", label: "All services", count: 4 },
      { key: "llm_providers", label: "LLM providers", count: 2 },
      { key: "monitoring", label: "Monitoring", count: 1 },
      { key: "custom", label: "Custom", count: 1 },
    ]);
  });

  test("an empty list still offers all services", () => {
    expect(catalogShelves([])).toEqual([{ key: "all", label: "All services", count: 0 }]);
  });
});

describe("activeShelf", () => {
  const shelves = (l: StoredTemplate[]) => catalogShelves(l);

  test("a search whose only match awaits approval shows that shelf", () => {
    const matching = list.filter((t) => t.template.id === "imported-tool");
    expect(activeShelf(shelves(matching), "all", true)?.key).toBe("pending");
  });

  test("keeps the chosen shelf while it has matches", () => {
    expect(activeShelf(shelves(list), "all", true)?.key).toBe("all");
    expect(activeShelf(shelves(list), "monitoring", false)?.key).toBe("monitoring");
  });

  test("a shelf the filters removed falls back to all services", () => {
    const llms = list.filter((t) => t.template.category === "llm_providers");
    expect(activeShelf(shelves(llms), "monitoring", false)?.key).toBe("all");
  });

  test("with no match anywhere, all services (and its empty state)", () => {
    expect(activeShelf(shelves([]), "all", true)?.key).toBe("all");
  });
});
