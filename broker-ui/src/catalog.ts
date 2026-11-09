// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Presentation of the template catalogue: categories, search and the
// "latest version per service" view. Nothing here affects injection.

import type { ServiceKind, ServiceTemplate, StoredTemplate, TemplateCategory } from "./api";

export const CATEGORIES: { value: TemplateCategory; label: string }[] = [
  { value: "llm_providers", label: "LLM providers" },
  { value: "developer_tools", label: "Developer tools" },
  { value: "infrastructure", label: "Infrastructure" },
  { value: "communication", label: "Communication" },
  { value: "monitoring", label: "Monitoring" },
  { value: "productivity", label: "Productivity" },
  { value: "payments", label: "Payments" },
  { value: "commerce", label: "Commerce" },
  { value: "search", label: "Search" },
  { value: "custom", label: "Custom" },
];

export const CATEGORY_LABEL = Object.fromEntries(CATEGORIES.map((c) => [c.value, c.label])) as Record<
  TemplateCategory,
  string
>;

export const KIND_LABEL: Record<ServiceKind, string> = { http: "HTTP API", mcp: "MCP server" };

/** The newest approved version of each service, plus any pending imports. */
export function latestTemplates(all: StoredTemplate[]): StoredTemplate[] {
  const best = new Map<string, StoredTemplate>();
  for (const t of all) {
    const key = t.status === "approved" ? t.template.id : `${t.template.id}@${t.template.version}`;
    const current = best.get(key);
    if (!current || t.template.version > current.template.version) best.set(key, t);
  }
  return [...best.values()].sort((a, b) => a.template.name.localeCompare(b.template.name));
}

export function matchesSearch(t: ServiceTemplate, query: string): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  return [t.name, t.id, t.description, ...t.hosts, ...(t.aliases ?? [])].some((s) => s.toLowerCase().includes(q));
}

/** The catalogue's popular picks, alphabetically. */
export function popularTemplates(list: StoredTemplate[]): StoredTemplate[] {
  return list.filter((t) => t.template.popular && t.status === "approved");
}

export function injectionSummary(t: ServiceTemplate): string {
  switch (t.injection.method) {
    case "bearer":
      return `Authorization: Bearer <${t.injection.field}>`;
    case "basic":
      return `Authorization: Basic <${t.injection.username_field}:${t.injection.password_field}>`;
    case "basic_token":
      return `Authorization: Basic ${t.injection.username}:<${t.injection.password_field}>`;
    case "header":
      return `${t.injection.name}: ${t.injection.prefix ?? ""}<${t.injection.field}>`;
  }
}

/** Where a credential's requests go, for lists: its override or its template's hosts. */
export function targetHosts(t: ServiceTemplate | undefined, hostOverride: string[]): string[] {
  if (hostOverride.length) return hostOverride;
  return t?.hosts ?? [];
}

/** A shelf of the catalogue's rail: popular picks, everything, one category, or imports awaiting approval. */
export type Shelf = "popular" | "all" | "pending" | TemplateCategory;

export interface ShelfEntry {
  key: Shelf;
  label: string;
  count: number;
}

/** The custom bearer template leads "Popular" as the any-API starting point. */
const CUSTOM_FIRST = "generic-bearer";

/** The templates on one shelf, in the order the catalogue shows them. */
export function shelfItems(list: StoredTemplate[], shelf: Shelf): StoredTemplate[] {
  if (shelf === "pending") return list.filter((t) => t.status !== "approved");
  const approved = list.filter((t) => t.status === "approved");
  if (shelf === "all") return approved;
  if (shelf === "popular") {
    const popular = popularTemplates(approved);
    const custom = approved.find((t) => t.template.id === CUSTOM_FIRST);
    return custom ? [custom, ...popular.filter((t) => t !== custom)] : popular;
  }
  return approved.filter((t) => t.template.category === shelf);
}

/**
 * The rail's entries with their counts. Empty categories are left out;
 * "pending" shows only while something waits for approval, and "popular"
 * only when the list has popular picks (a search for one service may not).
 */
export function catalogShelves(list: StoredTemplate[]): ShelfEntry[] {
  const entry = (key: Shelf, label: string): ShelfEntry => ({ key, label, count: shelfItems(list, key).length });
  const head = [entry("pending", "Waiting for approval"), entry("popular", "Popular")].filter((e) => e.count > 0);
  const categories = CATEGORIES.map((c) => entry(c.value, c.label)).filter((e) => e.count > 0);
  return [...head, entry("all", "All services"), ...categories];
}

/**
 * The shelf to show: the one chosen, unless a search emptied it, then the
 * first shelf holding a match (an import awaiting approval included), so a
 * search never says "no match" while a match sits on another shelf.
 */
export function activeShelf(shelves: ShelfEntry[], chosen: Shelf, searching: boolean): ShelfEntry | undefined {
  const all = shelves.find((s) => s.key === "all");
  const picked = shelves.find((s) => s.key === chosen);
  if (picked && (picked.count > 0 || !searching)) return picked;
  if (searching) return shelves.find((s) => s.count > 0) ?? all;
  return all;
}
