// SPDX-FileCopyrightText: 2026 credential-broker contributors
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
    case "header":
      return `${t.injection.name}: ${t.injection.prefix ?? ""}<${t.injection.field}>`;
  }
}

/** Where a credential's requests go, for lists: its override or its template's hosts. */
export function targetHosts(t: ServiceTemplate | undefined, hostOverride: string[]): string[] {
  if (hostOverride.length) return hostOverride;
  return t?.hosts ?? [];
}
