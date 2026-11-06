// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// The service catalogue as cards: a popular section and one section per
// category, filtered by type, category and search. Used on the Templates
// page and as the first step of the Add a service page.

import { useMemo, useState, type ReactNode } from "react";
import { Search } from "lucide-react";
import type { ServiceKind, StoredTemplate, TemplateCategory } from "../api";
import { CATEGORIES, CATEGORY_LABEL, KIND_LABEL, latestTemplates, matchesSearch, popularTemplates } from "../catalog";
import { cn } from "../lib/utils";
import { SelectField } from "./common";
import { ServiceLogo } from "./ServiceLogo";
import { Badge } from "./ui/badge";
import { Input } from "./ui/input";
import { Skeleton } from "./ui/skeleton";

type KindFilter = "all" | ServiceKind;
type CategoryFilter = "all" | TemplateCategory;

const KIND_FILTERS: { value: KindFilter; label: string }[] = [
  { value: "all", label: "All" },
  { value: "http", label: "HTTP APIs" },
  { value: "mcp", label: "MCP servers" },
];

/** The custom bearer template leads "Popular" as the any-API starting point. */
const CUSTOM_FIRST = "generic-bearer";

interface CatalogSection {
  key: string;
  title: string;
  items: StoredTemplate[];
}

export function TemplateCatalog({
  templates,
  loading,
  includePending = false,
  onOpen,
  openLabel,
  cardAction,
  autoFocus = false,
}: {
  templates: StoredTemplate[];
  loading: boolean;
  /** Show imported templates awaiting approval in their own section. */
  includePending?: boolean;
  onOpen: (t: StoredTemplate) => void;
  /** What clicking a card does, for screen readers, e.g. "Add GitHub". */
  openLabel?: (t: StoredTemplate) => string;
  /** A call to action in each card's footer; without it the whole card is the button. */
  cardAction?: (t: StoredTemplate) => ReactNode;
  autoFocus?: boolean;
}) {
  const [kind, setKind] = useState<KindFilter>("all");
  const [category, setCategory] = useState<CategoryFilter>("all");
  const [query, setQuery] = useState("");

  const latest = useMemo(
    () => latestTemplates(templates).filter((t) => includePending || t.status === "approved"),
    [templates, includePending],
  );
  const visible = useMemo(
    () =>
      latest.filter(
        (t) =>
          (kind === "all" || t.template.kind === kind) &&
          (category === "all" || t.template.category === category) &&
          matchesSearch(t.template, query),
      ),
    [latest, kind, category, query],
  );

  const sections = useMemo(() => {
    const out: CatalogSection[] = [];
    const pending = visible.filter((t) => t.status !== "approved");
    if (pending.length) out.push({ key: "pending", title: "Waiting for approval", items: pending });
    const approved = visible.filter((t) => t.status === "approved");
    if (!query.trim() && category === "all") {
      const custom = approved.find((t) => t.template.id === CUSTOM_FIRST);
      const popular = popularTemplates(approved);
      const items = custom ? [custom, ...popular.filter((t) => t !== custom)] : popular;
      if (items.length) out.push({ key: "popular", title: "Popular", items });
    }
    for (const c of CATEGORIES) {
      const items = approved.filter((t) => t.template.category === c.value);
      if (items.length) out.push({ key: c.value, title: c.label, items });
    }
    return out;
  }, [visible, query, category]);

  const counts = useMemo(
    () =>
      ({
        all: latest.length,
        http: latest.filter((t) => t.template.kind === "http").length,
        mcp: latest.filter((t) => t.template.kind === "mcp").length,
      }) satisfies Record<KindFilter, number>,
    [latest],
  );

  return (
    // A query container: the catalogue is a list until it is wide enough
    // for cards that are not cramped, sidebar or not.
    <div className="@container space-y-6">
      <div className="flex flex-col gap-2 sm:flex-row sm:flex-wrap sm:items-center">
        <div className="relative w-full sm:w-80">
          <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            autoFocus={autoFocus}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search services, hosts or aliases…"
            className="pl-9"
            aria-label="Search the catalogue"
          />
        </div>
        <div role="radiogroup" aria-label="Service type" className="flex rounded-md border p-0.5">
          {KIND_FILTERS.map((f) => (
            <button
              key={f.value}
              type="button"
              role="radio"
              aria-checked={kind === f.value}
              onClick={() => setKind(f.value)}
              className={cn(
                "flex h-8 items-center gap-1.5 rounded-sm px-3 text-sm text-muted-foreground transition-colors hover:text-foreground",
                kind === f.value && "bg-accent font-medium text-foreground",
              )}
            >
              {f.label}
              <span className="text-xs tabular-nums text-muted-foreground">{counts[f.value]}</span>
            </button>
          ))}
        </div>
        <div className="w-full sm:w-[200px]">
          <SelectField
            value={category}
            onChange={(v) => setCategory(v as CategoryFilter)}
            options={[{ value: "all", label: "All categories" }, ...CATEGORIES]}
          />
        </div>
      </div>
      {loading ? (
        <>
          <div className="divide-y rounded-lg border @4xl:hidden">
            {Array.from({ length: 6 }, (_, i) => (
              <div key={i} className="flex items-center gap-3 px-4 py-3">
                <Skeleton className="size-8 shrink-0 rounded-md" />
                <div className="flex-1 space-y-1.5">
                  <Skeleton className="h-4 w-40" />
                  <Skeleton className="h-3 w-64 max-w-full" />
                </div>
              </div>
            ))}
          </div>
          <div className={cn(GRID, "hidden")}>
            {Array.from({ length: 8 }, (_, i) => (
              <Skeleton key={i} className="h-36 w-full rounded-lg" />
            ))}
          </div>
        </>
      ) : sections.length === 0 ? (
        <p className="rounded-lg border border-dashed py-12 text-center text-sm text-muted-foreground">
          {latest.length ? (
            <>
              No service matches{query.trim() ? ` “${query.trim()}”` : " these filters"}. Use{" "}
              <span className="font-medium text-foreground">Custom HTTP API</span> for any service that takes a bearer
              token, or import a template.
            </>
          ) : (
            "The catalogue is empty. Import a template YAML to describe a service."
          )}
        </p>
      ) : (
        sections.map((section) => (
          <section key={section.key} className="space-y-3">
            <h3 className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
              {section.title} <span className="tabular-nums">· {section.items.length}</span>
            </h3>
            {/* One list or one grid shows, by the catalogue's width. */}
            <ul role="list" className="divide-y rounded-lg border @4xl:hidden">
              {section.items.map((t) => (
                <TemplateRow
                  key={`${section.key}-${t.template.id}`}
                  t={t}
                  onOpen={() => onOpen(t)}
                  openLabel={openLabel?.(t)}
                  action={cardAction?.(t)}
                />
              ))}
            </ul>
            <div className={cn(GRID, "hidden")}>
              {section.items.map((t) => (
                <TemplateCard
                  key={`${section.key}-${t.template.id}`}
                  t={t}
                  onOpen={() => onOpen(t)}
                  openLabel={openLabel?.(t)}
                  action={cardAction?.(t)}
                />
              ))}
            </div>
          </section>
        ))
      )}
    </div>
  );
}

/** Cards only where three fit without cramping: 56rem of catalogue and up. */
const GRID = "@4xl:grid @4xl:grid-cols-3 @4xl:gap-3 @7xl:grid-cols-4";

function categoryLabel(t: StoredTemplate): string {
  return t.template.kind === "mcp" ? KIND_LABEL.mcp : CATEGORY_LABEL[t.template.category];
}

/** A catalogue entry as a list row: logo, name, one line of description. */
function TemplateRow({
  t,
  onOpen,
  openLabel,
  action,
}: {
  t: StoredTemplate;
  onOpen: () => void;
  openLabel?: string;
  action?: ReactNode;
}) {
  const tpl = t.template;
  return (
    <li className="flex items-center gap-2 pr-3 transition-colors hover:bg-accent/40">
      <button
        type="button"
        onClick={onOpen}
        aria-label={openLabel}
        title={openLabel}
        className="flex min-w-0 flex-1 items-center gap-3 py-3 pl-4 text-left focus-visible:outline-2 focus-visible:outline-ring"
      >
        <ServiceLogo template={tpl} size="sm" />
        <span className="min-w-0 flex-1">
          <span className="flex items-center gap-2">
            <span className="truncate text-sm font-medium">{tpl.name}</span>
            {t.status !== "approved" && (
              <Badge variant="outline" className="shrink-0 border-warning/50 font-normal text-warning-strong">
                Pending approval
              </Badge>
            )}
          </span>
          <span className="block truncate text-xs text-muted-foreground">{tpl.description}</span>
        </span>
        <span className="hidden shrink-0 text-xs text-muted-foreground @xl:block">{categoryLabel(t)}</span>
        <span
          className="hidden max-w-48 shrink-0 truncate font-mono text-xs text-muted-foreground @2xl:block"
          title={tpl.hosts.join(", ")}
        >
          {hostSummary(t)}
        </span>
      </button>
      {action}
    </li>
  );
}

function hostSummary(t: StoredTemplate): string {
  const hosts = t.template.hosts;
  if (hosts.length === 0) return "Host set when added";
  return hosts.length === 1 ? (hosts[0] ?? "") : `${hosts[0] ?? ""} +${hosts.length - 1}`;
}

function CardBody({ t }: { t: StoredTemplate }) {
  const tpl = t.template;
  return (
    <>
      <div className="flex items-start justify-between gap-2">
        <ServiceLogo template={tpl} />
        {t.status === "approved" ? (
          <Badge variant="secondary" className="font-normal">
            {categoryLabel(t)}
          </Badge>
        ) : (
          <Badge variant="outline" className="border-warning/50 font-normal text-warning-strong">
            Pending approval
          </Badge>
        )}
      </div>
      <div className="min-w-0 space-y-1">
        <div className="truncate text-sm font-medium">{tpl.name}</div>
        <p className="line-clamp-2 text-xs text-muted-foreground">{tpl.description}</p>
      </div>
    </>
  );
}

export function TemplateCard({
  t,
  onOpen,
  openLabel,
  action,
}: {
  t: StoredTemplate;
  onOpen: () => void;
  openLabel?: string;
  action?: ReactNode;
}) {
  if (!action) {
    return (
      <button
        type="button"
        onClick={onOpen}
        className="flex h-full flex-col gap-3 rounded-lg border bg-card p-4 text-left transition-colors hover:border-foreground/30 hover:bg-accent/40 focus-visible:outline-2 focus-visible:outline-ring"
      >
        <CardBody t={t} />
      </button>
    );
  }
  return (
    <div className="group flex h-full flex-col rounded-lg border bg-card transition-colors hover:border-foreground/30">
      <button
        type="button"
        onClick={onOpen}
        aria-label={openLabel ?? t.template.name}
        title={openLabel}
        className="flex flex-1 flex-col gap-3 rounded-t-lg p-4 text-left focus-visible:outline-2 focus-visible:outline-ring"
      >
        <CardBody t={t} />
      </button>
      <div className="flex items-center justify-between gap-2 border-t px-4 py-2.5">
        <span className="min-w-0 truncate font-mono text-xs text-muted-foreground" title={t.template.hosts.join(", ")}>
          {hostSummary(t)}
        </span>
        {action}
      </div>
    </div>
  );
}
