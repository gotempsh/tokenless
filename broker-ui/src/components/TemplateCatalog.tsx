// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// The service catalogue: a rail of shelves (popular, all, one per category)
// beside the services on the chosen shelf, filtered by type and search.
// Used on the Templates page and as the first step of Add a service.

import { useMemo, useState, type ReactNode } from "react";
import { Search } from "lucide-react";
import type { ServiceKind, StoredTemplate } from "../api";
import { catalogShelves, latestTemplates, matchesSearch, shelfItems, type Shelf } from "../catalog";
import { cn } from "../lib/utils";
import { SelectField } from "./common";
import { ServiceLogo } from "./ServiceLogo";
import { Badge } from "./ui/badge";
import { Input } from "./ui/input";
import { Skeleton } from "./ui/skeleton";

type KindFilter = "all" | ServiceKind;

const KIND_FILTERS: { value: KindFilter; label: string }[] = [
  { value: "all", label: "All" },
  { value: "http", label: "HTTP APIs" },
  { value: "mcp", label: "MCP servers" },
];

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
  /** Show imported templates awaiting approval on their own shelf. */
  includePending?: boolean;
  onOpen: (t: StoredTemplate) => void;
  /** What clicking an entry does, for screen readers, e.g. "Add GitHub". */
  openLabel?: (t: StoredTemplate) => string;
  /** A secondary action at the end of each entry, beside the main one. */
  cardAction?: (t: StoredTemplate) => ReactNode;
  autoFocus?: boolean;
}) {
  const [kind, setKind] = useState<KindFilter>("all");
  const [shelf, setShelf] = useState<Shelf>("popular");
  const [query, setQuery] = useState("");

  const latest = useMemo(
    () => latestTemplates(templates).filter((t) => includePending || t.status === "approved"),
    [templates, includePending],
  );
  const matching = useMemo(
    () => latest.filter((t) => (kind === "all" || t.template.kind === kind) && matchesSearch(t.template, query)),
    [latest, kind, query],
  );
  const shelves = useMemo(() => catalogShelves(matching), [matching]);
  // A shelf the filters emptied falls back to everything that matches.
  const active = shelves.find((s) => s.key === shelf) ?? shelves.find((s) => s.key === "all");
  const items = useMemo(() => (active ? shelfItems(matching, active.key) : []), [matching, active]);

  const counts = useMemo(
    () =>
      ({
        all: latest.length,
        http: latest.filter((t) => t.template.kind === "http").length,
        mcp: latest.filter((t) => t.template.kind === "mcp").length,
      }) satisfies Record<KindFilter, number>,
    [latest],
  );

  const search = (value: string) => {
    // A search looks across the whole catalogue; the rail then narrows it.
    if (!query.trim() && value.trim()) setShelf("all");
    setQuery(value);
  };

  return (
    // A query container: the rail and the tile grid appear once the
    // catalogue itself is wide enough, sidebar or not.
    <div className="@container">
      <div className="grid gap-x-8 gap-y-4 @3xl:grid-cols-[200px_minmax(0,1fr)]">
        <div className="space-y-3 @3xl:sticky @3xl:top-4 @3xl:self-start">
          <div className="relative">
            <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              autoFocus={autoFocus}
              value={query}
              onChange={(e) => search(e.target.value)}
              placeholder={latest.length ? `Search ${latest.length} services…` : "Search services…"}
              className="pl-9"
              aria-label="Search the catalogue"
            />
          </div>
          <nav aria-label="Categories" className="hidden @3xl:block">
            <ul className="space-y-0.5">
              {shelves.map((s) => (
                <li key={s.key}>
                  <button
                    type="button"
                    aria-current={active?.key === s.key ? "true" : undefined}
                    onClick={() => setShelf(s.key)}
                    className={cn(
                      "flex w-full items-center justify-between gap-2 rounded-md px-2.5 py-1.5 text-left text-sm text-muted-foreground transition-colors hover:bg-accent/50 hover:text-foreground focus-visible:outline-2 focus-visible:outline-ring",
                      active?.key === s.key && "bg-accent font-medium text-foreground",
                      s.key === "pending" && "text-warning-strong",
                    )}
                  >
                    <span className="truncate">{s.label}</span>
                    <span className="text-xs tabular-nums text-muted-foreground">{s.count}</span>
                  </button>
                </li>
              ))}
            </ul>
          </nav>
        </div>

        <div className="min-w-0 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="min-w-48 flex-1 @3xl:hidden">
              <SelectField
                value={active?.key ?? "all"}
                onChange={(v) => setShelf(v as Shelf)}
                options={shelves.map((s) => ({ value: s.key, label: `${s.label} · ${s.count}` }))}
              />
            </div>
            <h2 className="hidden text-sm font-medium @3xl:block">
              {active?.label ?? "All services"}{" "}
              <span className="font-normal tabular-nums text-muted-foreground">{items.length}</span>
            </h2>
            <div role="radiogroup" aria-label="Service type" className="flex rounded-md border p-0.5">
              {KIND_FILTERS.map((f) => (
                <button
                  key={f.value}
                  type="button"
                  role="radio"
                  aria-checked={kind === f.value}
                  onClick={() => setKind(f.value)}
                  className={cn(
                    "flex h-7 items-center gap-1.5 rounded-sm px-2.5 text-sm text-muted-foreground transition-colors hover:text-foreground",
                    kind === f.value && "bg-accent font-medium text-foreground",
                  )}
                >
                  {f.label}
                  <span className="text-xs tabular-nums text-muted-foreground">{counts[f.value]}</span>
                </button>
              ))}
            </div>
          </div>

          {loading ? (
            <ul className={TILES}>
              {Array.from({ length: 9 }, (_, i) => (
                <li key={i} className="flex items-center gap-3 p-3">
                  <Skeleton className="size-8 shrink-0 rounded-md" />
                  <div className="flex-1 space-y-1.5">
                    <Skeleton className="h-4 w-28" />
                    <Skeleton className="h-3 w-40 max-w-full" />
                  </div>
                </li>
              ))}
            </ul>
          ) : items.length === 0 ? (
            <p className="rounded-lg border border-dashed px-4 py-12 text-center text-sm text-muted-foreground">
              {latest.length ? (
                <>
                  No service matches{query.trim() ? ` “${query.trim()}”` : " this filter"}. Use{" "}
                  <span className="font-medium text-foreground">Custom HTTP API</span> for any service that takes a
                  bearer token, or import a template.
                </>
              ) : (
                "The catalogue is empty. Import a template YAML to describe a service."
              )}
            </p>
          ) : (
            <ul role="list" className={TILES}>
              {items.map((t) => (
                <TemplateTile
                  key={`${t.template.id}@${t.template.version}`}
                  t={t}
                  onOpen={() => onOpen(t)}
                  openLabel={openLabel?.(t)}
                  action={cardAction?.(t)}
                />
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}

/**
 * One list of entries that changes shape with the catalogue's width: a
 * bordered list while three tiles would not fit, then a grid of tiles,
 * four across from 80rem of catalogue (about 260px a tile).
 */
const TILES = cn(
  "divide-y rounded-lg border",
  "@3xl:grid @3xl:grid-cols-3 @3xl:gap-3 @3xl:divide-y-0 @3xl:rounded-none @3xl:border-0",
  "@3xl:[&>li]:rounded-lg @3xl:[&>li]:border @3xl:[&>li]:bg-card @7xl:grid-cols-4",
);

function hostSummary(t: StoredTemplate): string {
  const hosts = t.template.hosts;
  return hosts.length === 0 ? "Host set when added" : hosts.join(", ");
}

/** A catalogue entry: logo, name and one line of description; the whole entry opens it. */
function TemplateTile({
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
    <li className="flex min-w-0 items-center gap-1 pr-2 transition-colors hover:bg-accent/40 @3xl:hover:border-foreground/30">
      <button
        type="button"
        onClick={onOpen}
        aria-label={openLabel}
        title={`${openLabel ?? tpl.name} · ${hostSummary(t)}`}
        className="flex min-w-0 flex-1 items-center gap-3 rounded-lg py-3 pl-3 text-left focus-visible:outline-2 focus-visible:outline-ring"
      >
        <ServiceLogo template={tpl} size="sm" />
        <span className="min-w-0 flex-1">
          <span className="flex items-center gap-2">
            <span className="truncate text-sm font-medium">{tpl.name}</span>
            {t.status !== "approved" && (
              <Badge variant="outline" className="shrink-0 border-warning/50 font-normal text-warning-strong">
                Pending
              </Badge>
            )}
          </span>
          <span className="block truncate text-xs text-muted-foreground">{tpl.description}</span>
        </span>
      </button>
      {action}
    </li>
  );
}
