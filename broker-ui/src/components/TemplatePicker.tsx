// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// "Choose a template": the catalogue as cards, grouped into a popular
// section and one section per category, filtered by type and search.

import { useMemo, useState } from "react";
import { Search } from "lucide-react";
import type { ServiceKind, StoredTemplate } from "../api";
import { CATEGORIES, CATEGORY_LABEL, KIND_LABEL, latestTemplates, matchesSearch, popularTemplates } from "../catalog";
import { cn } from "../lib/utils";
import { ServiceLogo } from "./ServiceLogo";
import { Badge } from "./ui/badge";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "./ui/dialog";
import { Input } from "./ui/input";
import { Skeleton } from "./ui/skeleton";

type KindFilter = "all" | ServiceKind;

const KIND_FILTERS: { value: KindFilter; label: string }[] = [
  { value: "all", label: "All types" },
  { value: "http", label: "HTTP APIs" },
  { value: "mcp", label: "MCP servers" },
];

/** The custom bearer template leads "Popular" as the any-API starting point. */
const CUSTOM_FIRST = "generic-bearer";

export function TemplatePicker({
  open,
  onOpenChange,
  templates,
  loading,
  onPick,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  templates: StoredTemplate[];
  loading: boolean;
  onPick: (t: StoredTemplate) => void;
}) {
  const [kind, setKind] = useState<KindFilter>("all");
  const [query, setQuery] = useState("");

  const visible = useMemo(
    () =>
      latestTemplates(templates).filter(
        (t) =>
          t.status === "approved" && (kind === "all" || t.template.kind === kind) && matchesSearch(t.template, query),
      ),
    [templates, kind, query],
  );

  const sections = useMemo(() => {
    const out: { key: string; title: string; items: StoredTemplate[] }[] = [];
    if (!query.trim()) {
      const custom = visible.find((t) => t.template.id === CUSTOM_FIRST);
      const popular = popularTemplates(visible);
      const items = custom ? [custom, ...popular.filter((t) => t !== custom)] : popular;
      if (items.length) out.push({ key: "popular", title: "Popular", items });
    }
    for (const c of CATEGORIES) {
      const items = visible.filter((t) => t.template.category === c.value);
      if (items.length) out.push({ key: c.value, title: c.label, items });
    }
    return out;
  }, [visible, query]);

  const counts = useMemo(() => {
    const approved = latestTemplates(templates).filter((t) => t.status === "approved");
    return {
      all: approved.length,
      http: approved.filter((t) => t.template.kind === "http").length,
      mcp: approved.filter((t) => t.template.kind === "mcp").length,
    } satisfies Record<KindFilter, number>;
  }, [templates]);

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        onOpenChange(o);
        if (!o) setQuery("");
      }}
    >
      <DialogContent className="flex h-[85vh] max-h-[85vh] flex-col gap-0 p-0 sm:max-w-5xl">
        <DialogHeader className="border-b p-6 pb-4">
          <DialogTitle>Choose a template</DialogTitle>
          <DialogDescription>
            A template knows the service's hosts and how its credential is sent. You add the secret, or reference a
            variable, on the next step.
          </DialogDescription>
        </DialogHeader>
        <div className="flex min-h-0 flex-1 flex-col md:flex-row">
          <nav
            aria-label="Template type"
            className="flex shrink-0 gap-1 border-b p-3 md:w-48 md:flex-col md:border-b-0 md:border-r"
          >
            {KIND_FILTERS.map((f) => (
              <button
                key={f.value}
                type="button"
                aria-pressed={kind === f.value}
                onClick={() => setKind(f.value)}
                className={cn(
                  "flex h-8 items-center justify-between gap-2 rounded-md px-2 text-sm text-muted-foreground transition-colors hover:bg-accent hover:text-foreground",
                  kind === f.value && "bg-accent font-medium text-foreground",
                )}
              >
                {f.label}
                <span className="text-xs tabular-nums text-muted-foreground">{counts[f.value]}</span>
              </button>
            ))}
          </nav>
          <div className="flex min-h-0 flex-1 flex-col">
            <div className="border-b p-3">
              <div className="relative">
                <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  autoFocus
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Search services, hosts or aliases…"
                  className="pl-9"
                  aria-label="Search templates"
                />
              </div>
            </div>
            <div className="min-h-0 flex-1 space-y-6 overflow-y-auto p-4">
              {loading ? (
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
                  {Array.from({ length: 6 }, (_, i) => (
                    <Skeleton key={i} className="h-28 w-full rounded-lg" />
                  ))}
                </div>
              ) : sections.length === 0 ? (
                <p className="py-12 text-center text-sm text-muted-foreground">
                  No template matches “{query}”. Use <span className="font-medium text-foreground">Custom HTTP API</span>{" "}
                  for any service that takes a bearer token, or import a template.
                </p>
              ) : (
                sections.map((section) => (
                  <section key={section.key} className="space-y-3">
                    <h3 className="text-xs font-medium uppercase tracking-wide text-muted-foreground">{section.title}</h3>
                    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
                      {section.items.map((t) => (
                        <TemplateCard key={`${section.key}-${t.template.id}`} t={t} onPick={() => onPick(t)} />
                      ))}
                    </div>
                  </section>
                ))
              )}
            </div>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

function TemplateCard({ t, onPick }: { t: StoredTemplate; onPick: () => void }) {
  const tpl = t.template;
  return (
    <button
      type="button"
      onClick={onPick}
      className="flex h-full flex-col gap-3 rounded-lg border bg-card p-4 text-left transition-colors hover:border-foreground/30 hover:bg-accent/40 focus-visible:outline-2 focus-visible:outline-ring"
    >
      <div className="flex items-start justify-between gap-2">
        <ServiceLogo template={tpl} />
        <Badge variant="secondary" className="font-normal">
          {tpl.kind === "mcp" ? KIND_LABEL.mcp : CATEGORY_LABEL[tpl.category]}
        </Badge>
      </div>
      <div className="min-w-0 space-y-1">
        <div className="truncate text-sm font-medium">{tpl.name}</div>
        <p className="line-clamp-2 text-xs text-muted-foreground">{tpl.description}</p>
      </div>
    </button>
  );
}
