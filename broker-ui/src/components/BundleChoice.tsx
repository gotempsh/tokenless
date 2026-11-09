// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// The access bundles a new session can start from, as radio choices, each
// with its services' logos so it is known at a glance. Past a handful, a
// filter narrows them; the chosen one always stays listed.

import { useState, type ReactNode } from "react";
import { Search } from "lucide-react";
import type { AccessBundle } from "../api";
import { bundleChoices, onFilterKey, ruleCount, serviceNames } from "../bundleChoice";
import { cn } from "../lib/utils";
import { Input } from "./ui/input";
import { Label } from "./ui/label";
import { RadioGroup, RadioGroupItem } from "./ui/radio-group";
import { ServiceLogos, type StripService } from "./ServiceStrip";
import { Skeleton } from "./ui/skeleton";

export function BundleChoice({
  name,
  bundles,
  total,
  value,
  onChange,
  empty,
  hint,
  vaultNames,
  servicesOf,
}: {
  /** Prefix for element IDs, unique on the page. */
  name: string;
  /** Undefined while loading. */
  bundles: AccessBundle[] | undefined;
  /** How many there are, which may be more than were loaded. */
  total: number;
  value: string;
  onChange: (id: string) => void;
  /** Shown when there are no bundles. */
  empty: ReactNode;
  hint?: ReactNode;
  /** Names each bundle's vault, when the bundles come from several. */
  vaultNames?: Record<string, string>;
  /** Each bundle's services, shown as logos (`useBundleServices`); undefined until known. */
  servicesOf?: (b: AccessBundle) => StripService[] | undefined;
}) {
  const [query, setQuery] = useState("");
  if (!bundles) return <Skeleton className="h-16 w-full" />;
  if (bundles.length === 0) return <p className="text-sm text-muted-foreground">{empty}</p>;
  const { shown, hidden, filterable } = bundleChoices(bundles, query, value);

  return (
    <div className="space-y-2">
      <div>
        <p id={`${name}-label`} className="text-sm font-medium">
          Access bundle
        </p>
        {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
      </div>
      {filterable && (
        <div className="relative">
          <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            aria-label="Find a bundle"
            className="pl-9"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => onFilterKey(e, bundles, query, onChange)}
            placeholder={`Find one of ${total} bundles…`}
          />
        </div>
      )}
      {shown.length === 0 ? (
        <p className="rounded-md border px-3 py-4 text-sm text-muted-foreground">No bundle matches “{query.trim()}”.</p>
      ) : (
        <RadioGroup
          aria-labelledby={`${name}-label`}
          value={value}
          onValueChange={onChange}
          className="grid-cols-1 gap-0 divide-y overflow-hidden rounded-md border"
        >
          {shown.map((b) => {
            const id = `${name}-${b.id}`;
            const about = [vaultNames?.[b.vault_id], b.description].filter(Boolean).join(" · ");
            const reaches = servicesOf?.(b) ?? [];
            return (
              <Label
                key={b.id}
                htmlFor={id}
                className={cn(
                  "flex cursor-pointer items-start gap-3 px-3 py-2.5 font-normal transition-colors hover:bg-accent/50",
                  value === b.id && "bg-accent/40",
                )}
              >
                <RadioGroupItem id={id} value={b.id} className="mt-0.5" />
                <span className="min-w-0 flex-1">
                  <span className="flex items-baseline justify-between gap-3">
                    <span className="truncate text-sm font-medium">{b.name}</span>
                    {reaches.length === 0 && <span className="shrink-0 text-xs text-muted-foreground">{ruleCount(b)}</span>}
                  </span>
                  {about && <span className="block truncate text-xs text-muted-foreground">{about}</span>}
                </span>
                {reaches.length > 0 && (
                  <span className="shrink-0 self-center" title={serviceNames(reaches, b.rule_ids.length)}>
                    <ServiceLogos services={reaches} total={b.rule_ids.length} size="xs" />
                    <span className="sr-only">{serviceNames(reaches, b.rule_ids.length)}</span>
                  </span>
                )}
              </Label>
            );
          })}
        </RadioGroup>
      )}
      {(hidden > 0 || total > bundles.length) && (
        <p className="text-xs text-muted-foreground">
          {hidden > 0 && `${hidden} more ${hidden === 1 ? "matches" : "match"}: type to narrow the list. `}
          {total > bundles.length &&
            `Only the first ${bundles.length} of ${total} are listed here; start a session from the bundle's own page for the others.`}
        </p>
      )}
    </div>
  );
}
