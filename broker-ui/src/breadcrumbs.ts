// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// The header's breadcrumb trail. A page that sits below a section
// publishes its own trail (ancestors with links, then itself); every other
// page gets its section name.

import { createContext, useContext, useEffect } from "react";

export interface Crumb {
  /** Human-readable; `null` while the name is still loading. */
  label: string | null;
  /** Ancestors link back; the current page has none. */
  href?: string;
}

export const BreadcrumbContext = createContext<(crumbs: Crumb[] | null) => void>(() => {});

/** Publishes `crumbs` for the header while the calling page is shown. */
export function useBreadcrumbs(crumbs: Crumb[]): void {
  const set = useContext(BreadcrumbContext);
  const key = JSON.stringify(crumbs);
  useEffect(() => {
    set(JSON.parse(key) as Crumb[]);
  }, [key, set]);
  useEffect(() => () => set(null), [set]);
}

/**
 * The trail to render: the page's own, or just the section's name. The
 * last crumb is the current page and never links, whatever it was given.
 */
export function trail(sectionLabel: string, crumbs: Crumb[] | null): Crumb[] {
  const out = crumbs && crumbs.length > 0 ? crumbs : [{ label: sectionLabel }];
  return out.map((c, i) => (i === out.length - 1 ? { label: c.label } : c));
}

/** Where `back` (a hash path such as `vaults/<id>/bundles`) points, as crumbs. */
export function backCrumbs(
  back: string | undefined,
  names: { vault?: string | null; bundle?: string | null },
): Crumb[] {
  const [section, id] = (back ?? "").split("/");
  if (section === "vaults") {
    const root = { label: "Vaults", href: "#/vaults" };
    return id ? [root, { label: names.vault ?? null, href: `#/${back}` }] : [root];
  }
  if (section === "bundles") {
    const root = { label: "Access bundles", href: "#/bundles" };
    return id ? [root, { label: names.bundle ?? null, href: `#/${back}` }] : [root];
  }
  if (section === "templates") return [{ label: "Templates", href: "#/templates" }];
  return [];
}
