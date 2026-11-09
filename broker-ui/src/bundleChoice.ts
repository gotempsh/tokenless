// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Choosing an access bundle for a new session: every bundle is a radio
// choice, up to a limit; past it, a filter narrows them down.

import type { AccessBundle } from "./api";

/** How many bundles are listed at once before the rest wait for a filter. */
export const BUNDLES_SHOWN = 6;

export interface BundleChoices {
  /** The bundles to list, in the vault's order. */
  shown: AccessBundle[];
  /** Bundles that match but are not listed. */
  hidden: number;
  /** Whether a filter is worth offering. */
  filterable: boolean;
}

/**
 * The bundles to list for `query`. The chosen one stays listed even when
 * the filter leaves it out, so the choice is never invisible.
 */
export function bundleChoices(
  bundles: AccessBundle[],
  query: string,
  chosenId: string,
  limit = BUNDLES_SHOWN,
): BundleChoices {
  const q = query.trim().toLowerCase();
  const matches = q
    ? bundles.filter((b) => b.name.toLowerCase().includes(q) || b.description.toLowerCase().includes(q))
    : bundles;
  let shown = matches.slice(0, limit);
  const chosen = bundles.find((b) => b.id === chosenId);
  if (chosen && !shown.includes(chosen)) shown = [chosen, ...shown.slice(0, limit - 1)];
  const hidden = matches.filter((b) => !shown.includes(b)).length;
  return { shown, hidden, filterable: bundles.length > limit };
}

/**
 * The chosen bundle among `bundles`: `id` when it is one of them, else the
 * only bundle when there is just one, else none.
 */
export function chosenIn(bundles: AccessBundle[], id: string): string {
  if (bundles.some((b) => b.id === id)) return id;
  return bundles.length === 1 && bundles[0] ? bundles[0].id : "";
}

export function ruleCount(b: AccessBundle): string {
  return b.rule_ids.length === 1 ? "1 rule" : `${b.rule_ids.length} rules`;
}
