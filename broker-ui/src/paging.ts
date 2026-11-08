// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Paged lists: when to show the pager, and where to go when a page empties.

import type { Page } from "./api";

/** A list needs its pager when there is a second page, or it is already past the first. */
export function hasPager(page: Page<unknown>): boolean {
  return page.page > 1 || page.total > page.page_size;
}

/**
 * The page to show instead of an empty one past the first, as when its last
 * item was just deleted: the last page that still has items. `null` when
 * this page is fine as it is.
 */
export function fallbackPage(page: Page<unknown>): number | null {
  if (page.items.length > 0 || page.page <= 1) return null;
  return Math.max(1, Math.ceil(page.total / page.page_size));
}
