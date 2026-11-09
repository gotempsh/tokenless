// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// What a record panel shows of the services it holds: a few logos and a
// count of the rest, so every panel in a grid is the same height.

/** Logos a panel shows before the rest become "+N". */
export const STRIP_MAX = 4;

export interface Strip<T> {
  shown: T[];
  /** Services beyond those shown, counted from the record's total. */
  more: number;
}

/** The first `max` of `items`, and how many of `total` that leaves out. */
export function serviceStrip<T>(items: T[], total: number, max = STRIP_MAX): Strip<T> {
  const shown = items.slice(0, max);
  return { shown, more: Math.max(0, total - shown.length) };
}
