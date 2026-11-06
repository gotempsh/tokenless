// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Short, readable times for tables: "5 minutes ago" for the last day,
// "Nov 6" after that and "Nov 6, 2025" in another year. The exact time
// goes in the tooltip.

const UNITS: [Intl.RelativeTimeFormatUnit, number][] = [
  ["year", 365 * 24 * 3600],
  ["month", 30 * 24 * 3600],
  ["week", 7 * 24 * 3600],
  ["day", 24 * 3600],
  ["hour", 3600],
  ["minute", 60],
  ["second", 1],
];

const DAY_SECS = 24 * 3600;

/** "3 hours ago" / "in 5 days". */
export function relativeTime(at: Date, now: Date, locale?: string): string {
  const secs = (at.getTime() - now.getTime()) / 1000;
  if (Math.abs(secs) < 45) return secs > 0 ? "in a moment" : "just now";
  const [unit, size] = UNITS.find(([, n]) => Math.abs(secs) >= n) ?? ["second", 1];
  return new Intl.RelativeTimeFormat(locale, { numeric: "auto" }).format(Math.round(secs / size), unit);
}

/** Relative within a day either way, otherwise the date alone. */
export function compactTime(at: Date, now: Date, locale?: string): string {
  if (Math.abs(at.getTime() - now.getTime()) < DAY_SECS * 1000) return relativeTime(at, now, locale);
  const sameYear = at.getFullYear() === now.getFullYear();
  return at.toLocaleDateString(locale, { month: "short", day: "numeric", ...(sameYear ? {} : { year: "numeric" }) });
}

/** The full local date and time, for tooltips and detail views. */
export function exactTime(at: Date, locale?: string): string {
  return at.toLocaleString(locale, { dateStyle: "medium", timeStyle: "short" });
}
