// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import type { RateLimit } from "./api";

/** The server's default: 20 a second, bursts of 100. */
export const DEFAULT_RATE_LIMIT: RateLimit = { per_sec: 20, burst: 100 };

const PRESETS: RateLimit[] = [
  { per_sec: 5, burst: 25 },
  DEFAULT_RATE_LIMIT,
  { per_sec: 50, burst: 250 },
  { per_sec: 200, burst: 1000 },
];

export function rateKey(r: RateLimit): string {
  return `${r.per_sec}/${r.burst}`;
}

export function parseRateKey(key: string): RateLimit {
  const [per_sec = 0, burst = 0] = key.split("/").map(Number);
  return { per_sec, burst };
}

export function rateLabel(r: RateLimit): string {
  const label = `${r.per_sec} a second, bursts of ${r.burst}`;
  return rateKey(r) === rateKey(DEFAULT_RATE_LIMIT) ? `${label} (default)` : label;
}

/** The presets, with `current` added when it is not one of them. */
export function rateOptions(current: RateLimit | null) {
  const all = current && !PRESETS.some((p) => rateKey(p) === rateKey(current)) ? [...PRESETS, current] : PRESETS;
  return all.map((r) => ({ value: rateKey(r), label: rateLabel(r) }));
}

/** A bundle's request limit, as its settings show it. */
export function requestLimitLabel(limit: number | null | undefined): string {
  if (limit == null) return "No limit";
  return `${limit.toLocaleString("en-US")} request${limit === 1 ? "" : "s"} per session`;
}

/** The typed limit: a whole number from 1, or why not. */
export function parseRequestLimit(text: string): { limit: number } | { error: string } {
  const n = Number(text.trim());
  if (!/^\d+$/.test(text.trim()) || !Number.isSafeInteger(n) || n < 1) {
    return { error: "A whole number of requests, 1 or more" };
  }
  if (n > 1_000_000_000) return { error: "At most 1,000,000,000; remove the limit for none" };
  return { limit: n };
}
