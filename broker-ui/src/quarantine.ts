// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import type { QuarantinePolicy } from "./api";

/** The server's default: 20 refusals in 5 minutes. */
export const DEFAULT_QUARANTINE: QuarantinePolicy = { refusals: 20, window_secs: 300 };

const PRESETS: QuarantinePolicy[] = [
  { refusals: 10, window_secs: 300 },
  DEFAULT_QUARANTINE,
  { refusals: 50, window_secs: 300 },
  { refusals: 100, window_secs: 600 },
];

export function quarantineKey(q: QuarantinePolicy): string {
  return `${q.refusals}/${q.window_secs}`;
}

export function parseQuarantineKey(key: string): QuarantinePolicy {
  const [refusals = 0, window = 0] = key.split("/").map(Number);
  return { refusals, window_secs: window };
}

function minutes(secs: number): string {
  if (secs % 60 !== 0) return `${secs} seconds`;
  const m = secs / 60;
  return `${m} minute${m === 1 ? "" : "s"}`;
}

export function quarantineLabel(q: QuarantinePolicy): string {
  const label = `${q.refusals} refusals in ${minutes(q.window_secs)}`;
  return quarantineKey(q) === quarantineKey(DEFAULT_QUARANTINE) ? `${label} (default)` : label;
}

/** The presets, with `current` added when it is not one of them. */
export function quarantineOptions(current: QuarantinePolicy | null) {
  const all = current && !PRESETS.some((p) => quarantineKey(p) === quarantineKey(current)) ? [...PRESETS, current] : PRESETS;
  return all.map((q) => ({ value: quarantineKey(q), label: quarantineLabel(q) }));
}
