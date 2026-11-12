// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import type { Alert, AlertKind, AlertSummary, AuditDestination, RefusalThreshold } from "./api";

export const KIND_LABEL: Record<AlertKind, string> = {
  quarantine: "Session cut off",
  tripwire: "Tripwire",
  refusals: "Refused often",
  new_proxy: "Second proxy",
};

/** The server's default: 10 refusals in 5 minutes, half the quarantine's. */
export const DEFAULT_REFUSALS: RefusalThreshold = { refusals: 10, window_secs: 300 };

const PRESETS: RefusalThreshold[] = [
  { refusals: 5, window_secs: 300 },
  DEFAULT_REFUSALS,
  { refusals: 20, window_secs: 300 },
  { refusals: 50, window_secs: 600 },
];

export function refusalKey(t: RefusalThreshold): string {
  return `${t.refusals}/${t.window_secs}`;
}

export function parseRefusalKey(key: string): RefusalThreshold {
  const [refusals = 0, window = 0] = key.split("/").map(Number);
  return { refusals, window_secs: window };
}

function minutes(secs: number): string {
  if (secs % 60 !== 0) return `${secs} seconds`;
  const m = secs / 60;
  return `${m} minute${m === 1 ? "" : "s"}`;
}

export function refusalLabel(t: RefusalThreshold): string {
  const label = `${t.refusals} refusals in ${minutes(t.window_secs)}`;
  return refusalKey(t) === refusalKey(DEFAULT_REFUSALS) ? `${label} (default)` : label;
}

/** The presets, with `current` added when it is not one of them. */
export function refusalOptions(current: RefusalThreshold | null) {
  const all = current && !PRESETS.some((p) => refusalKey(p) === refusalKey(current)) ? [...PRESETS, current] : PRESETS;
  return all.map((t) => ({ value: refusalKey(t), label: refusalLabel(t) }));
}

/** When `kind` last fired, or null when it never has. */
export function lastRaised(summary: AlertSummary | undefined, kind: AlertKind): string | null {
  return summary?.last_raised.find((l) => l.kind === kind)?.at ?? null;
}

/**
 * The webhooks that get alerts: those sending every action, or an
 * `alert.` prefix (or a shorter one covering it), and successes. Paused
 * ones send nothing.
 */
export function alertDestinations(destinations: AuditDestination[]): AuditDestination[] {
  return destinations.filter(
    (d) =>
      !d.paused &&
      (d.filter.action_prefixes.length === 0 || d.filter.action_prefixes.some((p) => "alert.raised".startsWith(p))) &&
      (d.filter.outcomes.length === 0 || d.filter.outcomes.includes("success")),
  );
}

/** The banner's title: one alert says what it is, several are counted. */
export function bannerTitle(open: number, latest: Alert | null): string {
  if (open === 1 && latest) return KIND_LABEL[latest.kind];
  return `${open} open alerts`;
}
