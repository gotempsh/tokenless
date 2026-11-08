// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// The New session form: which lifetimes it offers, and the commands that
// hand the new token to an agent.

import { shellQuote } from "./bundleConnect";

export interface Lifetime {
  secs: number;
  label: string;
}

const HOUR = 3600;
const DAY = 24 * HOUR;

export const LIFETIMES: Lifetime[] = [
  { secs: HOUR, label: "1 hour" },
  { secs: 8 * HOUR, label: "8 hours" },
  { secs: DAY, label: "1 day" },
  { secs: 7 * DAY, label: "7 days" },
  { secs: 30 * DAY, label: "30 days" },
  { secs: 90 * DAY, label: "90 days" },
];

/** "7 days", "8 hours", "45 minutes": a lifetime in its largest whole unit. */
export function lifetimeLabel(secs: number): string {
  const [n, unit] =
    secs % DAY === 0 ? [secs / DAY, "day"] : secs % HOUR === 0 ? [secs / HOUR, "hour"] : [Math.round(secs / 60), "minute"];
  return `${n} ${unit}${n === 1 ? "" : "s"}`;
}

/**
 * The lifetimes Settings allow, longest last. When the cap is not one of
 * the presets it is offered too, so the longest allowed is always a choice.
 */
export function lifetimesUpTo(maxSecs: number): Lifetime[] {
  const allowed = LIFETIMES.filter((l) => l.secs <= maxSecs);
  if (!allowed.some((l) => l.secs === maxSecs)) allowed.push({ secs: maxSecs, label: lifetimeLabel(maxSecs) });
  return allowed;
}

/** One day when allowed: long enough for a day's work, short enough to forget safely. */
export function defaultLifetime(maxSecs: number): number {
  return Math.min(DAY, maxSecs);
}

/** The lines that give an agent's shell the token and start the agent. */
export function tokenCommands(token: string, agentCommand: string): { exportLine: string; run: string } {
  return {
    exportLine: `export TOKENLESS_SESSION_TOKEN=${shellQuote(token)}`,
    run: `tokenless run -- ${agentCommand}`,
  };
}
