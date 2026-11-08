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

/** Installs the `tokenless` CLI on Linux or macOS. */
export const INSTALL_COMMAND = "curl -fsSL https://raw.githubusercontent.com/gotempsh/tokenless/main/site/install.sh | sh";

/** Where the agent's machine reaches the console, the proxy and the session. */
export interface AgentTarget {
  /** The console's address: the browser's origin. */
  url: string;
  /** The proxy's `host:port`. */
  proxy: string;
  token: string;
}

function isLoopback(hostname: string): boolean {
  return hostname === "localhost" || hostname === "::1" || hostname === "[::1]" || hostname.startsWith("127.");
}

/**
 * The proxy address to suggest: the one last used in this browser, else
 * the proxy's default port on the console's host, which is where a
 * single-machine install runs it.
 */
export function suggestedProxy(hostname: string, remembered?: string | null): string {
  if (remembered?.trim()) return remembered.trim();
  return isLoopback(hostname) ? "127.0.0.1:3128" : `${hostname.includes(":") ? `[${hostname}]` : hostname}:3128`;
}

/**
 * The MCP gateway next to a proxy: the same host, one port up, as
 * `node run` sets them by default (3128 and 3129).
 */
export function gatewayFor(proxy: string): string {
  const m = /^(.*):(\d+)$/.exec(proxy.trim());
  if (!m) return `http://${proxy.trim()}:3129`;
  return `http://${m[1]}:${Number(m[2]) + 1}`;
}

/** The token shortened for display; copying still gives the whole of it. */
export function shortToken(token: string): string {
  return token.length > 28 ? `${token.slice(0, 24)}…` : token;
}

function envLines(t: AgentTarget, token: string, prefix: string): string[] {
  return [
    `${prefix}TOKENLESS_URL=${shellQuote(t.url)}`,
    `${prefix}TOKENLESS_PROXY_ADDRESS=${shellQuote(t.proxy)}`,
    `${prefix}TOKENLESS_SESSION_TOKEN=${token === t.token ? shellQuote(token) : token}`,
  ];
}

/**
 * What to paste in the agent's terminal: where the console and proxy are,
 * the session, and the agent started through it. `display` hides most of
 * the token.
 */
export function agentScript(t: AgentTarget, command: string): { copy: string; display: string } {
  const build = (token: string) => [...envLines(t, token, "export "), `tokenless run -- ${command}`].join("\n");
  return { copy: build(t.token), display: build(shortToken(t.token)) };
}

/** The same settings as environment variables for a CI job or a container. */
export function agentEnv(t: AgentTarget): { copy: string; display: string } {
  const build = (token: string) => envLines(t, token, "").join("\n");
  return { copy: `${build(t.token)}\n`, display: build(shortToken(t.token)) };
}
