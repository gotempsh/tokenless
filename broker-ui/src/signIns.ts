// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

/** What signing out elsewhere did, in words. */
export function revokedMessage(revoked: number, who?: string): string {
  const ended = `${revoked} sign-in${revoked === 1 ? "" : "s"}`;
  if (who) return revoked === 0 ? `${who} was not signed in anywhere.` : `Signed ${who} out everywhere: ended ${ended}.`;
  return revoked === 0 ? "You were signed in only here." : `Signed out everywhere else: ended ${ended}.`;
}

/** The idle timeouts an admin picks from; `"off"` is no idle expiry. */
export const IDLE_CHOICES: { value: string; label: string }[] = [
  { value: String(15 * 60), label: "15 minutes" },
  { value: String(3600), label: "1 hour" },
  { value: String(2 * 3600), label: "2 hours (default)" },
  { value: String(8 * 3600), label: "8 hours" },
  { value: String(24 * 3600), label: "1 day" },
  { value: String(7 * 24 * 3600), label: "7 days" },
  { value: "off", label: "Never" },
];

export function idleValue(secs: number | null): string {
  return secs === null ? "off" : String(secs);
}

export function idleSecs(value: string): number | null {
  return value === "off" ? null : Number(value);
}

/** The choices, with `current` added when it is not one of them. */
export function idleOptions(current: number | null) {
  const value = idleValue(current);
  if (IDLE_CHOICES.some((c) => c.value === value)) return IDLE_CHOICES;
  return [...IDLE_CHOICES, { value, label: `${Math.round((current ?? 0) / 60)} minutes` }];
}
