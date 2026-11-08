// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// A service's secret can carry the time it stops working upstream. The
// proxy stops sending it then, so the page flags it and asks for a new one.

/** Has the secret's deadline passed? False when it has none. */
export function secretExpired(notAfter: string | null | undefined, now: Date): boolean {
  if (!notAfter) return false;
  const at = Date.parse(notAfter);
  return !Number.isNaN(at) && at <= now.getTime();
}

/**
 * The deadline to send for a `datetime-local` input's value: `null` when
 * left empty, `undefined` with `problem` set when it can't be used.
 */
export function expiryToSend(local: string, now: Date): { value?: string | null; problem?: string } {
  if (local.trim() === "") return { value: null };
  const at = new Date(local);
  if (Number.isNaN(at.getTime())) return { problem: "Enter a date and time, or leave it empty." };
  if (at.getTime() <= now.getTime()) return { problem: "That time has passed; give when the new secret stops working." };
  return { value: at.toISOString() };
}
