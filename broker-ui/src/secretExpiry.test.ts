// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { describe, expect, test } from "bun:test";
import { expiryToSend, secretExpired } from "./secretExpiry";

const now = new Date("2026-06-01T12:00:00Z");

describe("a secret's deadline", () => {
  test("is flagged once it has passed, and never when there is none", () => {
    expect(secretExpired(undefined, now)).toBe(false);
    expect(secretExpired(null, now)).toBe(false);
    expect(secretExpired("2026-06-01T11:59:59Z", now)).toBe(true);
    expect(secretExpired("2026-06-01T12:00:00Z", now)).toBe(true);
    expect(secretExpired("2026-06-01T12:00:01Z", now)).toBe(false);
  });

  test("left empty clears it; a past or unreadable time is refused before sending", () => {
    expect(expiryToSend("", now)).toEqual({ value: null });
    expect(expiryToSend("not a date", now).problem).toContain("Enter a date");
    expect(expiryToSend("2020-01-01T00:00", now).problem).toContain("has passed");
    const later = expiryToSend("2030-01-01T00:00", now);
    expect(later.problem).toBeUndefined();
    expect(Date.parse(later.value ?? "")).toBe(new Date("2030-01-01T00:00").getTime());
  });
});
