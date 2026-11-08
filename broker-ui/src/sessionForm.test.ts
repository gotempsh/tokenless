// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { describe, expect, test } from "bun:test";
import { defaultLifetime, lifetimeLabel, lifetimesUpTo, tokenCommands } from "./sessionForm";

describe("new session form", () => {
  test("offers the presets up to the cap, and the cap itself", () => {
    expect(lifetimesUpTo(7 * 86400).map((l) => l.label)).toEqual(["1 hour", "8 hours", "1 day", "7 days"]);
    expect(lifetimesUpTo(3600).map((l) => l.label)).toEqual(["1 hour"]);
    expect(lifetimesUpTo(2 * 86400).map((l) => l.label)).toEqual(["1 hour", "8 hours", "1 day", "2 days"]);
    expect(lifetimesUpTo(15 * 60).map((l) => l.label)).toEqual(["15 minutes"]);
  });

  test("defaults to a day, or the cap when it is shorter", () => {
    expect(defaultLifetime(90 * 86400)).toBe(86400);
    expect(defaultLifetime(3600)).toBe(3600);
  });

  test("names a lifetime in its largest whole unit", () => {
    expect(lifetimeLabel(86400)).toBe("1 day");
    expect(lifetimeLabel(8 * 3600)).toBe("8 hours");
    expect(lifetimeLabel(90)).toBe("2 minutes");
  });

  test("hands the token to the agent's shell, never to the command line of run", () => {
    const { exportLine, run } = tokenCommands("v4.public.abc", "claude");
    expect(exportLine).toBe("export TOKENLESS_SESSION_TOKEN=v4.public.abc");
    expect(run).toBe("tokenless run -- claude");
  });
});
