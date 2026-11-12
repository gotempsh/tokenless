// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { describe, expect, test } from "bun:test";
import { idleOptions, idleSecs, idleValue, revokedMessage } from "./signIns";

describe("revokedMessage", () => {
  test("says how many sign-ins ended", () => {
    expect(revokedMessage(2)).toBe("Signed out everywhere else: ended 2 sign-ins.");
    expect(revokedMessage(1, "ada")).toBe("Signed ada out everywhere: ended 1 sign-in.");
  });
  test("says when there was nothing to end", () => {
    expect(revokedMessage(0)).toBe("You were signed in only here.");
    expect(revokedMessage(0, "ada")).toBe("ada was not signed in anywhere.");
  });
});

describe("idle timeout choices", () => {
  test("off round-trips as null", () => {
    expect(idleValue(null)).toBe("off");
    expect(idleSecs("off")).toBeNull();
    expect(idleSecs(idleValue(7200))).toBe(7200);
  });
  test("a value set elsewhere is still shown", () => {
    const options = idleOptions(600);
    expect(options.at(-1)).toEqual({ value: "600", label: "10 minutes" });
    expect(idleOptions(7200)).toHaveLength(7);
  });
});
