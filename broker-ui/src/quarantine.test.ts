// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { describe, expect, test } from "bun:test";
import { DEFAULT_QUARANTINE, parseQuarantineKey, quarantineKey, quarantineLabel, quarantineOptions } from "./quarantine";

describe("quarantine choices", () => {
  test("read as a threshold", () => {
    expect(quarantineLabel(DEFAULT_QUARANTINE)).toBe("20 refusals in 5 minutes (default)");
    expect(quarantineLabel({ refusals: 100, window_secs: 600 })).toBe("100 refusals in 10 minutes");
    expect(quarantineLabel({ refusals: 5, window_secs: 90 })).toBe("5 refusals in 90 seconds");
  });
  test("round-trip through the select's value", () => {
    expect(parseQuarantineKey(quarantineKey({ refusals: 50, window_secs: 300 }))).toEqual({ refusals: 50, window_secs: 300 });
  });
  test("a value set over the API is still shown", () => {
    const options = quarantineOptions({ refusals: 7, window_secs: 60 });
    expect(options.at(-1)).toEqual({ value: "7/60", label: "7 refusals in 1 minute" });
    expect(quarantineOptions(DEFAULT_QUARANTINE)).toHaveLength(4);
  });
});
