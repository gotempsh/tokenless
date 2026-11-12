// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { describe, expect, test } from "bun:test";
import { DEFAULT_RATE_LIMIT, parseRateKey, parseRequestLimit, rateKey, rateLabel, rateOptions, requestLimitLabel } from "./ratelimit";

describe("rate limit choices", () => {
  test("read as a rate", () => {
    expect(rateLabel(DEFAULT_RATE_LIMIT)).toBe("20 a second, bursts of 100 (default)");
    expect(rateLabel({ per_sec: 5, burst: 25 })).toBe("5 a second, bursts of 25");
  });
  test("round-trip through the select's value, and one set over the API is shown", () => {
    expect(parseRateKey(rateKey({ per_sec: 50, burst: 250 }))).toEqual({ per_sec: 50, burst: 250 });
    expect(rateOptions({ per_sec: 7, burst: 70 }).at(-1)).toEqual({ value: "7/70", label: "7 a second, bursts of 70" });
    expect(rateOptions(DEFAULT_RATE_LIMIT)).toHaveLength(4);
  });
});

describe("a bundle's request limit", () => {
  test("reads as a count or none", () => {
    expect(requestLimitLabel(null)).toBe("No limit");
    expect(requestLimitLabel(1)).toBe("1 request per session");
    expect(requestLimitLabel(5000)).toBe("5,000 requests per session");
  });
  test("is a whole number in range", () => {
    expect(parseRequestLimit(" 500 ")).toEqual({ limit: 500 });
    for (const bad of ["", "0", "-3", "1.5", "lots"]) {
      expect("error" in parseRequestLimit(bad)).toBe(true);
    }
    expect(parseRequestLimit("2000000000")).toEqual({ error: "At most 1,000,000,000; remove the limit for none" });
  });
});
