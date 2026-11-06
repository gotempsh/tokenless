// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { describe, expect, test } from "bun:test";
import { compactTime, relativeTime } from "./time";

const now = new Date("2026-11-06T12:00:00Z");
const ago = (secs: number) => new Date(now.getTime() - secs * 1000);

describe("table times", () => {
  test("the last day reads relative", () => {
    expect(relativeTime(ago(10), now, "en")).toBe("just now");
    expect(compactTime(ago(5 * 60), now, "en")).toBe("5 minutes ago");
    expect(compactTime(ago(-3 * 3600), now, "en")).toBe("in 3 hours");
  });

  test("older dates show the day only, with the year when it differs", () => {
    expect(compactTime(ago(3 * 24 * 3600), now, "en")).toBe("Nov 3");
    expect(compactTime(new Date("2025-02-01T12:00:00Z"), now, "en")).toBe("Feb 1, 2025");
    expect(compactTime(ago(3 * 24 * 3600), now, "en")).not.toMatch(/:/);
  });
});
