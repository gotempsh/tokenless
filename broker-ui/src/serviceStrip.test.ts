// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { describe, expect, test } from "bun:test";
import { serviceStrip } from "./serviceStrip";

describe("serviceStrip", () => {
  test("shows up to four and counts the rest from the record's total", () => {
    expect(serviceStrip(["a", "b", "c", "d", "e", "f"], 6)).toEqual({ shown: ["a", "b", "c", "d"], more: 2 });
  });

  test("counts services the list did not include", () => {
    // A vault overview carries a few services but the full count.
    expect(serviceStrip(["a", "b", "c", "d"], 9)).toEqual({ shown: ["a", "b", "c", "d"], more: 5 });
  });

  test("nothing more when everything fits", () => {
    expect(serviceStrip(["a", "b"], 2)).toEqual({ shown: ["a", "b"], more: 0 });
    expect(serviceStrip([], 0)).toEqual({ shown: [], more: 0 });
  });
});
