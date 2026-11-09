// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { describe, expect, test } from "bun:test";
import type { Page } from "./api";
import { fallbackPage, hasPager } from "./paging";

const page = (n: number, items: number, total: number): Page<number> => ({
  items: Array.from({ length: items }, (_, i) => i),
  total,
  page: n,
  page_size: 20,
});

describe("hasPager", () => {
  test("only when there is somewhere else to go", () => {
    expect(hasPager(page(1, 20, 20))).toBe(false);
    expect(hasPager(page(1, 20, 21))).toBe(true);
  });

  test("past the first page even when the rest fit on one", () => {
    // 21 bundles, the only one on page 2 deleted: the way back stays.
    expect(hasPager(page(2, 0, 20))).toBe(true);
  });
});

describe("fallbackPage", () => {
  test("an emptied page goes back to the last page with items", () => {
    expect(fallbackPage(page(2, 0, 20))).toBe(1);
    expect(fallbackPage(page(5, 0, 41))).toBe(3);
  });

  test("leaves a page with items, the first page and an empty list alone", () => {
    expect(fallbackPage(page(2, 1, 21))).toBeNull();
    expect(fallbackPage(page(1, 0, 0))).toBeNull();
    expect(fallbackPage(page(3, 0, 0))).toBe(1);
  });
});
