// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { describe, expect, test } from "bun:test";
import { allowsLabel, suggestedCopyName } from "./rules";

const rule = (paths: string[], methods: string[]) => ({ allow: { hosts: ["api.example.com"], paths, methods } });

describe("allowsLabel", () => {
  test("a rule that narrows nothing says so", () => {
    expect(allowsLabel(rule(["/*"], ["*"]))).toBe("Every path and method");
    expect(allowsLabel(rule([], []))).toBe("Every path and method");
  });

  test("names only what is narrowed", () => {
    expect(allowsLabel(rule(["/repos/*"], ["*"]))).toBe("Any method on /repos/*");
    expect(allowsLabel(rule(["/*"], ["GET", "HEAD"]))).toBe("GET, HEAD on any path");
    expect(allowsLabel(rule(["/v1/charges"], ["POST"]))).toBe("POST on /v1/charges");
  });
});

test("copy names distinguish drafts and fit the server's UTF-8 byte limit", () => {
  expect(suggestedCopyName("build")).not.toBe(suggestedCopyName("build"));
  for (const source of ["a".repeat(100), "界".repeat(33), "🐙".repeat(25)]) {
    const name = suggestedCopyName(source);
    expect(new TextEncoder().encode(name).length).toBeLessThanOrEqual(100);
    expect(name).toMatch(/ \(copy [a-f0-9]{12}\)$/);
    expect(source.startsWith(name.slice(0, name.indexOf(" (copy ")))).toBe(true);
    expect(new TextDecoder().decode(new TextEncoder().encode(name))).toBe(name);
  }
});
