// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { describe, expect, test } from "bun:test";
import { allowsLabel } from "./rules";

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
