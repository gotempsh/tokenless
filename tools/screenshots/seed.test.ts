// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { describe, expect, test } from "bun:test";
import { runChecked } from "./seed.ts";

describe("runChecked", () => {
  test("returns what the command printed", () => {
    expect(runChecked("sh", ["-c", "echo 401"])).toBe("401");
  });

  test("a binary that is not there names it and how to point at it", () => {
    expect(() => runChecked("tokenless-not-installed-here", ["--version"])).toThrow(
      /could not run tokenless-not-installed-here \(set TOKENLESS_BIN/,
    );
  });

  test("a run that fails stops the seeding with its error", () => {
    expect(() => runChecked("sh", ["-c", "echo 'proxy unreachable' >&2; exit 3"])).toThrow(
      /exited 3: proxy unreachable/,
    );
  });
});
