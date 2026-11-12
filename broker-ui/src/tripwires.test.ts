// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { describe, expect, test } from "bun:test";
import { kindLabel, TRIPWIRE_KINDS, whereSeen } from "./tripwires";

describe("tripwires", () => {
  test("every kind has a label", () => {
    expect(TRIPWIRE_KINDS.map((k) => k.value)).toEqual(["aws", "github", "openai", "generic"]);
    expect(kindLabel("aws")).toBe("AWS access key");
  });

  test("says where a decoy is looked for", () => {
    expect(whereSeen("github")).toBe(
      "Seen in every request a proxy opens for a session's rules, and on api.github.com, github.com when other hosts are blocked.",
    );
    expect(whereSeen("generic")).toBe("Seen in every request a proxy opens for a session's rules.");
  });
});
