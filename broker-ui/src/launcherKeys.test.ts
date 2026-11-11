// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { describe, expect, test } from "bun:test";
import type { LauncherKey } from "./api";
import { KEY_SAVE_COMMAND, keyRunCommand, keyState, lengthChoices, sessionLength } from "./launcherKeys";

const now = new Date("2026-06-01T12:00:00Z");

function key(over: Partial<LauncherKey> = {}): LauncherKey {
  return {
    id: "k1",
    name: "build-runner",
    prefix: "cbk_abc",
    vault_id: "v1",
    bundle_id: "b1",
    max_ttl_secs: 900,
    labels: {},
    created_by: "user:u1",
    created_at: "2026-05-01T00:00:00Z",
    expires_at: "2026-08-01T00:00:00Z",
    revoked_at: null,
    last_used_at: null,
    ...over,
  };
}

describe("launcher keys", () => {
  test("a key is active until it is revoked or expires", () => {
    expect(keyState(key(), now)).toBe("active");
    expect(keyState(key({ expires_at: "2026-06-01T11:59:59Z" }), now)).toBe("expired");
    expect(keyState(key({ revoked_at: "2026-05-02T00:00:00Z", expires_at: "2026-05-03T00:00:00Z" }), now)).toBe("revoked");
  });

  test("session lengths read as people say them", () => {
    expect(sessionLength(900)).toBe("15 min");
    expect(sessionLength(3600)).toBe("1 h");
    expect(sessionLength(5400)).toBe("90 min");
    expect(sessionLength(45)).toBe("45 s");
  });

  test("only lengths Settings allow are offered", () => {
    expect(lengthChoices(7 * 24 * 3600)).toEqual([300, 900, 3600, 28800]);
    expect(lengthChoices(1800)).toEqual([300, 900]);
  });

  test("the machine's commands quote what needs quoting", () => {
    expect(keyRunCommand("code-review", "claude", "work")).toBe(
      "tokenless run --api-key-file ~/.config/tokenless/launcher.key --vault work --bundle code-review -- claude",
    );
    expect(keyRunCommand("code-review", "claude")).not.toContain("--vault");
    expect(keyRunCommand("b", "claude", "my vault")).toContain("--vault 'my vault'");
    // The key is pasted, never typed into the command line.
    expect(KEY_SAVE_COMMAND).toContain("umask 077");
    expect(KEY_SAVE_COMMAND).not.toContain("cbk_");
  });
});
