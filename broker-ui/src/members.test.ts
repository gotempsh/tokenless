// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { describe, expect, test } from "bun:test";
import type { VaultMember } from "./api";
import { addedByLabel, isLastAdmin, joinsVaults, roleLabel, VAULT_ROLES } from "./members";

const member = (user_id: string, role: VaultMember["role"]): VaultMember => ({
  vault_id: "v",
  user_id,
  username: user_id,
  role,
  added_by: "user:someone",
  added_at: "2026-01-01T00:00:00Z",
});

describe("members", () => {
  test("roles go from least to most access", () => {
    expect(VAULT_ROLES.map((r) => r.value)).toEqual(["runner", "viewer", "editor", "admin"]);
    expect(roleLabel("runner")).toBe("Runner");
  });

  test("says who gave a role", () => {
    const names = { meId: "me", users: new Map([["u2", "someone"]]) };
    expect(addedByLabel("sso:corp", names)).toBe("Groups at corp");
    expect(addedByLabel("system", names)).toBe("Kept from before vault roles");
    expect(addedByLabel("user:u2", names)).toBe("someone");
    expect(addedByLabel("user:me", names)).toBe("You");
  });

  test("only the one remaining admin is the last admin", () => {
    expect(isLastAdmin([member("a", "admin"), member("b", "editor")], "a")).toBe(true);
    expect(isLastAdmin([member("a", "admin"), member("b", "admin")], "a")).toBe(false);
    expect(isLastAdmin([member("a", "admin"), member("b", "editor")], "b")).toBe(false);
  });

  test("an invitation says which vaults it gives, and with which role", () => {
    const at = "2026-01-01T00:00:00Z";
    expect(joinsVaults({ role: "member", vaults: [], expires_at: at })).toContain("no vault yet");
    expect(joinsVaults({ role: "admin", vaults: [], expires_at: at })).toContain("run this instance");
    expect(
      joinsVaults({
        role: "member",
        vaults: [
          { vault_id: "a", name: "work", role: "runner" },
          { vault_id: "b", name: "ci", role: "editor" },
        ],
        expires_at: at,
      }),
    ).toBe("You join the vaults work as runner, ci as editor.");
  });
});
