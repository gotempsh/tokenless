// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { describe, expect, test } from "bun:test";
import { can, canSomewhere, meFrom, oversees, vaultRole, type Me } from "./access";

const base = {
  id: "u1",
  username: "someone",
  created_at: "2026-01-01T00:00:00Z",
  disabled_at: null,
  totp_enrolled: true,
};

function me(role: "admin" | "member", vaults: Me["vaults"], scope: Me["scope"] = "full"): Me {
  return { ...base, role, vaults, scope };
}

describe("access", () => {
  test("a member acts with their role in each vault, and nothing outside them", () => {
    const m = me("member", [
      { vault_id: "work", role: "editor" },
      { vault_id: "ci", role: "runner" },
    ]);
    expect(vaultRole(m, "work")).toBe("editor");
    expect(can(m, "work", "edit")).toBe(true);
    expect(can(m, "work", "manage")).toBe(false);
    expect(can(m, "ci", "start")).toBe(true);
    expect(can(m, "ci", "audit")).toBe(false);
    expect(can(m, "ci", "edit")).toBe(false);
    expect(can(m, "other", "read")).toBe(false);
    expect(oversees(m, "other")).toBe(false);
  });

  test("an instance admin oversees a vault they are not in, and joins it to change it", () => {
    const a = me("admin", []);
    expect(oversees(a, "work")).toBe(true);
    expect(can(a, "work", "audit")).toBe(true);
    expect(can(a, "work", "stop")).toBe(true);
    expect(can(a, "work", "read")).toBe(false);
    expect(can(a, "work", "edit")).toBe(false);
    expect(can(a, "work", "start")).toBe(false);
    const joined = me("admin", [{ vault_id: "work", role: "admin" }]);
    expect(oversees(joined, "work")).toBe(false);
    expect(can(joined, "work", "manage")).toBe(true);
  });

  test("a launch-only sign-in changes nothing anywhere", () => {
    const l = me("admin", [{ vault_id: "work", role: "admin" }], "launch");
    expect(can(l, "work", "manage")).toBe(false);
    expect(canSomewhere(l, "edit")).toBe(false);
  });

  test("a session from before vault memberships reads as no vaults and a full sign-in", () => {
    const m = meFrom({
      user: { ...base, role: "member" },
      csrf_token: "c",
      expires_at: "2026-01-01T00:00:00Z",
      step_up_at: null,
    } as unknown as Parameters<typeof meFrom>[0]);
    expect(m.vaults).toEqual([]);
    expect(m.scope).toBe("full");
  });
});
