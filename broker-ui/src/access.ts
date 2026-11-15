// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// What the signed-in person may do, as the server decides it: inside a
// vault by their role there, elsewhere by their instance role. Instance
// admins oversee vaults they are not members of (read, audit, stop
// sessions and keys) and join one to change it.

import type { SessionInfo, UserSummary, VaultGrant, VaultRole } from "./api";

/** The signed-in person with the vaults they belong to. */
export interface Me extends UserSummary {
  vaults: VaultGrant[];
  /** `launch` for a sign-in that only starts sessions. */
  scope: SessionInfo["scope"];
}

export function meFrom(session: SessionInfo): Me {
  return {
    ...session.user,
    vaults: session.vaults ?? [],
    scope: session.scope ?? "full",
  };
}

/**
 * - `read`: see the vault's services, rules and bundles;
 * - `audit`: its sessions, launcher keys and audit log;
 * - `start`: start sessions from its bundles;
 * - `stop`: revoke sessions and launcher keys, acknowledge alerts;
 * - `edit`: change rules, bundles and launcher keys;
 * - `manage`: add and change services, and who is a member.
 */
export type VaultAbility = "read" | "audit" | "start" | "stop" | "edit" | "manage";

const BY_ROLE: Record<VaultRole, VaultAbility[]> = {
  admin: ["read", "audit", "start", "stop", "edit", "manage"],
  editor: ["read", "audit", "start", "stop", "edit"],
  viewer: ["read", "audit"],
  runner: ["read", "start"],
};

/** What an instance admin may do in a vault without being a member. */
const OVERSIGHT: VaultAbility[] = ["audit", "stop"];

export function isInstanceAdmin(me: Me): boolean {
  return me.role === "admin";
}

export function vaultRole(me: Me, vaultId: string | undefined): VaultRole | null {
  if (!vaultId) return null;
  return me.vaults.find((g) => g.vault_id === vaultId)?.role ?? null;
}

export function can(me: Me, vaultId: string | undefined, ability: VaultAbility): boolean {
  if (me.scope === "launch") return false;
  const role = vaultRole(me, vaultId);
  if (role) return BY_ROLE[role].includes(ability);
  return Boolean(vaultId) && isInstanceAdmin(me) && OVERSIGHT.includes(ability);
}

/** Whether the person may do `ability` in at least one vault. */
export function canSomewhere(me: Me, ability: VaultAbility): boolean {
  return me.vaults.some((g) => can(me, g.vault_id, ability));
}

/** Whether an instance admin sees this vault only from outside, and can join it. */
export function oversees(me: Me, vaultId: string | undefined): boolean {
  return Boolean(vaultId) && isInstanceAdmin(me) && vaultRole(me, vaultId) === null;
}

/** Why a control is off, for its title: who may use it. */
export function onlyFor(ability: VaultAbility): string {
  switch (ability) {
    case "manage":
      return "Only the vault's admins can do this";
    case "edit":
    case "stop":
      return "Only the vault's editors and admins can do this";
    case "start":
      return "Viewers cannot start sessions; ask a vault admin for the runner or editor role";
    case "audit":
      return "Runners do not see the vault's sessions or audit log";
    case "read":
      return "You are not a member of this vault";
  }
}
