// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Vault roles as people pick them, and who gave a member their role.

import type { InviteInfo, VaultMember, VaultRole } from "./api";
import { actorName, type ActorNames } from "./audit";

export const VAULT_ROLES: {
  value: VaultRole;
  label: string;
  description: string;
}[] = [
  {
    value: "runner",
    label: "Runner",
    description: "Starts sessions from the vault's bundles. Sees which services they reach, never a secret.",
  },
  {
    value: "viewer",
    label: "Viewer",
    description: "Reads services, rules, bundles, sessions and the audit log.",
  },
  {
    value: "editor",
    label: "Editor",
    description: "Also changes rules, bundles and launcher keys, and stops sessions.",
  },
  {
    value: "admin",
    label: "Admin",
    description: "Also adds and changes services, and decides who is a member.",
  },
];

export function roleLabel(role: VaultRole): string {
  return VAULT_ROLES.find((r) => r.value === role)?.label ?? role;
}

/** Who gave the role: a person, an identity provider's groups, or the upgrade. */
export function addedByLabel(addedBy: string, names: ActorNames): string {
  if (addedBy.startsWith("sso:")) return `Groups at ${addedBy.slice(4)}`;
  if (addedBy === "system") return "Kept from before vault roles";
  return actorName(addedBy, names);
}

/**
 * Whether removing this member, or demoting them, would leave the vault with
 * no admin. Only said when `members` is the whole vault (`total` of them):
 * another admin may be on a page not loaded, and the server refuses taking
 * the last one away anyway.
 */
export function isLastAdmin(members: VaultMember[], userId: string, total = members.length): boolean {
  if (total > members.length) return false;
  const admins = members.filter((m) => m.role === "admin");
  return admins.length === 1 && admins[0]?.user_id === userId;
}

/** What accepting the invite gives, in a sentence. */
export function joinsVaults(info: InviteInfo): string {
  const vaults = info.vaults ?? [];
  if (vaults.length === 0)
    return info.role === "admin" ? "You will run this instance." : "You join with no vault yet; a vault's admin adds you.";
  const list = vaults.map((v) => `${v.name} as ${roleLabel(v.role).toLowerCase()}`).join(", ");
  return `You join ${vaults.length === 1 ? "the vault" : "the vaults"} ${list}.`;
}
