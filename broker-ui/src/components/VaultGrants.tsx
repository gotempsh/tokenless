// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Roles in vaults, picked a vault at a time: what an invitation or an
// identity provider's group gives.

import { Plus, X } from "lucide-react";
import type { VaultGrant, VaultRole } from "../api";
import { VAULT_ROLES } from "../members";
import { SelectField } from "./common";
import { Button } from "./ui/button-components";

const VAULT_ROLE_OPTIONS: { value: VaultRole; label: string }[] = VAULT_ROLES.map((r) => ({ value: r.value, label: r.label }));

/** The vaults someone is given a role in, one row per vault. */
export function VaultGrants({
  group,
  grants,
  vaults,
  onChange,
  empty = "No vaults: they sign in and see nothing until a vault admin adds them.",
}: {
  /** Tells the rows' fields apart when there are several lists on a page. */
  group: number;
  grants: VaultGrant[];
  vaults: { value: string; label: string }[];
  onChange: (grants: VaultGrant[]) => void;
  /** What having no vaults means here. */
  empty?: string;
}) {
  const setGrant = (i: number, patch: Partial<VaultGrant>) => onChange(grants.map((g, j) => (j === i ? { ...g, ...patch } : g)));
  return (
    <div className="space-y-2">
      {grants.length === 0 && (
        <p className="text-xs text-muted-foreground">{empty}</p>
      )}
      {grants.map((g, i) => (
        <div key={i} className="flex items-center gap-2">
          <SelectField
            id={`vault-grant-${group}-${i}`}
            className="min-w-0 flex-1"
            value={g.vault_id}
            onChange={(vault_id) => setGrant(i, { vault_id })}
            options={vaults}
            placeholder="Choose a vault…"
          />
          <SelectField
            id={`vault-grant-role-${group}-${i}`}
            className="w-36 shrink-0"
            value={g.role}
            onChange={(v) => setGrant(i, { role: v as VaultRole })}
            options={VAULT_ROLE_OPTIONS}
          />
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="size-8 shrink-0"
            aria-label={`Remove vault ${i + 1} of group ${group}`}
            onClick={() => onChange(grants.filter((_, j) => j !== i))}
          >
            <X />
          </Button>
        </div>
      ))}
      <Button type="button" variant="ghost" size="sm" onClick={() => onChange([...grants, { vault_id: "", role: "runner" }])}>
        <Plus />
        Give a role in a vault
      </Button>
    </div>
  );
}
