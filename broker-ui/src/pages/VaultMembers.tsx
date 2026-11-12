// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Who works in a vault, and with which role; and, for an instance admin who
// is not one of them, the way in.

import { useMemo, useState, type FormEvent } from "react";
import { DoorOpen, Eye, LogOut, Pencil, Plus, UserMinus, Users } from "lucide-react";
import { del, get, post, put, type Page, type VaultMember, type VaultRole } from "../api";
import { can, onlyFor, type Me } from "../access";
import { addedByLabel, isLastAdmin, roleLabel, VAULT_ROLES } from "../members";
import { useAction, useLoad } from "../hooks";
import {
  fromWidth,
  ChoiceCards,
  ConfirmDialog,
  DialogActions,
  Empty,
  ErrorBanner,
  Field,
  FormDialog,
  Loading,
  Pager,
  Panel,
  Relative,
  RowActions,
  RowMenu,
  Section,
  useConfirm,
} from "../components/common";
import { cn } from "../lib/utils";
import { Alert, AlertDescription, AlertTitle } from "../components/ui/alert";
import { Button } from "../components/ui/button-components";
import { Input } from "../components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../components/ui/table";

export function VaultMembers({ vaultId, user, onAccessChanged }: { vaultId: string; user: Me; onAccessChanged: () => void }) {
  const [page, setPage] = useState(1);
  const members = useLoad(() => get<Page<VaultMember>>(`/vaults/${vaultId}/members?page=${page}`), [vaultId, page]);
  const [editing, setEditing] = useState<VaultMember | "new" | null>(null);
  const confirm = useConfirm<VaultMember>();
  const action = useAction();
  const canManage = can(user, vaultId, "manage");
  const items = members.data?.items ?? [];
  const names = useMemo(
    () => ({
      meId: user.id,
      users: new Map(items.map((m) => [m.user_id, m.username])),
    }),
    [user.id, items],
  );

  const remove = async (m: VaultMember) => {
    const done = await action.run(() => del(`/vaults/${vaultId}/members/${m.user_id}`).then(() => true));
    confirm.close();
    if (!done) return;
    if (m.user_id === user.id) onAccessChanged();
    else members.reload();
  };

  const addButton = (
    <Button
      type="button"
      onClick={() => setEditing("new")}
      disabled={!canManage}
      title={canManage ? undefined : onlyFor("manage")}
    >
      <Plus />
      Add someone
    </Button>
  );
  const leaving = confirm.target?.user_id === user.id;

  return (
    <Section title="Members" actions={addButton}>
      <ErrorBanner error={members.error ?? action.error} />
      <Panel>
        {members.loading && !members.data ? (
          <Loading />
        ) : items.length === 0 ? (
          <Empty
            icon={Users}
            title="Nobody works in this vault yet"
            description="Add someone by their username."
            action={addButton}
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Person</TableHead>
                <TableHead>Role</TableHead>
                <TableHead className={fromWidth.md}>Given by</TableHead>
                <TableHead className={fromWidth.lg}>Since</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((m) => {
                const me = m.user_id === user.id;
                const last = isLastAdmin(items, m.user_id);
                return (
                  <TableRow key={m.user_id}>
                    <TableCell>
                      <div className="font-medium">
                        {m.username}
                        {me && <span className="font-normal text-muted-foreground"> (you)</span>}
                      </div>
                      <div className="text-xs text-muted-foreground @md:hidden">{addedByLabel(m.added_by, names)}</div>
                    </TableCell>
                    <TableCell>{roleLabel(m.role)}</TableCell>
                    <TableCell className={cn(fromWidth.md, "text-muted-foreground")}>{addedByLabel(m.added_by, names)}</TableCell>
                    <TableCell className={cn(fromWidth.lg, "text-muted-foreground")}>
                      <Relative at={m.added_at} />
                    </TableCell>
                    <TableCell>
                      <RowActions>
                        <RowMenu
                          label={m.username}
                          items={[
                            {
                              label: "Change role",
                              icon: Pencil,
                              onSelect: () => setEditing(m),
                              disabled: !canManage,
                              reason: onlyFor("manage"),
                            },
                            {
                              label: me ? "Leave vault" : "Remove from vault",
                              icon: me ? LogOut : UserMinus,
                              onSelect: () => confirm.ask(m),
                              destructive: true,
                              disabled: last || !(me || canManage),
                              reason: last
                                ? "A vault keeps at least one admin; make someone else admin first"
                                : onlyFor("manage"),
                            },
                          ]}
                        />
                      </RowActions>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        )}
        <Pager page={members.data} onPage={setPage} />
      </Panel>
      <FormDialog
        open={editing !== null}
        onOpenChange={(o) => !o && setEditing(null)}
        title={editing === "new" || editing === null ? "Add someone to this vault" : `${editing.username}'s role`}
        wide
      >
        {editing !== null && (
          <MemberForm
            vaultId={vaultId}
            member={editing === "new" ? null : editing}
            demotingLastAdmin={editing !== "new" && isLastAdmin(items, editing.user_id)}
            onCancel={() => setEditing(null)}
            onSaved={(m) => {
              setEditing(null);
              if (m.user_id === user.id) onAccessChanged();
              else members.reload();
            }}
          />
        )}
      </FormDialog>
      <ConfirmDialog
        open={confirm.open}
        onOpenChange={confirm.onOpenChange}
        title={leaving ? "Leave this vault?" : `Remove ${confirm.target?.username ?? ""} from this vault?`}
        description={
          leaving
            ? "You stop reaching its services, rules and bundles. Sessions already started keep running until they expire or someone stops them."
            : "They stop reaching its services, rules and bundles. Sessions they already started keep running until they expire or someone stops them."
        }
        confirmLabel={leaving ? "Leave vault" : "Remove"}
        busy={action.busy}
        onConfirm={() => confirm.target && void remove(confirm.target)}
      />
    </Section>
  );
}

function MemberForm({
  vaultId,
  member,
  demotingLastAdmin,
  onCancel,
  onSaved,
}: {
  vaultId: string;
  member: VaultMember | null;
  demotingLastAdmin: boolean;
  onCancel: () => void;
  onSaved: (m: VaultMember) => void;
}) {
  const [username, setUsername] = useState(member?.username ?? "");
  const [role, setRole] = useState<VaultRole>(member?.role ?? "runner");
  const action = useAction();

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const saved = await action.run(() =>
      put<VaultMember>(`/vaults/${vaultId}/members`, {
        username: username.trim(),
        role,
      }),
    );
    if (saved) onSaved(saved);
  };

  return (
    <form onSubmit={(e) => void submit(e)} className="space-y-4">
      <ErrorBanner error={action.error} />
      {!member && (
        <Field label="Username" htmlFor="member-username" hint="They need an account first: an admin invites them from People.">
          <Input
            id="member-username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="off"
            required
            autoFocus
          />
        </Field>
      )}
      <Field
        label="Role in this vault"
        error={
          demotingLastAdmin && role !== "admin" ? "They are the vault's only admin; make someone else admin first." : undefined
        }
      >
        <ChoiceCards
          name="member-role"
          value={role}
          onChange={setRole}
          columns={2}
          choices={VAULT_ROLES.map((r) => ({
            value: r.value,
            title: r.label,
            description: r.description,
          }))}
        />
      </Field>
      <DialogActions>
        <Button type="button" variant="outline" onClick={onCancel}>
          Cancel
        </Button>
        <Button type="submit" disabled={action.busy || username.trim() === "" || (demotingLastAdmin && role !== "admin")}>
          {member ? "Save role" : "Add to vault"}
        </Button>
      </DialogActions>
    </form>
  );
}

/**
 * What an instance admin sees of a vault they are not a member of: that
 * they can watch and stop it, not change it, and the way in.
 */
export function OverseeNotice({ vaultId, onJoined }: { vaultId: string; onJoined: () => void }) {
  const action = useAction();
  const join = async () => {
    const joined = await action.run(() => post<VaultMember>(`/vaults/${vaultId}/join`));
    if (joined) onJoined();
  };
  return (
    <Alert>
      <Eye className="size-4" />
      <AlertTitle>You oversee this vault, you are not a member of it</AlertTitle>
      <AlertDescription className="space-y-3">
        <p>
          As an instance admin you see its sessions, launcher keys and audit log, and can stop them. Its services, rules and
          bundles are for its members. Joining makes you one of its admins and is recorded in the audit log.
        </p>
        <ErrorBanner error={action.error} />
        <Button type="button" variant="outline" onClick={() => void join()} disabled={action.busy}>
          <DoorOpen />
          Join as admin
        </Button>
      </AlertDescription>
    </Alert>
  );
}
