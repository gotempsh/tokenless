// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { useState, type FormEvent, type ReactNode } from "react";
import { Mail, ShieldCheck, UserPlus } from "lucide-react";
import { del, get, patch, post, type Invite, type Page, type Role, type UserSummary } from "../api";
import { useAction, useLoad } from "../hooks";
import {
  ChoiceCards,
  ConfirmDialog,
  DialogActions,
  Empty,
  ErrorBanner,
  Field,
  FormDialog,
  Loading,
  Mono,
  OneTimeSecret,
  Pager,
  Panel,
  RowActions,
  Section,
  SelectField,
  Status,
  useConfirm,
  When,
  type Choice,
  type Tone,
} from "../components/common";
import { Alert, AlertDescription, AlertTitle } from "../components/ui/alert";
import { Button } from "../components/ui/button-components";
import { Input } from "../components/ui/input";
import { PageContainer, PageHeader } from "../components/ui/page-header";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../components/ui/table";

type PersonRole = Extract<Role, "admin" | "editor" | "viewer">;

const PERSON_ROLES: Choice<PersonRole>[] = [
  { value: "viewer", title: "Viewer", description: "Read vaults, rules, sessions and the audit log" },
  { value: "editor", title: "Editor", description: "Also manage rules and mint or revoke sessions" },
  { value: "admin", title: "Admin", description: "Full control, including credentials and people" },
];

function inviteStatus(i: Invite): { label: string; tone: Tone } {
  if (i.accepted_at) return { label: "accepted", tone: "success" };
  if (i.revoked_at) return { label: "revoked", tone: "destructive" };
  if (new Date(i.expires_at) <= new Date()) return { label: "expired", tone: "neutral" };
  return { label: "pending", tone: "warning" };
}

interface PendingChange {
  user: UserSummary;
  change: { role?: Role; disabled?: boolean };
  title: string;
  description: ReactNode;
  confirmLabel: string;
  destructive: boolean;
}

/** People: invite with a role, change roles, disable accounts. */
export function People({ me }: { me: UserSummary }) {
  const isAdmin = me.role === "admin";
  const [userPage, setUserPage] = useState(1);
  const [invitePage, setInvitePage] = useState(1);
  const users = useLoad(
    () => (isAdmin ? get<Page<UserSummary>>(`/users?page=${userPage}`) : Promise.resolve(undefined)),
    [isAdmin, userPage],
  );
  const invites = useLoad(
    () => (isAdmin ? get<Page<Invite>>(`/invites?page=${invitePage}`) : Promise.resolve(undefined)),
    [isAdmin, invitePage],
  );
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({ role: "editor" as PersonRole, expires_in_hours: 72 });
  const [link, setLink] = useState<string | null>(null);
  const change = useConfirm<PendingChange>();
  const revokeConfirm = useConfirm<Invite>();
  const inviteAction = useAction();
  const action = useAction();

  const invite = async (e: FormEvent) => {
    e.preventDefault();
    const result = await inviteAction.run(() => post<{ token: string; invite: Invite }>("/invites", form));
    if (result) {
      setLink(`${window.location.origin}${window.location.pathname}#/invite/${result.token}`);
      invites.reload();
    }
  };

  const closeInvite = (o: boolean) => {
    setOpen(o);
    if (!o) {
      setLink(null);
      inviteAction.clearError();
    }
  };

  const apply = async (p: PendingChange) => {
    await action.run(() => patch<UserSummary>(`/users/${p.user.id}`, p.change));
    change.close();
    users.reload();
  };

  const revoke = async (i: Invite) => {
    await action.run(() => del(`/invites/${i.id}`));
    revokeConfirm.close();
    invites.reload();
  };

  const inviteButton = (
    <Button
      type="button"
      onClick={() => setOpen(true)}
      disabled={!isAdmin}
      title={isAdmin ? undefined : "Only admins can invite people"}
    >
      <UserPlus />
      Invite someone
    </Button>
  );

  return (
    <PageContainer>
      <PageHeader
        title="People"
        description="Everyone who can sign in to this console, and the invites waiting to be accepted."
        actions={inviteButton}
      />
      {!isAdmin ? (
        <Alert>
          <ShieldCheck className="size-4" />
          <AlertTitle>Only admins can manage people</AlertTitle>
          <AlertDescription>
            You are signed in as <strong>{me.username}</strong> with the <strong>{me.role}</strong> role. Ask an admin
            if you need more access.
          </AlertDescription>
        </Alert>
      ) : (
        <>
          <ErrorBanner error={users.error ?? invites.error ?? action.error} />
          <Section title="Accounts">
            <Panel>
              {users.loading && !users.data ? (
                <Loading />
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Username</TableHead>
                      <TableHead>Role</TableHead>
                      <TableHead>Sign-in</TableHead>
                      <TableHead>Since</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {users.data?.items.map((u) => (
                      <TableRow key={u.id}>
                        <TableCell className="font-medium">
                          {u.username}
                          {u.id === me.id && <span className="ml-1 font-normal text-muted-foreground">(you)</span>}
                        </TableCell>
                        <TableCell className="w-40">
                          <SelectField
                            value={u.role}
                            onChange={(role) =>
                              change.ask({
                                user: u,
                                change: { role: role as Role },
                                title: `Make ${u.username} ${role}?`,
                                description:
                                  PERSON_ROLES.find((r) => r.value === role)?.description ?? "Their access changes immediately.",
                                confirmLabel: `Make ${role}`,
                                destructive: false,
                              })
                            }
                            options={PERSON_ROLES.map((r) => ({ value: r.value, label: r.value }))}
                            className="h-9"
                          />
                        </TableCell>
                        <TableCell>
                          {u.totp_enrolled ? (
                            <Status tone="success">password + authenticator</Status>
                          ) : (
                            <Status tone="warning">password only</Status>
                          )}
                        </TableCell>
                        <TableCell className="text-muted-foreground">
                          <When at={u.created_at} />
                        </TableCell>
                        <TableCell>
                          {u.disabled_at ? <Status tone="destructive">disabled</Status> : <Status tone="success">active</Status>}
                        </TableCell>
                        <TableCell>
                          <RowActions>
                            {u.disabled_at ? (
                              <Button
                                type="button"
                                variant="outline"
                                size="sm"
                                onClick={() =>
                                  change.ask({
                                    user: u,
                                    change: { disabled: false },
                                    title: `Re-enable ${u.username}?`,
                                    description: "They can sign in again with their existing password.",
                                    confirmLabel: "Enable",
                                    destructive: false,
                                  })
                                }
                              >
                                Enable
                              </Button>
                            ) : (
                              u.id !== me.id && (
                                <Button
                                  type="button"
                                  variant="outline"
                                  size="sm"
                                  onClick={() =>
                                    change.ask({
                                      user: u,
                                      change: { disabled: true },
                                      title: `Disable ${u.username}?`,
                                      description: "They are signed out immediately and cannot sign in until re-enabled.",
                                      confirmLabel: "Disable",
                                      destructive: true,
                                    })
                                  }
                                >
                                  Disable
                                </Button>
                              )
                            )}
                          </RowActions>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
              <Pager page={users.data} onPage={setUserPage} />
            </Panel>
          </Section>
          <Section title="Invites">
            <Panel>
              {invites.loading && !invites.data ? (
                <Loading />
              ) : invites.data?.items.length === 0 ? (
                <Empty
                  icon={Mail}
                  title="No invites yet"
                  description="Invite someone with a role. They choose their own username and password from the link."
                  action={inviteButton}
                />
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Role</TableHead>
                      <TableHead>Created by</TableHead>
                      <TableHead>Expires</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {invites.data?.items.map((i) => {
                      const status = inviteStatus(i);
                      return (
                        <TableRow key={i.id}>
                          <TableCell className="font-medium">{i.role}</TableCell>
                          <TableCell>
                            <Mono>{i.created_by}</Mono>
                          </TableCell>
                          <TableCell className="text-muted-foreground">
                            <When at={i.expires_at} />
                          </TableCell>
                          <TableCell>
                            <Status tone={status.tone}>{status.label}</Status>
                          </TableCell>
                          <TableCell>
                            <RowActions>
                              {status.label === "pending" && (
                                <Button type="button" variant="outline" size="sm" onClick={() => revokeConfirm.ask(i)}>
                                  Revoke
                                </Button>
                              )}
                            </RowActions>
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              )}
              <Pager page={invites.data} onPage={setInvitePage} />
            </Panel>
          </Section>
        </>
      )}
      <FormDialog
        open={open}
        onOpenChange={closeInvite}
        wide
        title={link ? "Invite link created" : "Invite someone"}
        description={
          link
            ? undefined
            : "Send the link to the person you are inviting. They choose a username and password, and can add an authenticator. The link works once."
        }
      >
        {link ? (
          <div className="space-y-4">
            <OneTimeSecret
              label="Invite link"
              value={link}
              hint="Anyone holding it can create the account until it is accepted, revoked or expires."
            />
            <DialogActions>
              <Button type="button" onClick={() => closeInvite(false)}>
                Done
              </Button>
            </DialogActions>
          </div>
        ) : (
          <form className="space-y-4" onSubmit={invite}>
            <ErrorBanner error={inviteAction.error} />
            <div className="space-y-2">
              <p className="text-sm font-medium">Role</p>
              <ChoiceCards
                name="invite-role"
                value={form.role}
                onChange={(role) => setForm({ ...form, role })}
                choices={PERSON_ROLES}
              />
            </div>
            <Field label="Link expires in (hours)" htmlFor="invite-hours" hint="At most 168 (7 days).">
              <Input
                id="invite-hours"
                type="number"
                min={1}
                max={168}
                className="md:w-40"
                value={form.expires_in_hours}
                onChange={(e) => setForm({ ...form, expires_in_hours: Number(e.target.value) })}
              />
            </Field>
            <DialogActions>
              <Button type="button" variant="outline" onClick={() => closeInvite(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={inviteAction.busy}>
                Create invite link
              </Button>
            </DialogActions>
          </form>
        )}
      </FormDialog>
      <ConfirmDialog
        open={change.open}
        onOpenChange={change.onOpenChange}
        title={change.target?.title ?? ""}
        description={change.target?.description ?? ""}
        confirmLabel={change.target?.confirmLabel ?? "Confirm"}
        destructive={change.target?.destructive ?? true}
        busy={action.busy}
        onConfirm={() => {
          if (change.target) void apply(change.target);
        }}
      />
      <ConfirmDialog
        open={revokeConfirm.open}
        onOpenChange={revokeConfirm.onOpenChange}
        title={`Revoke the pending ${revokeConfirm.target?.role ?? ""} invite?`}
        description="The link stops working immediately."
        confirmLabel="Revoke invite"
        busy={action.busy}
        onConfirm={() => {
          if (revokeConfirm.target) void revoke(revokeConfirm.target);
        }}
      />
    </PageContainer>
  );
}
