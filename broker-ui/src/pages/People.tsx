// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { useMemo, useState, type FormEvent, type ReactNode } from "react";
import { LogOut, Mail, ShieldCheck, UserPlus } from "lucide-react";
import {
  del,
  get,
  patch,
  post,
  type InstanceRole,
  type Invite,
  type OidcProvider,
  type Page,
  type SignInsRevoked,
  type UserSummary,
  type Vault,
  type VaultGrant,
} from "../api";
import type { Me } from "../access";
import { roleLabel } from "../members";
import { VaultGrants } from "../components/VaultGrants";
import { revokedMessage } from "../signIns";
import { actorName } from "../audit";
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
  OneTimeSecret,
  Pager,
  Panel,
  RowActions,
  RowMenu,
  Section,
  SelectField,
  Status,
  useConfirm,
  When,
  type Choice,
  type Tone,
} from "../components/common";
import { cn } from "../lib/utils";
import { Alert, AlertDescription, AlertTitle } from "../components/ui/alert";
import { Button } from "../components/ui/button-components";
import { Input } from "../components/ui/input";
import { PageContainer, PageHeader } from "../components/ui/page-header";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../components/ui/table";

const PERSON_ROLES: Choice<InstanceRole>[] = [
  {
    value: "member",
    title: "Member",
    description: "Works in the vaults they are given a role in, and nothing else",
  },
  {
    value: "admin",
    title: "Instance admin",
    description:
      "Runs the instance: people, templates, proxies, settings. Sees every vault's sessions and audit log, and joins a vault to change it",
  },
];

function inviteStatus(i: Invite): { label: string; tone: Tone } {
  if (i.accepted_at) return { label: "accepted", tone: "success" };
  if (i.revoked_at) return { label: "revoked", tone: "destructive" };
  if (new Date(i.expires_at) <= new Date()) return { label: "expired", tone: "neutral" };
  return { label: "pending", tone: "warning" };
}

interface PendingChange {
  user: UserSummary;
  change: { role?: InstanceRole; disabled?: boolean };
  title: string;
  description: ReactNode;
  confirmLabel: string;
  destructive: boolean;
}

function instanceRoleLabel(role: InstanceRole): string {
  return role === "admin" ? "Instance admin" : "Member";
}

/** People: invite with a role, change roles, disable accounts. */
export function People({ me }: { me: Me }) {
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
  const providers = useLoad(
    () => (isAdmin ? get<OidcProvider[]>("/identity-providers") : Promise.resolve(undefined)),
    [isAdmin],
  );
  const vaults = useLoad(() => (isAdmin ? get<Page<Vault>>("/vaults?page_size=100") : Promise.resolve(undefined)), [isAdmin]);
  const vaultName = (id: string) => vaults.data?.items.find((v) => v.id === id)?.name ?? id.slice(0, 8);
  const vaultOptions = (vaults.data?.items ?? []).map((v) => ({ value: v.id, label: v.name }));
  const providerName = (id: string) => providers.data?.find((p) => p.id === id)?.name ?? "single sign-on";
  const names = useMemo(
    () => ({ meId: me.id, users: new Map(users.data?.items.map((u) => [u.id, u.username])) }),
    [me.id, users.data],
  );
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({ role: "member" as InstanceRole, vaults: [] as VaultGrant[], expires_in_hours: 72 });
  const [link, setLink] = useState<string | null>(null);
  const change = useConfirm<PendingChange>();
  const revokeConfirm = useConfirm<Invite>();
  const signOutConfirm = useConfirm<UserSummary>();
  const [signedOut, setSignedOut] = useState<string | null>(null);
  const inviteAction = useAction();
  const action = useAction();

  const invite = async (e: FormEvent) => {
    e.preventDefault();
    const body = { ...form, vaults: form.vaults.filter((g) => g.vault_id !== "") };
    const result = await inviteAction.run(() => post<{ token: string; invite: Invite }>("/invites", body));
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

  const signOut = async (u: UserSummary) => {
    const result = await action.run(() => post<SignInsRevoked>(`/users/${u.id}/sign-ins/revoke`));
    signOutConfirm.close();
    if (result) setSignedOut(revokedMessage(result.revoked, u.username));
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
      title={isAdmin ? undefined : "Only instance admins can invite people"}
    >
      <UserPlus />
      Invite someone
    </Button>
  );

  return (
    <PageContainer width="settings">
      <PageHeader
        title="People"
        actions={inviteButton}
      />
      {!isAdmin ? (
        <Alert>
          <ShieldCheck className="size-4" />
          <AlertTitle>Only instance admins manage people</AlertTitle>
          <AlertDescription>
            You are signed in as <strong>{me.username}</strong>, a member
            {me.vaults.length === 0
              ? " of no vault yet. Ask a vault's admin to add you."
              : ` of ${me.vaults.length === 1 ? "1 vault" : `${me.vaults.length} vaults`}. A vault's admins add people to it from its Members tab.`}
          </AlertDescription>
        </Alert>
      ) : (
        <>
          <ErrorBanner error={users.error ?? invites.error ?? action.error} />
          {signedOut && (
            <p className="text-sm text-muted-foreground" role="status">
              {signedOut}
            </p>
          )}
          <Section title="Accounts">
            <Panel>
              {users.loading && !users.data ? (
                <Loading />
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Username</TableHead>
                      <TableHead className={fromWidth["2xl"]}>Role</TableHead>
                      <TableHead className={fromWidth["3xl"]}>Sign-in</TableHead>
                      <TableHead className={fromWidth["4xl"]}>Since</TableHead>
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
                          <div className="text-xs font-normal text-muted-foreground @2xl:hidden">{instanceRoleLabel(u.role)}</div>
                        </TableCell>
                        <TableCell className={cn(fromWidth["2xl"], "w-40")}>
                          {u.sso_provider_id ? (
                            <span title={`Set by their groups at ${providerName(u.sso_provider_id)} at each sign-in`}>
                              {instanceRoleLabel(u.role)}
                            </span>
                          ) : (
                            <SelectField
                              value={u.role}
                              onChange={(role) =>
                                change.ask({
                                  user: u,
                                  change: { role: role as InstanceRole },
                                  title: `Make ${u.username} ${instanceRoleLabel(role as InstanceRole).toLowerCase()}?`,
                                  description:
                                    role === "admin"
                                      ? "They run the instance and oversee every vault; they still join a vault before changing it."
                                      : "They keep their roles in the vaults they are a member of, and lose the rest of the instance.",
                                  confirmLabel: `Make ${instanceRoleLabel(role as InstanceRole).toLowerCase()}`,
                                  destructive: false,
                                })
                              }
                              options={PERSON_ROLES.map((r) => ({ value: r.value, label: r.title }))}
                              className="h-9"
                            />
                          )}
                        </TableCell>
                        <TableCell className={fromWidth["3xl"]}>
                          {u.sso_provider_id ? (
                            <Status tone="success">{providerName(u.sso_provider_id)}</Status>
                          ) : u.totp_enrolled ? (
                            <Status tone="success">password + authenticator</Status>
                          ) : (
                            <Status tone="warning">password only</Status>
                          )}
                        </TableCell>
                        <TableCell className={cn(fromWidth["4xl"], "text-muted-foreground")}>
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
                                    description: u.sso_provider_id ? "They can sign in again with single sign-on." : "They can sign in again with their existing password.",
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
                            {!u.disabled_at && u.id !== me.id && (
                              <RowMenu
                                label={u.username}
                                items={[
                                  {
                                    label: "Sign out everywhere",
                                    icon: LogOut,
                                    destructive: true,
                                    onSelect: () => signOutConfirm.ask(u),
                                  },
                                ]}
                              />
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
                      <TableHead className={fromWidth.md}>Vaults</TableHead>
                      <TableHead className={fromWidth.xl}>Created by</TableHead>
                      <TableHead className={fromWidth.lg}>Expires</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {invites.data?.items.map((i) => {
                      const status = inviteStatus(i);
                      return (
                        <TableRow key={i.id}>
                          <TableCell className="font-medium">{instanceRoleLabel(i.role)}</TableCell>
                          <TableCell className={cn(fromWidth.md, "text-muted-foreground")}>
                            {(i.vaults ?? []).length === 0
                              ? "none"
                              : (i.vaults ?? []).map((g) => `${vaultName(g.vault_id)} (${roleLabel(g.role).toLowerCase()})`).join(", ")}
                          </TableCell>
                          <TableCell className={fromWidth.xl}>
                            {actorName(i.created_by, names)}
                          </TableCell>
                          <TableCell className={cn(fromWidth.lg, "text-muted-foreground")}>
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
            <div className="space-y-2">
              <p className="text-sm font-medium">Vaults</p>
              <VaultGrants
                group={0}
                grants={form.vaults}
                vaults={vaultOptions}
                onChange={(vaults) => setForm({ ...form, vaults })}
                empty="None yet: they join with no access, and a vault's admins add them later."
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
        open={signOutConfirm.open}
        onOpenChange={signOutConfirm.onOpenChange}
        title={`Sign ${signOutConfirm.target?.username ?? "them"} out everywhere?`}
        description="Every browser and CLI login of theirs ends at once; they can sign in again. Agent sessions they already started keep running until they expire: end those from Sessions."
        confirmLabel="Sign out everywhere"
        destructive
        busy={action.busy}
        onConfirm={() => {
          if (signOutConfirm.target) void signOut(signOutConfirm.target);
        }}
      />
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
        title="Revoke the pending invite?"
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
