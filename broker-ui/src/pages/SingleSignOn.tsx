// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Single sign-on with OpenID Connect: the identity providers people sign in
// with, which of their groups get which role, and who may still use a
// password. The provider form is a page of its own.

import { useState, type FormEvent } from "react";
import { KeyRound, Pencil, Plus, Power, PowerOff, Trash2, X } from "lucide-react";
import {
  del,
  get,
  post,
  put,
  type OidcProvider,
  type PasswordSignIn,
  type Role,
  type SignInSettings,
} from "../api";
import { useBreadcrumbs } from "../breadcrumbs";
import { useAction, useLoad } from "../hooks";
import {
  CheckField,
  ChoiceCards,
  ConfirmDialog,
  CopyButton,
  Empty,
  ErrorBanner,
  Field,
  fromWidth,
  Loading,
  Mono,
  Panel,
  rowLink,
  RowMenu,
  SelectField,
  Status,
  useConfirm,
} from "../components/common";
import { SettingsSection } from "../components/layout";
import { Button } from "../components/ui/button-components";
import { Input } from "../components/ui/input";
import { PageContainer, PageHeader } from "../components/ui/page-header";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../components/ui/table";
import {
  newProviderForm,
  providerForm,
  providerFormProblem,
  providerInput,
  slugFromName,
  type ProviderForm,
} from "../sso";

const NEW_HREF = "#/settings/sso/new";
const providerHref = (id: string) => `#/settings/sso/${id}`;

const ROLES: { value: Role; label: string }[] = [
  { value: "viewer", label: "Viewer" },
  { value: "editor", label: "Editor" },
  { value: "admin", label: "Admin" },
];

function host(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

/** The Settings sections for single sign-on. */
export function SingleSignOnSettings() {
  const providers = useLoad(() => get<OidcProvider[]>("/identity-providers"), []);
  const signIn = useLoad(() => get<SignInSettings>("/auth/sign-in-settings"), []);
  const action = useAction();
  const remove = useConfirm<OidcProvider>();
  const list = providers.data;
  const anyEnabled = list?.some((p) => p.enabled) ?? false;

  const setEnabled = async (p: OidcProvider, enabled: boolean) => {
    const done = await action.run(() => put<OidcProvider>(`/identity-providers/${p.id}`, { ...providerInput(providerForm(p)), enabled }));
    if (done) providers.reload();
  };
  const confirmDelete = async () => {
    const p = remove.target;
    if (!p) return;
    const done = await action.run(async () => {
      await del(`/identity-providers/${p.id}`);
      return true;
    });
    remove.close();
    if (done) providers.reload();
  };
  const setPasswordSignIn = async (password_sign_in: PasswordSignIn) => {
    const done = await action.run(() => put<SignInSettings>("/auth/sign-in-settings", { password_sign_in }));
    if (done) signIn.reload();
  };

  const addButton = (
    <Button asChild variant="outline" size="sm">
      <a href={NEW_HREF}>
        <Plus />
        Add a provider
      </a>
    </Button>
  );

  return (
    <>
      <SettingsSection title="Single sign-on" hint="OpenID Connect. Groups from the provider decide each person's role.">
        <ErrorBanner error={providers.error ?? action.error} />
        <Panel>
          {!list ? (
            <Loading rows={2} />
          ) : list.length === 0 ? (
            <Empty
              icon={KeyRound}
              title="No identity provider"
              description="People sign in with a username and password. Add a provider such as Okta, Entra ID or Keycloak so they sign in with it instead, with a role from their groups."
              action={addButton}
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Provider</TableHead>
                  <TableHead className={fromWidth.xl}>Issuer</TableHead>
                  <TableHead className={fromWidth.md}>Status</TableHead>
                  <TableHead className="w-10">
                    <span className="sr-only">Actions</span>
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {list.map((p) => (
                  <TableRow key={p.id} {...rowLink(providerHref(p.id))}>
                    <TableCell>
                      <div className="font-medium">{p.name}</div>
                      <div className="text-xs text-muted-foreground">
                        {p.role_mappings.length === 1 ? "1 group mapped" : `${p.role_mappings.length} groups mapped`}
                      </div>
                    </TableCell>
                    <TableCell className={fromWidth.xl}>
                      <Mono>{host(p.issuer)}</Mono>
                    </TableCell>
                    <TableCell className={fromWidth.md}>
                      <Status tone={p.enabled ? "success" : "neutral"}>{p.enabled ? "On" : "Off"}</Status>
                    </TableCell>
                    <TableCell className="text-right">
                      <RowMenu
                        label={p.name}
                        items={[
                          { label: "Edit", icon: Pencil, onSelect: () => (window.location.hash = providerHref(p.id)) },
                          p.enabled
                            ? { label: "Turn off", icon: PowerOff, onSelect: () => void setEnabled(p, false) }
                            : { label: "Turn on", icon: Power, onSelect: () => void setEnabled(p, true) },
                          { label: "Delete", icon: Trash2, onSelect: () => remove.ask(p), destructive: true },
                        ]}
                      />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </Panel>
        {list && list.length > 0 && addButton}
      </SettingsSection>
      <SettingsSection title="Password sign-in" hint="Who may still sign in with a username and password.">
        <ErrorBanner error={signIn.error} />
        {signIn.data && (
          <>
            <ChoiceCards<PasswordSignIn>
              name="password-sign-in"
              value={signIn.data.password_sign_in}
              onChange={(v) => void setPasswordSignIn(v)}
              choices={[
                {
                  value: "everyone",
                  title: "Everyone with a local account",
                  description: "People invited here sign in with their password, alongside single sign-on.",
                },
                {
                  value: "admins_only",
                  title: "Local admins only",
                  description:
                    "Everyone else signs in with single sign-on. Local admins keep a password to get in when the provider is down.",
                },
              ]}
            />
            {!anyEnabled && signIn.data.password_sign_in === "everyone" && (
              <p className="text-xs text-muted-foreground">Limiting passwords to admins needs a provider that is on.</p>
            )}
          </>
        )}
      </SettingsSection>
      <ConfirmDialog
        open={remove.open}
        onOpenChange={remove.onOpenChange}
        title={`Delete ${remove.target?.name ?? "the provider"}?`}
        description="Its sign-in button goes away. A provider people have signed in with cannot be deleted: turn it off instead, which signs them out."
        confirmLabel="Delete provider"
        busy={action.busy}
        onConfirm={() => void confirmDelete()}
      />
    </>
  );
}

/** Adding (`providerId` absent) or editing an identity provider. */
export function ProviderFormPage({ providerId }: { providerId?: string }) {
  const provider = useLoad(
    () => (providerId ? get<OidcProvider>(`/identity-providers/${providerId}`) : Promise.resolve(undefined)),
    [providerId],
  );
  const p = provider.data;
  useBreadcrumbs([
    { label: "Settings", href: "#/settings" },
    { label: providerId ? (p?.name ?? null) : "Add an identity provider" },
  ]);
  const leave = () => {
    window.location.hash = "#/settings";
  };

  return (
    <PageContainer width="form">
      <PageHeader title={providerId ? (p ? `Edit ${p.name}` : "Edit provider") : "Add an identity provider"} />
      <ErrorBanner error={provider.error} />
      {providerId && !p ? (
        provider.loading && (
          <Panel>
            <Loading />
          </Panel>
        )
      ) : (
        <ProviderFormBody key={p?.id ?? "new"} provider={p ?? null} onDone={leave} />
      )}
    </PageContainer>
  );
}

function ProviderFormBody({ provider, onDone }: { provider: OidcProvider | null; onDone: () => void }) {
  const [form, setForm] = useState<ProviderForm>(() =>
    provider ? providerForm(provider) : newProviderForm(window.location.origin),
  );
  const [slugEdited, setSlugEdited] = useState(provider !== null);
  const action = useAction();
  const problem = providerFormProblem(form);
  const set = (patch: Partial<ProviderForm>) => setForm((f) => ({ ...f, ...patch }));
  const setMapping = (i: number, patch: Partial<ProviderForm["role_mappings"][number]>) =>
    set({ role_mappings: form.role_mappings.map((m, j) => (j === i ? { ...m, ...patch } : m)) });

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (problem) return;
    const body = providerInput(form);
    const saved = await action.run(() =>
      provider ? put<OidcProvider>(`/identity-providers/${provider.id}`, body) : post<OidcProvider>("/identity-providers", body),
    );
    if (saved) onDone();
  };

  return (
    <form className="space-y-6" onSubmit={submit}>
      <ErrorBanner error={action.error} />
      <fieldset className="space-y-4">
        <legend className="mb-2 text-sm font-semibold">Provider</legend>
        <Field label="Name" htmlFor="sso-name" hint="On the sign-in button: Continue with …">
          <Input
            id="sso-name"
            value={form.name}
            onChange={(e) => set({ name: e.target.value, ...(slugEdited ? {} : { slug: slugFromName(e.target.value) }) })}
            placeholder="Company login"
            required
          />
        </Field>
        <Field label="Slug" htmlFor="sso-slug" hint={<>In the sign-in URL: /api/v1/auth/oidc/{form.slug || "…"}/start</>}>
          <Input
            id="sso-slug"
            className="font-mono"
            value={form.slug}
            onChange={(e) => {
              setSlugEdited(true);
              set({ slug: e.target.value });
            }}
            placeholder="company"
            required
          />
        </Field>
        <Field label="Issuer URL" htmlFor="sso-issuer" hint="Its discovery document is read from /.well-known/openid-configuration.">
          <Input
            id="sso-issuer"
            type="url"
            className="font-mono"
            value={form.issuer}
            onChange={(e) => set({ issuer: e.target.value })}
            placeholder="https://login.example.com/realms/main"
            required
          />
        </Field>
      </fieldset>

      <fieldset className="space-y-4 border-t pt-6">
        <legend className="mb-2 text-sm font-semibold">Client registered at the provider</legend>
        <Field label="Redirect URI" htmlFor="sso-redirect" hint="Register exactly this at the provider.">
          <div className="flex items-center gap-2">
            <Input
              id="sso-redirect"
              type="url"
              className="font-mono"
              value={form.redirect_uri}
              onChange={(e) => set({ redirect_uri: e.target.value })}
              required
            />
            <CopyButton value={form.redirect_uri} iconOnly label="Copy redirect URI" />
          </div>
        </Field>
        <Field label="Client ID" htmlFor="sso-client-id">
          <Input
            id="sso-client-id"
            className="font-mono"
            value={form.client_id}
            onChange={(e) => set({ client_id: e.target.value })}
            autoComplete="off"
            required
          />
        </Field>
        <Field
          label="Client secret"
          htmlFor="sso-client-secret"
          hint={
            provider?.has_client_secret
              ? "A secret is stored and never shown. Leave this empty to keep it."
              : "Leave empty for a public client, which uses PKCE alone."
          }
        >
          <Input
            id="sso-client-secret"
            type="password"
            value={form.client_secret}
            onChange={(e) => set({ client_secret: e.target.value })}
            autoComplete="new-password"
            placeholder={provider?.has_client_secret ? "••••••••  (stored)" : undefined}
            disabled={form.clear_client_secret}
          />
        </Field>
        {provider?.has_client_secret && (
          <CheckField
            id="sso-clear-secret"
            checked={form.clear_client_secret}
            onChange={(v) => set({ clear_client_secret: v, client_secret: "" })}
          >
            Remove the stored secret
          </CheckField>
        )}
      </fieldset>

      <fieldset className="space-y-4 border-t pt-6">
        <legend className="mb-2 text-sm font-semibold">Roles from groups</legend>
        <Field label="Groups claim" htmlFor="sso-groups-claim" hint="Where the groups are, in the ID token or user info. A dotted path reaches nested claims.">
          <Input
            id="sso-groups-claim"
            className="font-mono"
            value={form.groups_claim}
            onChange={(e) => set({ groups_claim: e.target.value })}
            required
          />
        </Field>
        <div className="space-y-2">
          <p className="text-sm font-medium">Group → role</p>
          <p className="text-xs text-muted-foreground">
            Someone in several groups gets the highest role. Someone in none is refused, and the refusal names their groups.
          </p>
          <div className="space-y-2">
            {form.role_mappings.map((m, i) => (
              <div key={i} className="flex items-center gap-2">
                <Input
                  aria-label={`Group ${i + 1}`}
                  className="min-w-0 flex-1 font-mono"
                  value={m.group}
                  onChange={(e) => setMapping(i, { group: e.target.value })}
                  placeholder="tokenless-admins"
                />
                <SelectField
                  id={`sso-role-${i}`}
                  className="w-32 shrink-0"
                  value={m.role}
                  onChange={(v) => setMapping(i, { role: v as Role })}
                  options={ROLES}
                />
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="size-8 shrink-0"
                  aria-label={`Remove group ${i + 1}`}
                  disabled={form.role_mappings.length === 1}
                  onClick={() => set({ role_mappings: form.role_mappings.filter((_, j) => j !== i) })}
                >
                  <X />
                </Button>
              </div>
            ))}
          </div>
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => set({ role_mappings: [...form.role_mappings, { group: "", role: "viewer" }] })}
          >
            <Plus />
            Add a group
          </Button>
        </div>
      </fieldset>

      <fieldset className="space-y-4 border-t pt-6">
        <legend className="mb-2 text-sm font-semibold">Accounts</legend>
        <Field
          label="Username claim"
          htmlFor="sso-username-claim"
          hint="An account is created at the first sign-in with this as its username. A local account with the same name is never taken over."
        >
          <Input
            id="sso-username-claim"
            className="font-mono"
            value={form.username_claim}
            onChange={(e) => set({ username_claim: e.target.value })}
            required
          />
        </Field>
        <Field label="Extra scopes" htmlFor="sso-scopes" hint="Besides openid. Some providers send groups only for a scope of their own.">
          <Input id="sso-scopes" className="font-mono" value={form.scopes} onChange={(e) => set({ scopes: e.target.value })} />
        </Field>
        <CheckField
          id="sso-enabled"
          checked={form.enabled}
          onChange={(v) => set({ enabled: v })}
          hint="Off hides the button and signs out everyone who signed in with it."
        >
          On
        </CheckField>
      </fieldset>

      <div className="flex items-center justify-end gap-2 border-t pt-4">
        {problem && <p className="mr-auto text-xs text-muted-foreground">{problem}</p>}
        <Button type="button" variant="outline" onClick={onDone}>
          Cancel
        </Button>
        <Button type="submit" disabled={action.busy || problem !== null}>
          {provider ? "Save provider" : "Add provider"}
        </Button>
      </div>
    </form>
  );
}
