// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { useMemo, useState, type FormEvent } from "react";
import { ChevronLeft, FlaskConical, KeyRound, ListChecks, Plus, RefreshCw, ShieldAlert, Timer, Trash2 } from "lucide-react";
import {
  del,
  get,
  patch,
  post,
  put,
  type CredentialMeta,
  type CredentialValidation,
  type Page,
  type ProxySession,
  type Rule,
  type StoredTemplate,
  type UserSummary,
  type Vault,
} from "../api";
import { useAction, useLoad } from "../hooks";
import {
  CheckField,
  ConfirmDialog,
  DialogActions,
  Empty,
  ErrorBanner,
  Field,
  FormDialog,
  lines,
  Loading,
  Mono,
  OneTimeSecret,
  Pager,
  Panel,
  RowActions,
  Section,
  SelectField,
  Status,
  Tags,
  useConfirm,
  When,
} from "../components/common";
import { Alert, AlertDescription, AlertTitle } from "../components/ui/alert";
import { Button } from "../components/ui/button-components";
import { Input } from "../components/ui/input";
import { PageContainer, PageHeader } from "../components/ui/page-header";
import { Skeleton } from "../components/ui/skeleton";
import { Switch } from "../components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../components/ui/table";
import { Tabs, TabsList, TabsTrigger } from "../components/ui/tabs";
import { Textarea } from "../components/ui/textarea";

type Tab = "credentials" | "rules" | "sessions";
const TABS: { value: Tab; label: string }[] = [
  { value: "credentials", label: "Credentials" },
  { value: "rules", label: "Rules" },
  { value: "sessions", label: "Sessions" },
];

export function VaultDetail({ vaultId, tab, user }: { vaultId: string; tab: Tab; user: UserSummary }) {
  const vault = useLoad(() => get<Vault>(`/vaults/${vaultId}`), [vaultId]);
  return (
    <PageContainer>
      <div className="space-y-2">
        <a
          href="#/vaults"
          className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
        >
          <ChevronLeft className="size-4" />
          Vaults
        </a>
        <PageHeader
          title={vault.data ? vault.data.name : <Skeleton className="h-8 w-48" />}
          description={vault.data ? <Mono>{vault.data.scope}</Mono> : undefined}
        />
      </div>
      <ErrorBanner error={vault.error} />
      <Tabs
        value={tab}
        onValueChange={(v) => {
          window.location.hash = `#/vaults/${vaultId}/${v}`;
        }}
      >
        <TabsList>
          {TABS.map((t) => (
            <TabsTrigger key={t.value} value={t.value}>
              {t.label}
            </TabsTrigger>
          ))}
        </TabsList>
      </Tabs>
      {tab === "credentials" && <Credentials vaultId={vaultId} user={user} />}
      {tab === "rules" && <Rules vaultId={vaultId} />}
      {tab === "sessions" && <Sessions vaultId={vaultId} />}
    </PageContainer>
  );
}

// ----- credentials -----------------------------------------------------------

function Credentials({ vaultId, user }: { vaultId: string; user: UserSummary }) {
  const [page, setPage] = useState(1);
  const creds = useLoad(() => get<Page<CredentialMeta>>(`/vaults/${vaultId}/credentials?page=${page}`), [vaultId, page]);
  const templates = useLoad(() => get<StoredTemplate[]>("/templates"), []);
  const approved = useMemo(() => (templates.data ?? []).filter((t) => t.status === "approved"), [templates.data]);
  const [adding, setAdding] = useState(false);
  const [rotating, setRotating] = useState<CredentialMeta | null>(null);
  const [results, setResults] = useState<Record<string, CredentialValidation>>({});
  const confirm = useConfirm<CredentialMeta>();
  const action = useAction();
  const hasValidation = (c: CredentialMeta) =>
    approved.some((t) => t.template.id === c.template_id && t.template.version === c.template_version && t.template.validation);

  const test = async (c: CredentialMeta) => {
    const r = await action.run(() => post<CredentialValidation>(`/credentials/${c.id}/validate`));
    if (r) setResults({ ...results, [c.id]: r });
  };

  const remove = async (c: CredentialMeta) => {
    await action.run(() => del(`/credentials/${c.id}`));
    confirm.close();
    creds.reload();
  };

  const addButton = (
    <Button type="button" onClick={() => setAdding(true)}>
      <Plus />
      Add credential
    </Button>
  );

  const failures = Object.values(results).filter((r) => !r.ok);

  return (
    <Section
      title="Credentials"
      description="Secrets are write-only: once saved, nobody (admins included) can read them back. They are only ever delivered, encrypted, to enrolled data plane nodes."
      actions={addButton}
    >
      <ErrorBanner error={creds.error ?? action.error} />
      {failures.map((r) => (
        <Alert key={r.credential_id} variant="warning">
          <FlaskConical className="size-4" />
          <AlertTitle>
            Test of {r.method} {r.path} on {r.host} failed
          </AlertTitle>
          <AlertDescription>
            {r.detail}
            {r.detail.includes("Settings") && (
              <>
                {" "}
                <a href="#/settings" className="font-medium underline underline-offset-4">
                  Open Settings
                </a>
              </>
            )}
          </AlertDescription>
        </Alert>
      ))}
      <Panel>
        {creds.loading && !creds.data ? (
          <Loading />
        ) : creds.data?.items.length === 0 ? (
          <Empty
            icon={KeyRound}
            title="No credentials in this vault"
            description="Add a credential from a service template, for example a GitHub token or a Stripe secret key."
            action={addButton}
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Template</TableHead>
                <TableHead>Fields</TableHead>
                <TableHead>Host override</TableHead>
                <TableHead>Updated</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {creds.data?.items.map((c) => {
                const result = results[c.id];
                return (
                  <TableRow key={c.id}>
                    <TableCell className="font-medium">{c.name}</TableCell>
                    <TableCell>
                      <Mono>
                        {c.template_id}@{c.template_version}
                      </Mono>
                    </TableCell>
                    <TableCell>
                      <Tags values={c.field_names.map((f) => `${f}: ••••••`)} />
                    </TableCell>
                    <TableCell>
                      {c.host_override.length ? (
                        <Tags values={c.host_override} />
                      ) : (
                        <span className="text-muted-foreground">template hosts</span>
                      )}
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      <When at={c.updated_at} />
                    </TableCell>
                    <TableCell>
                      <RowActions>
                        {result && (
                          <span title={result.detail}>
                            <Status tone={result.ok ? "success" : "destructive"}>
                              {result.ok ? "works" : `failed${result.status ? ` (${result.status})` : ""}`}
                            </Status>
                          </span>
                        )}
                        <Button
                          type="button"
                          variant="outline"
                          size="sm"
                          disabled={!hasValidation(c) || action.busy}
                          title={
                            hasValidation(c)
                              ? "Send the template's validation request with this credential"
                              : "This template declares no validation request"
                          }
                          onClick={() => void test(c)}
                        >
                          <FlaskConical />
                          <span className="hidden sm:inline">Test</span>
                        </Button>
                        <Button type="button" variant="outline" size="sm" onClick={() => setRotating(c)}>
                          <RefreshCw />
                          <span className="hidden sm:inline">Replace secret</span>
                        </Button>
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          className="text-destructive hover:text-destructive"
                          aria-label={`Delete ${c.name}`}
                          onClick={() => confirm.ask(c)}
                        >
                          <Trash2 />
                        </Button>
                      </RowActions>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        )}
        <Pager page={creds.data} onPage={setPage} />
      </Panel>
      <FormDialog
        open={adding}
        onOpenChange={setAdding}
        wide
        title="Add a credential"
        description="Choose the service it belongs to. The template sets the hosts, paths and methods it may ever be used for."
      >
        <CredentialForm
          templates={approved}
          templatesLoading={templates.loading && !templates.data}
          isAdmin={user.role === "admin"}
          onSubmit={(body) => post<CredentialMeta>(`/vaults/${vaultId}/credentials`, body)}
          onCancel={() => setAdding(false)}
          onSaved={() => {
            setAdding(false);
            creds.reload();
          }}
        />
      </FormDialog>
      <FormDialog
        open={rotating !== null}
        onOpenChange={(o) => {
          if (!o) setRotating(null);
        }}
        title={rotating ? `Replace secret for "${rotating.name}"` : "Replace secret"}
        description="The new value takes effect on the data plane at its next policy refresh. The old value cannot be recovered."
      >
        {rotating && (
          <RotateForm
            credential={rotating}
            template={approved.find((t) => t.template.id === rotating.template_id)}
            onCancel={() => setRotating(null)}
            onDone={() => {
              setRotating(null);
              creds.reload();
            }}
          />
        )}
      </FormDialog>
      <ConfirmDialog
        open={confirm.open}
        onOpenChange={confirm.onOpenChange}
        title={`Delete credential "${confirm.target?.name ?? ""}"?`}
        description="The secret is destroyed. Rules that use this credential must be deleted first."
        confirmLabel="Delete credential"
        busy={action.busy}
        onConfirm={() => {
          if (confirm.target) void remove(confirm.target);
        }}
      />
    </Section>
  );
}

interface CredentialBody {
  name: string;
  template_id: string;
  template_version: number;
  host_override: string[];
  fields: Record<string, string>;
}

function CredentialForm({
  templates,
  templatesLoading,
  isAdmin,
  onSubmit,
  onCancel,
  onSaved,
}: {
  templates: StoredTemplate[];
  templatesLoading: boolean;
  isAdmin: boolean;
  onSubmit: (body: CredentialBody) => Promise<CredentialMeta>;
  onCancel: () => void;
  onSaved: () => void;
}) {
  const [templateKey, setTemplateKey] = useState("");
  const [name, setName] = useState("");
  const [hostOverride, setHostOverride] = useState("");
  const [fields, setFields] = useState<Record<string, string>>({});
  const action = useAction();
  const selected = templates.find((t) => `${t.template.id}@${t.template.version}` === templateKey)?.template;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!selected) return;
    const saved = await action.run(() =>
      onSubmit({
        name,
        template_id: selected.id,
        template_version: selected.version,
        host_override: lines(hostOverride),
        fields,
      }),
    );
    // Clear secret values from memory as soon as they are saved.
    setFields({});
    if (saved) {
      setName("");
      setHostOverride("");
      onSaved();
    }
  };

  return (
    <form className="space-y-4" onSubmit={submit} autoComplete="off">
      <ErrorBanner error={action.error} />
      <Field
        label="Service template"
        htmlFor="cred-template"
        hint={
          templates.length === 0 && !templatesLoading ? (
            <>
              No approved templates. <a href="#/templates" className="underline">Review templates</a>.
            </>
          ) : undefined
        }
      >
        <SelectField
          id="cred-template"
          value={templateKey}
          onChange={setTemplateKey}
          placeholder={templatesLoading ? "Loading templates…" : "Choose a service…"}
          options={templates.map((t) => ({
            value: `${t.template.id}@${t.template.version}`,
            label: `${t.template.name} (v${t.template.version})`,
          }))}
        />
      </Field>
      {selected && (
        <>
          <div className="space-y-2 rounded-md border bg-muted/40 p-3 text-sm">
            <p className="text-muted-foreground">{selected.description}</p>
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs font-medium text-muted-foreground">Hosts</span>
              {selected.hosts.length ? <Tags values={selected.hosts} /> : <span className="text-xs">chosen below</span>}
            </div>
          </div>
          <Field label="Name" htmlFor="cred-name">
            <Input id="cred-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="ci-bot token" required />
          </Field>
          {selected.credential_fields.map((f) => (
            <Field
              key={f.name}
              htmlFor={`cred-field-${f.name}`}
              label={
                <>
                  {f.label}
                  {!f.required && <span className="font-normal text-muted-foreground"> (optional)</span>}
                </>
              }
              hint={f.description || undefined}
            >
              <Input
                id={`cred-field-${f.name}`}
                type="password"
                autoComplete="new-password"
                spellCheck={false}
                className="font-mono"
                value={fields[f.name] ?? ""}
                onChange={(e) => setFields({ ...fields, [f.name]: e.target.value })}
                required={f.required}
              />
            </Field>
          ))}
          {selected.host_override.allowed && (
            <div className="space-y-3 rounded-md border border-dashed p-4">
              <div className="flex items-center gap-2 text-sm font-medium">
                <ShieldAlert className="size-4 text-warning-strong" />
                Admin only: host override {selected.host_override.required ? "(required)" : "(optional)"}
              </div>
              <p className="text-xs text-muted-foreground">
                Replaces the template's hosts (for example a self-hosted base URL). This widens the template's scope,
                so it needs an admin and is recorded in the audit log.
              </p>
              <Field label={selected.host_override.label ?? "Base URL"} htmlFor="cred-host">
                <Input
                  id="cred-host"
                  placeholder="https://api.internal.example:8443"
                  value={hostOverride}
                  onChange={(e) => setHostOverride(e.target.value)}
                  disabled={!isAdmin}
                  required={selected.host_override.required && isAdmin}
                />
              </Field>
              {!isAdmin && <p className="text-xs text-muted-foreground">Ask an admin to create this credential.</p>}
            </div>
          )}
        </>
      )}
      <DialogActions>
        <Button type="button" variant="outline" onClick={onCancel}>
          Cancel
        </Button>
        <Button type="submit" disabled={!selected || action.busy || (selected.host_override.required && !isAdmin)}>
          Save credential
        </Button>
      </DialogActions>
    </form>
  );
}

function RotateForm({
  credential,
  template,
  onCancel,
  onDone,
}: {
  credential: CredentialMeta;
  template: StoredTemplate | undefined;
  onCancel: () => void;
  onDone: () => void;
}) {
  const [fields, setFields] = useState<Record<string, string>>({});
  const action = useAction();
  const names =
    template?.template.credential_fields ??
    credential.field_names.map((n) => ({ name: n, label: n, required: true, description: "" }));
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const ok = await action.run(() => put<CredentialMeta>(`/credentials/${credential.id}/secret`, { fields }));
    setFields({});
    if (ok) onDone();
  };
  return (
    <form className="space-y-4" onSubmit={submit} autoComplete="off">
      <ErrorBanner error={action.error} />
      {names.map((f) => (
        <Field key={f.name} label={`New ${f.label}`} htmlFor={`rotate-${f.name}`}>
          <Input
            id={`rotate-${f.name}`}
            type="password"
            autoComplete="new-password"
            className="font-mono"
            value={fields[f.name] ?? ""}
            onChange={(e) => setFields({ ...fields, [f.name]: e.target.value })}
            required={f.required}
          />
        </Field>
      ))}
      <DialogActions>
        <Button type="button" variant="outline" onClick={onCancel}>
          Cancel
        </Button>
        <Button type="submit" disabled={action.busy}>
          Replace secret
        </Button>
      </DialogActions>
    </form>
  );
}

// ----- rules ---------------------------------------------------------------

const EMPTY_RULE = { name: "", credential_id: "", hosts: "", paths: "", methods: "" };

function Rules({ vaultId }: { vaultId: string }) {
  const [page, setPage] = useState(1);
  const rules = useLoad(() => get<Page<Rule>>(`/vaults/${vaultId}/rules?page=${page}`), [vaultId, page]);
  const creds = useLoad(() => get<Page<CredentialMeta>>(`/vaults/${vaultId}/credentials?page_size=100`), [vaultId]);
  const [adding, setAdding] = useState(false);
  const [form, setForm] = useState(EMPTY_RULE);
  const confirm = useConfirm<Rule>();
  const action = useAction();
  const createAction = useAction();
  const credName = (id: string) => creds.data?.items.find((c) => c.id === id)?.name ?? id;

  const create = async (e: FormEvent) => {
    e.preventDefault();
    const opt = (v: string) => (lines(v).length ? lines(v) : undefined);
    const created = await createAction.run(() =>
      post<Rule>(`/vaults/${vaultId}/rules`, {
        name: form.name,
        credential_id: form.credential_id,
        hosts: opt(form.hosts),
        paths: opt(form.paths),
        methods: opt(form.methods),
      }),
    );
    if (created) {
      setForm(EMPTY_RULE);
      setAdding(false);
      rules.reload();
    }
  };

  const toggle = async (r: Rule) => {
    await action.run(() => patch<Rule>(`/rules/${r.id}`, { enabled: !r.enabled }));
    rules.reload();
  };

  const remove = async (r: Rule) => {
    await action.run(() => del(`/rules/${r.id}`));
    confirm.close();
    rules.reload();
  };

  const addButton = (
    <Button type="button" onClick={() => setAdding(true)}>
      <Plus />
      Add rule
    </Button>
  );

  return (
    <Section
      title="Rules"
      description="A rule lets a credential be injected for matching requests. Without a rule, a credential is never used."
      actions={addButton}
    >
      <ErrorBanner error={rules.error ?? action.error} />
      <Panel>
        {rules.loading && !rules.data ? (
          <Loading />
        ) : rules.data?.items.length === 0 ? (
          <Empty
            icon={ListChecks}
            title="No rules yet"
            description="Add a rule to allow a credential for some or all of its template's hosts, paths and methods."
            action={addButton}
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Credential</TableHead>
                <TableHead>Hosts</TableHead>
                <TableHead>Paths</TableHead>
                <TableHead>Methods</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rules.data?.items.map((r) => (
                <TableRow key={r.id}>
                  <TableCell className="font-medium">{r.name}</TableCell>
                  <TableCell>{credName(r.credential_id)}</TableCell>
                  <TableCell>
                    <Tags values={r.allow.hosts} />
                  </TableCell>
                  <TableCell>
                    <Tags values={r.allow.paths} />
                  </TableCell>
                  <TableCell>
                    <Tags values={r.allow.methods} />
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <Switch
                        checked={r.enabled}
                        disabled={action.busy}
                        onCheckedChange={() => void toggle(r)}
                        aria-label={`${r.enabled ? "Disable" : "Enable"} ${r.name}`}
                      />
                      <Status tone={r.enabled ? "success" : "neutral"}>{r.enabled ? "enabled" : "disabled"}</Status>
                    </div>
                  </TableCell>
                  <TableCell>
                    <RowActions>
                      <Button
                        type="button"
                        variant="ghost"
                        size="sm"
                        className="text-destructive hover:text-destructive"
                        aria-label={`Delete ${r.name}`}
                        onClick={() => confirm.ask(r)}
                      >
                        <Trash2 />
                      </Button>
                    </RowActions>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
        <Pager page={rules.data} onPage={setPage} />
      </Panel>
      <FormDialog
        open={adding}
        onOpenChange={setAdding}
        wide
        title="Add a rule"
        description="Leave hosts, paths and methods empty to use the template's maximum scope; anything you enter can only narrow it."
      >
        <form className="space-y-4" onSubmit={create}>
          <ErrorBanner error={createAction.error} />
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <Field label="Name" htmlFor="rule-name">
              <Input id="rule-name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
            </Field>
            <Field
              label="Credential"
              htmlFor="rule-cred"
              hint={creds.data?.items.length === 0 ? "Add a credential to this vault first." : undefined}
            >
              <SelectField
                id="rule-cred"
                value={form.credential_id}
                onChange={(v) => setForm({ ...form, credential_id: v })}
                placeholder="Choose…"
                options={(creds.data?.items ?? []).map((c) => ({ value: c.id, label: `${c.name} (${c.template_id})` }))}
              />
            </Field>
          </div>
          <Field label="Hosts" htmlFor="rule-hosts" hint="Optional, one per line.">
            <Textarea
              id="rule-hosts"
              rows={2}
              className="font-mono"
              value={form.hosts}
              onChange={(e) => setForm({ ...form, hosts: e.target.value })}
              placeholder="api.example.com"
            />
          </Field>
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <Field label="Paths" htmlFor="rule-paths" hint="Optional, one per line.">
              <Textarea
                id="rule-paths"
                rows={2}
                className="font-mono"
                value={form.paths}
                onChange={(e) => setForm({ ...form, paths: e.target.value })}
                placeholder="/v1/*"
              />
            </Field>
            <Field label="Methods" htmlFor="rule-methods" hint="Optional, comma separated.">
              <Input
                id="rule-methods"
                className="font-mono"
                value={form.methods}
                onChange={(e) => setForm({ ...form, methods: e.target.value })}
                placeholder="GET, POST"
              />
            </Field>
          </div>
          <DialogActions>
            <Button type="button" variant="outline" onClick={() => setAdding(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={createAction.busy || !form.credential_id}>
              Create rule
            </Button>
          </DialogActions>
        </form>
      </FormDialog>
      <ConfirmDialog
        open={confirm.open}
        onOpenChange={confirm.onOpenChange}
        title={`Delete rule "${confirm.target?.name ?? ""}"?`}
        description="Sessions that include this rule can no longer use it."
        confirmLabel="Delete rule"
        busy={action.busy}
        onConfirm={() => {
          if (confirm.target) void remove(confirm.target);
        }}
      />
    </Section>
  );
}

// ----- sessions ------------------------------------------------------------

interface Minted {
  token: string;
  session: ProxySession;
}

function sessionStatus(s: ProxySession) {
  if (s.revoked_at) return <Status tone="destructive">revoked</Status>;
  if (new Date(s.expires_at) <= new Date()) return <Status tone="neutral">expired</Status>;
  return <Status tone="success">active</Status>;
}

function Sessions({ vaultId }: { vaultId: string }) {
  const [page, setPage] = useState(1);
  const sessions = useLoad(() => get<Page<ProxySession>>(`/vaults/${vaultId}/sessions?page=${page}`), [vaultId, page]);
  const rules = useLoad(() => get<Page<Rule>>(`/vaults/${vaultId}/rules?page_size=100`), [vaultId]);
  const [open, setOpen] = useState(false);
  const [selected, setSelected] = useState<string[]>([]);
  const [ttlMinutes, setTtlMinutes] = useState(15);
  const [limit, setLimit] = useState("");
  const [labels, setLabels] = useState("");
  const [minted, setMinted] = useState<Minted | null>(null);
  const confirm = useConfirm<ProxySession>();
  const action = useAction();
  const mintAction = useAction();
  const enabledRules = (rules.data?.items ?? []).filter((r) => r.enabled);

  const mint = async (e: FormEvent) => {
    e.preventDefault();
    const labelMap: Record<string, string> = {};
    for (const line of lines(labels)) {
      const [k, ...rest] = line.split("=");
      if (k) labelMap[k.trim()] = rest.join("=").trim();
    }
    const result = await mintAction.run(() =>
      post<Minted>(`/vaults/${vaultId}/sessions`, {
        rule_ids: selected,
        ttl_secs: ttlMinutes * 60,
        request_limit: limit ? Number(limit) : undefined,
        labels: labelMap,
      }),
    );
    if (result) {
      setMinted(result);
      sessions.reload();
    }
  };

  const closeMint = (o: boolean) => {
    setOpen(o);
    if (!o) {
      setMinted(null);
      mintAction.clearError();
    }
  };

  const revoke = async (s: ProxySession) => {
    await action.run(() => post<ProxySession>(`/sessions/${s.id}/revoke`));
    confirm.close();
    sessions.reload();
  };

  const mintButton = (
    <Button type="button" onClick={() => setOpen(true)}>
      <Plus />
      Mint session
    </Button>
  );

  return (
    <Section
      title="Proxy sessions"
      description="A session lets an agent use selected rules through the data plane for a limited time. The agent never sees the credentials."
      actions={mintButton}
    >
      <ErrorBanner error={sessions.error ?? action.error} />
      <Panel>
        {sessions.loading && !sessions.data ? (
          <Loading />
        ) : sessions.data?.items.length === 0 ? (
          <Empty
            icon={Timer}
            title="No sessions yet"
            description="Mint a short-lived session and hand its token to an agent as its HTTPS proxy."
            action={mintButton}
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Session</TableHead>
                <TableHead>Labels</TableHead>
                <TableHead>Limit</TableHead>
                <TableHead>Created by</TableHead>
                <TableHead>Expires</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {sessions.data?.items.map((s) => (
                <TableRow key={s.id}>
                  <TableCell>
                    <Mono>{s.id.slice(0, 8)}</Mono>
                  </TableCell>
                  <TableCell>
                    <Tags values={Object.entries(s.labels).map(([k, v]) => `${k}=${v}`)} />
                  </TableCell>
                  <TableCell className="tabular-nums">{s.request_limit ?? "—"}</TableCell>
                  <TableCell>
                    <Mono>{s.created_by}</Mono>
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    <When at={s.expires_at} />
                  </TableCell>
                  <TableCell>{sessionStatus(s)}</TableCell>
                  <TableCell>
                    <RowActions>
                      {!s.revoked_at && (
                        <Button type="button" variant="outline" size="sm" onClick={() => confirm.ask(s)}>
                          Revoke
                        </Button>
                      )}
                    </RowActions>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
        <Pager page={sessions.data} onPage={setPage} />
      </Panel>
      <FormDialog
        open={open}
        onOpenChange={closeMint}
        wide
        title={minted ? "Session minted" : "Mint a proxy session"}
        description={minted ? undefined : "Choose the rules the agent may use and how long the session lives."}
      >
        {minted ? (
          <div className="space-y-4">
            <OneTimeSecret
              label="Proxy session token"
              value={minted.token}
              hint={
                <div className="space-y-2">
                  <p>Point the agent at the data plane:</p>
                  <code className="block break-all rounded-md border bg-background px-3 py-2 font-mono text-xs">
                    HTTPS_PROXY=http://{minted.token.slice(0, 18)}…@&lt;data-plane-host&gt;:3128
                  </code>
                  <p>
                    and trust the{" "}
                    <a href="/api/v1/ca/interception.pem" className="font-medium underline underline-offset-4">
                      interception CA certificate
                    </a>
                    .
                  </p>
                </div>
              }
            />
            <DialogActions>
              <Button type="button" onClick={() => closeMint(false)}>
                Done
              </Button>
            </DialogActions>
          </div>
        ) : (
          <form className="space-y-4" onSubmit={mint}>
            <ErrorBanner error={mintAction.error} />
            <div className="space-y-3">
              <p className="text-sm font-medium">Rules</p>
              {rules.loading && !rules.data ? (
                <Skeleton className="h-6 w-full" />
              ) : enabledRules.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  No enabled rules in this vault.{" "}
                  <a href={`#/vaults/${vaultId}/rules`} className="underline" onClick={() => closeMint(false)}>
                    Add a rule
                  </a>{" "}
                  first.
                </p>
              ) : (
                <div className="space-y-3 rounded-md border p-3">
                  {enabledRules.map((r) => (
                    <CheckField
                      key={r.id}
                      id={`mint-rule-${r.id}`}
                      checked={selected.includes(r.id)}
                      onChange={(checked) =>
                        setSelected(checked ? [...selected, r.id] : selected.filter((id) => id !== r.id))
                      }
                      hint={<Tags values={r.allow.hosts} />}
                    >
                      {r.name}
                    </CheckField>
                  ))}
                </div>
              )}
            </div>
            <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
              <Field label="Lifetime (minutes)" htmlFor="mint-ttl" hint="At most 60.">
                <Input
                  id="mint-ttl"
                  type="number"
                  min={1}
                  max={60}
                  value={ttlMinutes}
                  onChange={(e) => setTtlMinutes(Number(e.target.value))}
                />
              </Field>
              <Field label="Request limit" htmlFor="mint-limit" hint="Optional.">
                <Input id="mint-limit" type="number" min={1} value={limit} onChange={(e) => setLimit(e.target.value)} />
              </Field>
            </div>
            <Field label="Audit labels" htmlFor="mint-labels" hint="key=value, one per line. Recorded with every request.">
              <Textarea
                id="mint-labels"
                rows={2}
                className="font-mono"
                value={labels}
                onChange={(e) => setLabels(e.target.value)}
                placeholder="agent=build-bot"
              />
            </Field>
            <DialogActions>
              <Button type="button" variant="outline" onClick={() => closeMint(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={mintAction.busy || selected.length === 0}>
                Mint session
              </Button>
            </DialogActions>
          </form>
        )}
      </FormDialog>
      <ConfirmDialog
        open={confirm.open}
        onOpenChange={confirm.onOpenChange}
        title="Revoke this session?"
        description="The agent holding its token is refused on its next request."
        confirmLabel="Revoke session"
        busy={action.busy}
        onConfirm={() => {
          if (confirm.target) void revoke(confirm.target);
        }}
      />
    </Section>
  );
}
