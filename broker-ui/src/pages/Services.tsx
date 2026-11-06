// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// A vault's services: credentials created from a template, each with its
// secret fields (a value or a variable reference) and custom headers.

import { useMemo, useState, type FormEvent } from "react";
import { Braces, FlaskConical, KeyRound, ListPlus, Lock, Plus, RefreshCw, ShieldAlert, Trash2 } from "lucide-react";
import {
  ApiError,
  del,
  get,
  post,
  put,
  type CredentialField,
  type CredentialMeta,
  type CredentialValidation,
  type CustomHeader,
  type Page,
  type ServiceTemplate,
  type StoredTemplate,
  type UserSummary,
  type Variable,
} from "../api";
import { KIND_LABEL, targetHosts } from "../catalog";
import { useAction, useLoad } from "../hooks";
import {
  ConfirmDialog,
  DialogActions,
  Empty,
  ErrorBanner,
  Field,
  FormDialog,
  lines,
  Loading,
  Mono,
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
import { ServiceLogo } from "../components/ServiceLogo";
import { TemplatePicker } from "../components/TemplatePicker";
import { CustomHeadersEditor, referencedKeys } from "../components/VariableInput";
import { Alert, AlertDescription, AlertTitle } from "../components/ui/alert";
import { Button } from "../components/ui/button-components";
import { Input } from "../components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../components/ui/table";

/** Variable keys the caller may reference; empty (not an error) for non-admins. */
function useVariableKeys(enabled: boolean) {
  return useLoad(async () => {
    if (!enabled) return [] as string[];
    try {
      const page = await get<Page<Variable>>("/variables?page_size=100");
      return page.items.map((v) => v.key);
    } catch (e) {
      if (e instanceof ApiError && e.problem.status === 403) return [] as string[];
      throw e;
    }
  }, [enabled]);
}

function templateOf(templates: StoredTemplate[], c: CredentialMeta): ServiceTemplate | undefined {
  return templates.find((t) => t.template.id === c.template_id && t.template.version === c.template_version)?.template;
}

/** The headers the credential itself injects, lower-cased. */
function injectedHeaders(t: ServiceTemplate | undefined): string[] {
  if (!t) return [];
  return t.injection.method === "header" ? [t.injection.name.toLowerCase()] : ["authorization"];
}

export function Services({ vaultId, user }: { vaultId: string; user: UserSummary }) {
  const isAdmin = user.role === "admin";
  const [page, setPage] = useState(1);
  const creds = useLoad(() => get<Page<CredentialMeta>>(`/vaults/${vaultId}/credentials?page=${page}`), [vaultId, page]);
  const templates = useLoad(() => get<StoredTemplate[]>("/templates"), []);
  const variables = useVariableKeys(isAdmin);
  const all = useMemo(() => templates.data ?? [], [templates.data]);
  const [picking, setPicking] = useState(false);
  const [creating, setCreating] = useState<ServiceTemplate | null>(null);
  const [rotating, setRotating] = useState<CredentialMeta | null>(null);
  const [editingHeaders, setEditingHeaders] = useState<CredentialMeta | null>(null);
  const [results, setResults] = useState<Record<string, CredentialValidation>>({});
  const confirm = useConfirm<CredentialMeta>();
  const action = useAction();

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
    <Button
      type="button"
      onClick={() => setPicking(true)}
      disabled={!isAdmin}
      title={isAdmin ? undefined : "Only admins can add services"}
    >
      <Plus />
      Add service
    </Button>
  );

  const failures = Object.values(results).filter((r) => !r.ok);

  return (
    <Section
      title="Services"
      description="Each service holds the credential for one API. Secrets are write-only: once saved, nobody (admins included) can read them back. They are only ever delivered, encrypted, to enrolled proxies."
      actions={addButton}
    >
      <ErrorBanner error={creds.error ?? templates.error ?? variables.error ?? action.error} />
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
            title="No services in this vault"
            description="Add a service from the catalogue, for example a GitHub token or an OpenAI key. Agents never see the secret; the proxy adds it to their requests."
            action={addButton}
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Service</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Target</TableHead>
                <TableHead>Secret</TableHead>
                <TableHead>Updated</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {creds.data?.items.map((c) => {
                const tpl = templateOf(all, c);
                const result = results[c.id];
                return (
                  <TableRow key={c.id}>
                    <TableCell>
                      <div className="flex min-w-48 items-center gap-3">
                        <ServiceLogo template={tpl ?? { id: c.template_id, kind: "http" }} size="sm" />
                        <div className="min-w-0">
                          <div className="truncate font-medium">{c.name}</div>
                          <div className="truncate text-xs text-muted-foreground">
                            {tpl?.name ?? c.template_id} · v{c.template_version}
                          </div>
                        </div>
                      </div>
                    </TableCell>
                    <TableCell className="text-muted-foreground">{KIND_LABEL[tpl?.kind ?? "http"]}</TableCell>
                    <TableCell>
                      <Tags values={targetHosts(tpl, c.host_override)} />
                    </TableCell>
                    <TableCell>
                      <SecretSummary credential={c} />
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
                          disabled={!tpl?.validation || action.busy || !isAdmin}
                          title={
                            tpl?.validation
                              ? "Send the template's validation request with this credential"
                              : "This template declares no validation request"
                          }
                          onClick={() => void test(c)}
                        >
                          <FlaskConical />
                          <span className="hidden sm:inline">Test</span>
                        </Button>
                        <Button
                          type="button"
                          variant="outline"
                          size="sm"
                          disabled={!isAdmin}
                          onClick={() => setEditingHeaders(c)}
                        >
                          <ListPlus />
                          <span className="hidden sm:inline">Headers</span>
                        </Button>
                        <Button
                          type="button"
                          variant="outline"
                          size="sm"
                          disabled={!isAdmin}
                          onClick={() => setRotating(c)}
                        >
                          <RefreshCw />
                          <span className="hidden sm:inline">Replace secret</span>
                        </Button>
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          className="text-destructive hover:text-destructive"
                          aria-label={`Delete ${c.name}`}
                          disabled={!isAdmin}
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
      <TemplatePicker
        open={picking}
        onOpenChange={setPicking}
        templates={all}
        loading={templates.loading && !templates.data}
        onPick={(t) => {
          setPicking(false);
          setCreating(t.template);
        }}
      />
      <FormDialog
        open={creating !== null}
        onOpenChange={(o) => {
          if (!o) setCreating(null);
        }}
        wide
        title={creating ? `Add ${creating.name}` : "Add service"}
        description="The template sets the hosts, paths and methods this credential may ever be used for."
      >
        {creating && (
          <ServiceForm
            template={creating}
            variables={variables.data ?? []}
            isAdmin={isAdmin}
            onBack={() => {
              setCreating(null);
              setPicking(true);
            }}
            onSubmit={(body) => post<CredentialMeta>(`/vaults/${vaultId}/credentials`, body)}
            onSaved={() => {
              setCreating(null);
              creds.reload();
            }}
          />
        )}
      </FormDialog>
      <FormDialog
        open={rotating !== null}
        onOpenChange={(o) => {
          if (!o) setRotating(null);
        }}
        title={rotating ? `Replace secret for "${rotating.name}"` : "Replace secret"}
        description="The new value takes effect on the proxies at their next policy refresh. The old value cannot be recovered."
      >
        {rotating && (
          <RotateForm
            credential={rotating}
            template={templateOf(all, rotating)}
            variables={variables.data ?? []}
            onCancel={() => setRotating(null)}
            onDone={() => {
              setRotating(null);
              creds.reload();
            }}
          />
        )}
      </FormDialog>
      <FormDialog
        open={editingHeaders !== null}
        onOpenChange={(o) => {
          if (!o) setEditingHeaders(null);
        }}
        wide
        title={editingHeaders ? `Headers for "${editingHeaders.name}"` : "Custom headers"}
        description="Sent with every request this credential is injected into. Reference a variable with {{NAME}} to keep a value secret."
      >
        {editingHeaders && (
          <HeadersForm
            credential={editingHeaders}
            template={templateOf(all, editingHeaders)}
            variables={variables.data ?? []}
            onCancel={() => setEditingHeaders(null)}
            onDone={() => {
              setEditingHeaders(null);
              creds.reload();
            }}
          />
        )}
      </FormDialog>
      <ConfirmDialog
        open={confirm.open}
        onOpenChange={confirm.onOpenChange}
        title={`Delete service "${confirm.target?.name ?? ""}"?`}
        description="The secret is destroyed. Rules that use this service must be deleted first."
        confirmLabel="Delete service"
        busy={action.busy}
        onConfirm={() => {
          if (confirm.target) void remove(confirm.target);
        }}
      />
    </Section>
  );
}

function SecretSummary({ credential }: { credential: CredentialMeta }) {
  const refs = credential.variable_refs;
  const headers = credential.custom_headers.length;
  return (
    <div className="flex flex-wrap items-center gap-1.5 text-xs">
      {refs.length > 0 ? (
        refs.map((k) => (
          <span key={k} className="inline-flex items-center gap-1 rounded border bg-muted/40 px-1.5 py-0.5 font-mono">
            <Braces className="size-3 text-muted-foreground" />
            {k}
          </span>
        ))
      ) : (
        <span className="inline-flex items-center gap-1 text-muted-foreground">
          <Lock className="size-3" />
          stored value
        </span>
      )}
      {headers > 0 && (
        <span className="text-muted-foreground">
          · {headers} header{headers === 1 ? "" : "s"}
        </span>
      )}
    </div>
  );
}

// ----- forms -----------------------------------------------------------------

type SecretMode = "value" | "variable";

const EMPTY_SECRET: SecretInput = { mode: "value", value: "", variable: "" };

interface SecretInput {
  mode: SecretMode;
  value: string;
  variable: string;
}

function initialSecrets(
  fields: CredentialField[],
  variables: string[],
  suggested: string | null | undefined,
): Record<string, SecretInput> {
  const out: Record<string, SecretInput> = {};
  fields.forEach((f, i) => {
    const preferred = i === 0 && suggested && variables.includes(suggested) ? suggested : "";
    out[f.name] = { mode: preferred ? "variable" : "value", value: "", variable: preferred };
  });
  return out;
}

/** Values sent to the API: the typed secret, or a `{{KEY}}` reference. */
function secretValues(secrets: Record<string, SecretInput>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, s] of Object.entries(secrets)) {
    const v = s.mode === "variable" ? (s.variable ? `{{${s.variable}}}` : "") : s.value;
    if (v) out[name] = v;
  }
  return out;
}

function SecretFieldInput({
  field,
  input,
  onChange,
  variables,
  suggested,
  labelPrefix = "",
}: {
  field: CredentialField;
  input: SecretInput;
  onChange: (input: SecretInput) => void;
  variables: string[];
  suggested?: string | null;
  labelPrefix?: string;
}) {
  const id = `secret-${field.name}`;
  return (
    <Field
      htmlFor={id}
      label={
        <>
          {labelPrefix}
          {field.label}
          {!field.required && <span className="font-normal text-muted-foreground"> (optional)</span>}
        </>
      }
      hint={
        input.mode === "variable" && variables.length === 0 ? (
          <>
            No variables yet.{" "}
            <a href="#/variables" className="underline underline-offset-4">
              Create {suggested ? <Mono>{suggested}</Mono> : "one"} under Variables
            </a>{" "}
            to share a secret between services.
          </>
        ) : (
          field.description || undefined
        )
      }
    >
      <div className="flex flex-col gap-2 sm:flex-row">
        <div className="flex shrink-0 rounded-md border p-0.5" role="radiogroup" aria-label={`${field.label} source`}>
          {(["value", "variable"] as const).map((m) => (
            <button
              key={m}
              type="button"
              role="radio"
              aria-checked={input.mode === m}
              onClick={() => onChange({ ...input, mode: m })}
              className={`h-8 rounded-sm px-2.5 text-xs transition-colors ${
                input.mode === m ? "bg-accent font-medium text-foreground" : "text-muted-foreground hover:text-foreground"
              }`}
            >
              {m === "value" ? "Secret value" : "Variable"}
            </button>
          ))}
        </div>
        <div className="min-w-0 flex-1">
          {input.mode === "value" ? (
            <Input
              id={id}
              type="password"
              autoComplete="new-password"
              spellCheck={false}
              className="font-mono"
              value={input.value}
              onChange={(e) => onChange({ ...input, value: e.target.value })}
              required={field.required}
            />
          ) : (
            <SelectField
              id={id}
              value={input.variable}
              onChange={(variable) => onChange({ ...input, variable })}
              placeholder={variables.length ? "Choose a variable…" : "No variables"}
              options={variables.map((k) => ({ value: k, label: `{{${k}}}` }))}
            />
          )}
        </div>
      </div>
    </Field>
  );
}

interface CredentialBody {
  name: string;
  template_id: string;
  template_version: number;
  host_override: string[];
  fields: Record<string, string>;
  custom_headers: CustomHeader[];
}

function ServiceForm({
  template,
  variables,
  isAdmin,
  onBack,
  onSubmit,
  onSaved,
}: {
  template: ServiceTemplate;
  variables: string[];
  isAdmin: boolean;
  onBack: () => void;
  onSubmit: (body: CredentialBody) => Promise<CredentialMeta>;
  onSaved: () => void;
}) {
  const [name, setName] = useState(template.name);
  const [hostOverride, setHostOverride] = useState("");
  const [secrets, setSecrets] = useState(() =>
    initialSecrets(template.credential_fields, variables, template.suggested_variable),
  );
  const [headers, setHeaders] = useState<CustomHeader[]>(() => template.default_headers ?? []);
  const action = useAction();
  const missingVariable = Object.values(secrets).some((s) => s.mode === "variable" && !s.variable);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const saved = await action.run(() =>
      onSubmit({
        name,
        template_id: template.id,
        template_version: template.version,
        host_override: lines(hostOverride),
        fields: secretValues(secrets),
        custom_headers: headers,
      }),
    );
    if (saved) {
      // Clear typed secrets from memory as soon as they are stored.
      setSecrets(initialSecrets(template.credential_fields, [], null));
      onSaved();
    }
  };

  return (
    <form className="space-y-5" onSubmit={submit} autoComplete="off">
      <ErrorBanner error={action.error} />
      <div className="flex items-start gap-3 rounded-md border bg-muted/40 p-3">
        <ServiceLogo template={template} />
        <div className="min-w-0 flex-1 space-y-1.5 text-sm">
          <p className="text-muted-foreground">{template.description}</p>
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs font-medium text-muted-foreground">Hosts</span>
            {template.hosts.length ? <Tags values={template.hosts} /> : <span className="text-xs">chosen below</span>}
          </div>
        </div>
        <Button type="button" variant="ghost" size="sm" onClick={onBack}>
          Change
        </Button>
      </div>
      <Field label="Name" htmlFor="svc-name" hint="How this service appears in rules and sessions.">
        <Input id="svc-name" value={name} onChange={(e) => setName(e.target.value)} required />
      </Field>
      {template.credential_fields.map((f) => (
        <SecretFieldInput
          key={f.name}
          field={f}
          input={secrets[f.name] ?? EMPTY_SECRET}
          onChange={(input) => setSecrets({ ...secrets, [f.name]: input })}
          variables={variables}
          suggested={template.suggested_variable}
        />
      ))}
      <div className="space-y-2">
        <div>
          <div className="text-sm font-medium">Custom headers</div>
          <p className="text-xs text-muted-foreground">
            Added to every request, for example an API version. Type <Mono>{"{{"}</Mono> to reference a variable.
          </p>
        </div>
        <CustomHeadersEditor
          headers={headers}
          onChange={setHeaders}
          variables={variables}
          reserved={injectedHeaders(template)}
        />
      </div>
      {template.host_override.allowed && (
        <div className="space-y-3 rounded-md border border-dashed p-4">
          <div className="flex items-center gap-2 text-sm font-medium">
            <ShieldAlert className="size-4 text-warning-strong" />
            Admin only: host override {template.host_override.required ? "(required)" : "(optional)"}
          </div>
          <p className="text-xs text-muted-foreground">
            Replaces the template's hosts (for example a self-hosted base URL). This widens the template's scope, so it
            needs an admin and is recorded in the audit log.
          </p>
          <Field label={template.host_override.label ?? "Base URL"} htmlFor="svc-host">
            <Input
              id="svc-host"
              placeholder="https://api.internal.example:8443"
              value={hostOverride}
              onChange={(e) => setHostOverride(e.target.value)}
              disabled={!isAdmin}
              required={template.host_override.required && isAdmin}
            />
          </Field>
        </div>
      )}
      <DialogActions>
        <Button type="button" variant="outline" onClick={onBack}>
          Back
        </Button>
        <Button type="submit" disabled={action.busy || missingVariable || !isAdmin}>
          Save service
        </Button>
      </DialogActions>
    </form>
  );
}

function RotateForm({
  credential,
  template,
  variables,
  onCancel,
  onDone,
}: {
  credential: CredentialMeta;
  template: ServiceTemplate | undefined;
  variables: string[];
  onCancel: () => void;
  onDone: () => void;
}) {
  const fields =
    template?.credential_fields ??
    credential.field_names.map((n) => ({ name: n, label: n, required: true, description: "" }));
  const [secrets, setSecrets] = useState(() => initialSecrets(fields, [], null));
  const action = useAction();
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const ok = await action.run(() =>
      put<CredentialMeta>(`/credentials/${credential.id}/secret`, { fields: secretValues(secrets) }),
    );
    setSecrets(initialSecrets(fields, [], null));
    if (ok) onDone();
  };
  return (
    <form className="space-y-4" onSubmit={submit} autoComplete="off">
      <ErrorBanner error={action.error} />
      {fields.map((f) => (
        <SecretFieldInput
          key={f.name}
          field={f}
          input={secrets[f.name] ?? EMPTY_SECRET}
          onChange={(input) => setSecrets({ ...secrets, [f.name]: input })}
          variables={variables}
          labelPrefix="New "
        />
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

function HeadersForm({
  credential,
  template,
  variables,
  onCancel,
  onDone,
}: {
  credential: CredentialMeta;
  template: ServiceTemplate | undefined;
  variables: string[];
  onCancel: () => void;
  onDone: () => void;
}) {
  const [headers, setHeaders] = useState<CustomHeader[]>(credential.custom_headers);
  const action = useAction();
  const unknown = [...new Set(headers.flatMap((h) => referencedKeys(h.value)))].filter((k) => !variables.includes(k));
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const ok = await action.run(() =>
      put<CredentialMeta>(`/credentials/${credential.id}/headers`, { custom_headers: headers }),
    );
    if (ok) onDone();
  };
  return (
    <form className="space-y-4" onSubmit={submit} autoComplete="off">
      <ErrorBanner error={action.error} />
      <CustomHeadersEditor
        headers={headers}
        onChange={setHeaders}
        variables={variables}
        reserved={injectedHeaders(template)}
      />
      {unknown.length > 0 && (
        <p className="text-xs text-destructive">
          Unknown variable{unknown.length === 1 ? "" : "s"}: {unknown.join(", ")}.{" "}
          <a href="#/variables" className="underline underline-offset-4">
            Create {unknown.length === 1 ? "it" : "them"} under Variables
          </a>
          .
        </p>
      )}
      <DialogActions>
        <Button type="button" variant="outline" onClick={onCancel}>
          Cancel
        </Button>
        <Button type="submit" disabled={action.busy || unknown.length > 0}>
          Save headers
        </Button>
      </DialogActions>
    </form>
  );
}
