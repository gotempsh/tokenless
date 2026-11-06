// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// A vault's services: credentials created from a template, each with its
// secret fields (a value or a variable reference) and custom headers.

import { useMemo, useState, type FormEvent } from "react";
import { Braces, FlaskConical, KeyRound, ListPlus, Lock, Plus, RefreshCw, Replace, Trash2 } from "lucide-react";
import {
  del,
  get,
  post,
  put,
  type CredentialMeta,
  type CredentialValidation,
  type CustomHeader,
  type Page,
  type ServiceTemplate,
  type StoredTemplate,
  type Substitution,
  type UserSummary,
} from "../api";
import { KIND_LABEL, targetHosts } from "../catalog";
import { useAction, useLoad } from "../hooks";
import {
  fromWidth,
  ConfirmDialog,
  DialogActions,
  Empty,
  ErrorBanner,
  FormDialog,
  Loading,
  Mono,
  Pager,
  Panel,
  RowActions,
  RowMenu,
  Section,
  Status,
  Tags,
  useConfirm,
  When,
} from "../components/common";
import { cn } from "../lib/utils";
import { ServiceLogo } from "../components/ServiceLogo";
import { addServiceHref } from "../addService";
import {
  EMPTY_SECRET,
  initialSecrets,
  injectedHeaders,
  SecretFieldInput,
  secretValues,
  useVariableKeys,
} from "../components/ServiceForm";
import { SubstitutionsEditor, substitutionProblem } from "../components/SubstitutionsEditor";
import { CustomHeadersEditor, referencedKeys } from "../components/VariableInput";
import { Alert, AlertDescription, AlertTitle } from "../components/ui/alert";
import { Button } from "../components/ui/button-components";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../components/ui/table";

function templateOf(templates: StoredTemplate[], c: CredentialMeta): ServiceTemplate | undefined {
  return templates.find((t) => t.template.id === c.template_id && t.template.version === c.template_version)?.template;
}

export function Services({ vaultId, user }: { vaultId: string; user: UserSummary }) {
  const isAdmin = user.role === "admin";
  const [page, setPage] = useState(1);
  const creds = useLoad(() => get<Page<CredentialMeta>>(`/vaults/${vaultId}/credentials?page=${page}`), [vaultId, page]);
  const templates = useLoad(() => get<StoredTemplate[]>("/templates"), []);
  const variables = useVariableKeys(isAdmin);
  const all = useMemo(() => templates.data ?? [], [templates.data]);
  const [rotating, setRotating] = useState<CredentialMeta | null>(null);
  const [editingHeaders, setEditingHeaders] = useState<CredentialMeta | null>(null);
  const [editingPlaceholders, setEditingPlaceholders] = useState<CredentialMeta | null>(null);
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
      onClick={() => {
        window.location.hash = addServiceHref({ vault: vaultId, back: `vaults/${vaultId}` });
      }}
      disabled={!isAdmin}
      title={isAdmin ? undefined : "Only admins can add services"}
    >
      <Plus />
      Add service
    </Button>
  );

  const failures = Object.values(results).filter((r) => !r.ok);
  const adminOnly = "Only admins can change services";

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
                <TableHead className={fromWidth["4xl"]}>Type</TableHead>
                <TableHead className={fromWidth["2xl"]}>Target</TableHead>
                <TableHead className={fromWidth.xl}>Secret</TableHead>
                <TableHead className={fromWidth.lg}>Updated</TableHead>
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
                      <div className="flex min-w-0 items-center gap-3">
                        <ServiceLogo template={tpl ?? { id: c.template_id, kind: "http" }} size="sm" />
                        <div className="min-w-0">
                          <div className="truncate font-medium">{c.name}</div>
                          <div className="truncate text-xs text-muted-foreground">
                            {tpl?.name ?? c.template_id} · v{c.template_version}
                          </div>
                        </div>
                      </div>
                    </TableCell>
                    <TableCell className={cn(fromWidth["4xl"], "text-muted-foreground")}>{KIND_LABEL[tpl?.kind ?? "http"]}</TableCell>
                    <TableCell className={fromWidth["2xl"]}>
                      <Tags values={targetHosts(tpl, c.host_override)} />
                    </TableCell>
                    <TableCell className={fromWidth.xl}>
                      <SecretSummary credential={c} />
                    </TableCell>
                    <TableCell className={cn(fromWidth.lg, "text-muted-foreground")}>
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
                        <RowMenu
                          label={c.name}
                          items={[
                            {
                              label: "Test credential",
                              icon: FlaskConical,
                              onSelect: () => void test(c),
                              disabled: !tpl?.validation || action.busy || !isAdmin,
                              reason: !isAdmin
                                ? adminOnly
                                : tpl?.validation
                                  ? undefined
                                  : "This template declares no validation request",
                            },
                            {
                              label: "Custom headers",
                              icon: ListPlus,
                              onSelect: () => setEditingHeaders(c),
                              disabled: !isAdmin,
                              reason: adminOnly,
                            },
                            {
                              label: "Placeholders",
                              icon: Replace,
                              onSelect: () => setEditingPlaceholders(c),
                              disabled: !isAdmin,
                              reason: adminOnly,
                            },
                            {
                              label: "Replace secret",
                              icon: RefreshCw,
                              onSelect: () => setRotating(c),
                              disabled: !isAdmin,
                              reason: adminOnly,
                            },
                            {
                              label: "Delete service",
                              icon: Trash2,
                              onSelect: () => confirm.ask(c),
                              disabled: !isAdmin,
                              reason: adminOnly,
                              destructive: true,
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
        <Pager page={creds.data} onPage={setPage} />
      </Panel>
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
      <FormDialog
        open={editingPlaceholders !== null}
        onOpenChange={(o) => {
          if (!o) setEditingPlaceholders(null);
        }}
        wide
        title={editingPlaceholders ? `Placeholders for "${editingPlaceholders.name}"` : "Placeholders"}
        description="For APIs that take the key somewhere other than the injected header, or tools that refuse to start without one. The agent sends the placeholder; the proxy swaps in the secret on its way to this service's hosts, and nowhere else."
      >
        {editingPlaceholders && (
          <PlaceholdersForm
            credential={editingPlaceholders}
            onCancel={() => setEditingPlaceholders(null)}
            onDone={() => {
              setEditingPlaceholders(null);
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
  const placeholders = credential.substitutions.length;
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
      {placeholders > 0 && (
        <span className="text-muted-foreground">
          · {placeholders} placeholder{placeholders === 1 ? "" : "s"}
        </span>
      )}
    </div>
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

function PlaceholdersForm({
  credential,
  onCancel,
  onDone,
}: {
  credential: CredentialMeta;
  onCancel: () => void;
  onDone: () => void;
}) {
  const [substitutions, setSubstitutions] = useState<Substitution[]>(credential.substitutions);
  const action = useAction();
  const invalid = substitutions.some((s) => substitutionProblem(s, substitutions) !== null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const ok = await action.run(() =>
      put<CredentialMeta>(`/credentials/${credential.id}/substitutions`, { substitutions }),
    );
    if (ok) onDone();
  };
  const example = substitutions[0];
  return (
    <form className="space-y-4" onSubmit={submit} autoComplete="off">
      <ErrorBanner error={action.error} />
      <SubstitutionsEditor
        substitutions={substitutions}
        onChange={setSubstitutions}
        fields={credential.field_names}
        templateId={credential.template_id}
      />
      {example && (
        <p className="text-xs text-muted-foreground">
          For example, the agent requests <Mono>{`?api_key=${example.placeholder}`}</Mono> and the API receives the real
          value.
          {example.env && (
            <>
              {" "}
              <Mono>tokenless run</Mono> also sets <Mono>{`${example.env}=${example.placeholder}`}</Mono> for
              the agent.
            </>
          )}
        </p>
      )}
      <DialogActions>
        <Button type="button" variant="outline" onClick={onCancel}>
          Cancel
        </Button>
        <Button type="submit" disabled={action.busy || invalid}>
          Save placeholders
        </Button>
      </DialogActions>
    </form>
  );
}
