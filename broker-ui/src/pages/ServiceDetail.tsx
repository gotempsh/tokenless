// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// One service (a credential and how it is sent): what it reaches, the rules
// and bundles that let agents use it, and everything that changes it.

import { useMemo, useState, type FormEvent, type ReactNode } from "react";
import { AlertTriangle, CheckCircle2, FlaskConical, KeyRound, Pencil, RefreshCw, Trash2 } from "lucide-react";
import {
  ApiError,
  del,
  get,
  post,
  put,
  type AccessBundle,
  type CredentialMeta,
  type CredentialValidation,
  type CustomHeader,
  type Page,
  type Rule,
  type ServiceTemplate,
  type StoredTemplate,
  type Substitution,
  type UserSummary,
  type Vault,
} from "../api";
import { serviceHistoryPhrase } from "../audit";
import { useBreadcrumbs } from "../breadcrumbs";
import { KIND_LABEL, targetHosts } from "../catalog";
import { useAction, useLoad } from "../hooks";
import {
  ConfirmDialog,
  DialogActions,
  Empty,
  ErrorBanner,
  Exact,
  FormDialog,
  Mono,
  Panel,
  Relative,
  RowMenu,
  Section,
  Status,
  Tags,
  useConfirm,
} from "../components/common";
import { ServiceLogo } from "../components/ServiceLogo";
import { DetailLayout, Fact, FactList } from "../components/layout";
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
import { PageContainer, PageHeader } from "../components/ui/page-header";
import { Skeleton } from "../components/ui/skeleton";
import { useActorNames } from "./Audit";
import { RequestLog } from "./RequestLog";
import { SecretSummary, templateOf } from "./Services";

type Editing = "secret" | "headers" | "placeholders" | null;

const ADMIN_ONLY = "Only admins can change services";

export function ServiceDetail({ vaultId, credentialId, user }: { vaultId: string; credentialId: string; user: UserSummary }) {
  const isAdmin = user.role === "admin";
  // A service that does not exist (or no longer does) loads as null, not as an error.
  const cred = useLoad(
    () =>
      get<CredentialMeta>(`/credentials/${credentialId}`).catch((e: unknown) => {
        if (e instanceof ApiError && e.problem.status === 404) return null;
        throw e;
      }),
    [credentialId],
  );
  const vault = useLoad(() => get<Vault>(`/vaults/${vaultId}`), [vaultId]);
  const templates = useLoad(() => get<StoredTemplate[]>("/templates"), []);
  const rules = useLoad(() => get<Page<Rule>>(`/vaults/${vaultId}/rules?page_size=100`), [vaultId]);
  const bundles = useLoad(() => get<Page<AccessBundle>>(`/vaults/${vaultId}/bundles?page_size=100`), [vaultId]);
  const variables = useVariableKeys(isAdmin);
  const [editing, setEditing] = useState<Editing>(null);
  const [result, setResult] = useState<CredentialValidation | null>(null);
  const confirm = useConfirm<CredentialMeta>();
  const action = useAction();
  const names = useActorNames(user);

  // Ignore what is still loaded for another service while this one loads.
  const c = cred.data && cred.data.id === credentialId ? cred.data : undefined;
  const missing = cred.data === null && !cred.loading;
  const vaultHref = `#/vaults/${vaultId}/credentials`;
  useBreadcrumbs([
    { label: "Vaults", href: "#/vaults" },
    { label: vault.data?.name ?? null, href: vaultHref },
    { label: c?.name ?? (cred.error || missing ? "Service" : null) },
  ]);

  const template = c ? templateOf(templates.data ?? [], c) : undefined;
  const usedBy = (rules.data?.items ?? []).filter((r) => r.credential_id === credentialId);
  const ruleIds = new Set(usedBy.map((r) => r.id));
  const inBundles = (bundles.data?.items ?? []).filter((b) => b.rule_ids.some((id) => ruleIds.has(id)));
  const serviceName = c?.name ?? "";
  const logRules = useMemo(
    () =>
      new Map(
        (rules.data?.items ?? [])
          .filter((r) => r.credential_id === credentialId)
          .map((r) => [r.id, { credential: serviceName, rule: r.name }]),
      ),
    [rules.data, credentialId, serviceName],
  );

  const test = async (target: CredentialMeta) => {
    setResult(null);
    const r = await action.run(() => post<CredentialValidation>(`/credentials/${target.id}/validate`));
    if (r) setResult(r);
  };

  const remove = async (target: CredentialMeta) => {
    const deleted = await action.run(async () => {
      await del(`/credentials/${target.id}`);
      return true;
    });
    confirm.close();
    if (deleted) window.location.hash = vaultHref;
  };

  const done = () => {
    setEditing(null);
    cred.reload();
  };

  const canTest = isAdmin && Boolean(template?.validation);
  const testReason = !isAdmin ? ADMIN_ONLY : template?.validation ? undefined : "This template declares no test request";

  return (
    <PageContainer>
      <PageHeader
        title={
          c ? (
            <span className="flex min-w-0 items-center gap-3">
              <ServiceLogo template={template ?? { id: c.template_id, kind: "http" }} size="sm" />
              <span className="min-w-0 [overflow-wrap:anywhere]">{c.name}</span>
            </span>
          ) : cred.error || missing ? (
            "Service"
          ) : (
            <Skeleton className="h-8 w-48" />
          )
        }
        description={c ? `${template?.name ?? c.template_id} · v${c.template_version}` : undefined}
        actions={
          c && (
            <>
              <Button
                type="button"
                variant="outline"
                onClick={() => void test(c)}
                disabled={!canTest || action.busy}
                title={testReason}
              >
                <FlaskConical />
                Test
              </Button>
              <Button
                type="button"
                variant="outline"
                onClick={() => setEditing("secret")}
                disabled={!isAdmin}
                title={isAdmin ? undefined : ADMIN_ONLY}
              >
                <RefreshCw />
                Replace secret
              </Button>
              <RowMenu
                label={c.name}
                items={[
                  {
                    label: "Delete service",
                    icon: Trash2,
                    onSelect: () => confirm.ask(c),
                    disabled: !isAdmin,
                    reason: ADMIN_ONLY,
                    destructive: true,
                  },
                ]}
              />
            </>
          )
        }
      />
      <ErrorBanner error={cred.error ?? action.error ?? templates.error ?? rules.error ?? bundles.error ?? variables.error} />
      {result && <TestResult result={result} />}
      {missing ? (
        <Panel>
          <Empty
            icon={KeyRound}
            title="This service doesn't exist"
            description="It may have been deleted, or the link is wrong."
            action={
              <Button type="button" variant="outline" size="sm" asChild>
                <a href={vaultHref}>Back to the vault</a>
              </Button>
            }
          />
        </Panel>
      ) : !c ? (
        !cred.error && <Skeleton className="h-64 w-full rounded-lg" />
      ) : (
        <>
          {rules.data && usedBy.length === 0 && (
            <Alert variant="warning">
              <AlertTriangle className="size-4" />
              <AlertTitle>No rule uses this service</AlertTitle>
              <AlertDescription>
                Agents can't use it until a rule allows it.{" "}
                <a href={`#/vaults/${vaultId}/rules`} className="font-medium underline underline-offset-4">
                  Add a rule
                </a>
              </AlertDescription>
            </Alert>
          )}
          <DetailLayout
            facts={
              <FactList>
                <Fact label="Type">{KIND_LABEL[template?.kind ?? "http"]}</Fact>
                <Fact label="Hosts">
                  <Tags values={targetHosts(template, c.host_override)} />
                </Fact>
                <Fact label="Secret">
                  <SecretSummary credential={c} />
                </Fact>
                <Fact label="Created">
                  <Exact at={c.created_at} />
                </Fact>
                <Fact label="Updated">
                  <Relative at={c.updated_at} />
                </Fact>
              </FactList>
            }
          >
            <Section
              title="Rules"
              actions={
                <Button type="button" variant="outline" size="sm" asChild>
                  <a href={`#/vaults/${vaultId}/rules`}>Manage rules</a>
                </Button>
              }
            >
              <ItemList empty="No rule uses this service.">
                {usedBy.map((r) => (
                  <li key={r.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-3 text-sm">
                    <span className="font-medium">{r.name}</span>
                    <Tags values={r.allow.hosts} />
                    {!r.enabled && <Status tone="neutral">Disabled</Status>}
                  </li>
                ))}
              </ItemList>
            </Section>
            <Section title="Access bundles">
              <ItemList empty="Not in any access bundle.">
                {inBundles.map((b) => (
                  <li key={b.id}>
                    <a href={`#/bundles/${b.id}`} className="block px-4 py-3 text-sm font-medium hover:bg-muted/50">
                      {b.name}
                    </a>
                  </li>
                ))}
              </ItemList>
            </Section>
            <Section
              title="Custom headers"
              actions={<EditButton onClick={() => setEditing("headers")} isAdmin={isAdmin} />}
            >
              <ItemList empty="No custom headers.">
                {c.custom_headers.map((h) => (
                  <li key={h.name} className="flex flex-wrap items-baseline gap-x-2 px-4 py-3 text-sm">
                    <span className="font-medium">{h.name}</span>
                    <Mono>{h.value}</Mono>
                  </li>
                ))}
              </ItemList>
            </Section>
            <Section
              title="Placeholders"
              actions={<EditButton onClick={() => setEditing("placeholders")} isAdmin={isAdmin} />}
            >
              <ItemList empty="No placeholders.">
                {c.substitutions.map((s) => (
                  <li key={s.placeholder} className="flex flex-wrap items-baseline gap-x-2 gap-y-1 px-4 py-3 text-sm">
                    <Mono>{s.placeholder}</Mono>
                    <span className="text-muted-foreground">becomes {s.field}</span>
                    {s.env && <span className="text-muted-foreground">· sets {s.env}</span>}
                  </li>
                ))}
              </ItemList>
            </Section>
            <RequestLog
              query={`vault_id=${vaultId}&credential_id=${credentialId}`}
              deps={[c.updated_at]}
              names={names}
              rules={logRules}
              phrase={serviceHistoryPhrase}
              empty="Requests that use this service appear here a few seconds after a proxy handles them."
              showSession
            />
          </DetailLayout>
        </>
      )}
      <FormDialog
        open={editing === "secret"}
        onOpenChange={(o) => {
          if (!o) setEditing(null);
        }}
        title="Replace secret"
        description="The new value takes effect on the proxies at their next policy refresh. The old value cannot be recovered."
      >
        {c && editing === "secret" && (
          <RotateForm
            credential={c}
            template={template}
            variables={variables.data ?? []}
            onCancel={() => setEditing(null)}
            onDone={done}
          />
        )}
      </FormDialog>
      <FormDialog
        open={editing === "headers"}
        onOpenChange={(o) => {
          if (!o) setEditing(null);
        }}
        wide
        title="Custom headers"
        description="Sent with every request this credential is injected into. Reference a variable with {{NAME}} to keep a value secret."
      >
        {c && editing === "headers" && (
          <HeadersForm
            credential={c}
            template={template}
            variables={variables.data ?? []}
            onCancel={() => setEditing(null)}
            onDone={done}
          />
        )}
      </FormDialog>
      <FormDialog
        open={editing === "placeholders"}
        onOpenChange={(o) => {
          if (!o) setEditing(null);
        }}
        wide
        title="Placeholders"
        description="The agent sends the placeholder; the proxy swaps in the secret on its way to this service's hosts, and nowhere else."
      >
        {c && editing === "placeholders" && (
          <PlaceholdersForm credential={c} onCancel={() => setEditing(null)} onDone={done} />
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
    </PageContainer>
  );
}

function TestResult({ result }: { result: CredentialValidation }) {
  const request = `${result.method} ${result.path} on ${result.host}`;
  if (result.ok)
    return (
      <Alert>
        <CheckCircle2 className="size-4 text-success" />
        <AlertTitle>The credential works</AlertTitle>
        <AlertDescription>
          {request} answered {result.status}.
        </AlertDescription>
      </Alert>
    );
  return (
    <Alert variant="warning">
      <FlaskConical className="size-4" />
      <AlertTitle>Test of {request} failed</AlertTitle>
      <AlertDescription>
        {result.detail}
        {result.detail.includes("Settings") && (
          <>
            {" "}
            <a href="#/settings" className="font-medium underline underline-offset-4">
              Open Settings
            </a>
          </>
        )}
      </AlertDescription>
    </Alert>
  );
}

function EditButton({ onClick, isAdmin }: { onClick: () => void; isAdmin: boolean }) {
  return (
    <Button type="button" variant="outline" size="sm" onClick={onClick} disabled={!isAdmin} title={isAdmin ? undefined : ADMIN_ONLY}>
      <Pencil />
      Edit
    </Button>
  );
}

/** A bordered list, or one muted line when it has nothing in it. */
function ItemList({ empty, children }: { empty: string; children: ReactNode[] }) {
  if (children.length === 0) return <p className="text-sm text-muted-foreground">{empty}</p>;
  return (
    <Panel>
      <ul role="list" className="divide-y">
        {children}
      </ul>
    </Panel>
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
