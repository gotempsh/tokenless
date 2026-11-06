// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// "Add a service" as a page with its own address: the catalogue first, then
// one form for where the service lives, what agents may do with it, the
// access bundle it joins and its credential, with a summary of what will be
// created beside it. Started from the catalogue, a vault or a bundle.

import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Check, ChevronLeft, Lock } from "lucide-react";
import {
  get,
  patch,
  post,
  type AccessBundle,
  type CredentialMeta,
  type Page,
  type Rule,
  type ServiceTemplate,
  type StoredTemplate,
  type UserSummary,
  type Vault,
} from "../api";
import {
  addService,
  AddServiceError,
  addServiceHref,
  READ_ONLY_METHODS,
  type AccessPreset,
  type AddServiceApi,
  type AddServiceContext,
  type AddServicePlan,
  type AddServiceProgress,
  type BundleChoice,
  type CredentialBody,
} from "../addService";
import { latestTemplates } from "../catalog";
import { useLoad } from "../hooks";
import { cn } from "../lib/utils";
import { CommandSnippet, runCommand } from "./Bundles";
import {
  DialogActions,
  ErrorBanner,
  Field,
  Mono,
  Panel,
  SelectField,
  Tags,
  type Choice,
} from "../components/common";
import { ServiceForm, useVariableKeys } from "../components/ServiceForm";
import { ServiceLogo } from "../components/ServiceLogo";
import { TemplateCatalog } from "../components/TemplateCatalog";
import { Button } from "../components/ui/button-components";
import { Input } from "../components/ui/input";
import { PageContainer, PageHeader } from "../components/ui/page-header";
import { Skeleton } from "../components/ui/skeleton";

const NEW_VAULT = "__new__";
const NEW_BUNDLE = "__new_bundle__";
const NO_BUNDLE = "__no_bundle__";
const BUNDLE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

const liveApi: AddServiceApi = {
  createVault: (name) => post<Vault>("/vaults", { name }),
  createCredential: (vaultId, body) => post<CredentialMeta>(`/vaults/${vaultId}/credentials`, body),
  createRule: (vaultId, body) => post<Rule>(`/vaults/${vaultId}/rules`, body),
  getBundle: (id) => get<AccessBundle>(`/bundles/${id}`),
  createBundle: (vaultId, body) => post<AccessBundle>(`/vaults/${vaultId}/bundles`, body),
  setBundleRules: (id, ruleIds) => patch<AccessBundle>(`/bundles/${id}`, { rule_ids: ruleIds }),
};

interface Where {
  vaultId: string;
  newVaultName: string;
  access: AccessPreset;
  bundleMode: BundleChoice["kind"];
  bundleId: string;
  newBundleName: string;
}

function initialWhere(ctx: AddServiceContext): Where {
  return {
    vaultId: ctx.vault ?? "",
    newVaultName: "",
    access: "full",
    // Joining an existing bundle is the common case; the form switches to
    // "new" when the vault has none.
    bundleMode: "existing",
    bundleId: ctx.bundle ?? "",
    newBundleName: "",
  };
}

/** What still has to be chosen before the service can be added, if anything. */
function whereProblem(where: Where): string | null {
  if (where.vaultId === "") return "Choose a vault first.";
  if (where.vaultId === NEW_VAULT && where.newVaultName.trim() === "") return "Name the new vault first.";
  if (where.bundleMode === "existing" && where.bundleId === "") return "Choose the access bundle first.";
  if (where.bundleMode === "new") {
    const name = where.newBundleName.trim();
    if (name === "") return "Name the new access bundle first.";
    if (!BUNDLE_NAME.test(name)) return "Fix the bundle name first.";
  }
  return null;
}

/** The bundle select's value: a bundle id, "new", "none" or nothing yet. */
function bundleSelectValue(where: Where): string {
  if (where.bundleMode === "new") return NEW_BUNDLE;
  if (where.bundleMode === "none") return NO_BUNDLE;
  return where.bundleId;
}

function fromBundleSelect(value: string): Partial<Where> {
  if (value === NEW_BUNDLE) return { bundleMode: "new" };
  if (value === NO_BUNDLE) return { bundleMode: "none" };
  return { bundleMode: "existing", bundleId: value };
}

function bundleHint(where: Where): string {
  if (where.bundleMode === "new") {
    const name = where.newBundleName.trim();
    return name && !BUNDLE_NAME.test(name)
      ? "Letters, digits, '-', '_' and '.', starting with a letter or digit."
      : "Agents start with it by name: --bundle <name>.";
  }
  if (where.bundleMode === "none") return "Add it to a bundle later from the bundle's page.";
  return "Agents started with the bundle get this service.";
}

/** A compact choice between a few options, as a row of toggle buttons. */
function Segmented<T extends string>({
  name,
  value,
  onChange,
  choices,
}: {
  name: string;
  value: T;
  onChange: (value: T) => void;
  choices: Choice<T>[];
}) {
  return (
    <div role="radiogroup" className="inline-flex rounded-md border p-0.5">
      {choices.map((c) => (
        <button
          key={c.value}
          id={`${name}-${c.value}`}
          type="button"
          role="radio"
          aria-checked={value === c.value}
          onClick={() => onChange(c.value)}
          className={cn(
            "rounded-sm px-3 py-1.5 text-sm text-muted-foreground transition-colors hover:text-foreground",
            value === c.value && "bg-accent font-medium text-foreground",
          )}
        >
          {c.title}
        </button>
      ))}
    </div>
  );
}

function planFor(where: Where, credential: CredentialBody): AddServicePlan {
  const vault: AddServicePlan["vault"] =
    where.vaultId === NEW_VAULT
      ? { kind: "new", name: where.newVaultName }
      : { kind: "existing", id: where.vaultId, name: where.vaultId };
  const bundle: BundleChoice =
    where.bundleMode === "existing"
      ? { kind: "existing", id: where.bundleId, name: "" }
      : where.bundleMode === "new"
        ? { kind: "new", name: where.newBundleName, description: "" }
        : { kind: "none" };
  return { vault, credential, access: where.access, bundle };
}

const BACK_LABELS: [RegExp, string][] = [
  [/^vaults\/[^/]+\/bundles$/, "access bundles"],
  [/^vaults\/[^/]+/, "vault"],
  [/^bundles/, "access bundles"],
  [/^templates/, "templates"],
];

function backLink(ctx: AddServiceContext): { href: string; label: string } {
  const back = ctx.back ?? "templates";
  const label = BACK_LABELS.find(([re]) => re.test(back))?.[1] ?? "templates";
  return { href: `#/${back}`, label: `Back to ${label}` };
}

export function AddService({ ctx, user }: { ctx: AddServiceContext; user: UserSummary }) {
  const templates = useLoad(() => get<StoredTemplate[]>("/templates"), []);
  const template = useMemo(
    () =>
      ctx.template
        ? latestTemplates(templates.data ?? []).find(
            (t) => t.template.id === ctx.template && t.status === "approved",
          )?.template
        : undefined,
    [templates.data, ctx.template],
  );
  const back = backLink(ctx);

  return (
    <PageContainer>
      <a href={back.href} className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
        <ChevronLeft className="size-4" />
        {back.label}
      </a>
      <ErrorBanner error={templates.error} />
      {!ctx.template ? (
        <Catalogue ctx={ctx} templates={templates.data ?? []} loading={templates.loading && !templates.data} />
      ) : templates.loading && !templates.data ? (
        <div className="space-y-4">
          <Skeleton className="h-8 w-64" />
          <Skeleton className="h-64 w-full" />
        </div>
      ) : template ? (
        <ServicePage key={`${template.id}@${template.version}`} ctx={ctx} template={template} user={user} back={back.href} />
      ) : (
        <Panel className="space-y-3 p-6">
          <p className="font-medium">No approved template "{ctx.template}"</p>
          <p className="text-sm text-muted-foreground">
            It may have been renamed, or an imported template may still be waiting for an admin to approve it.
          </p>
          <Button type="button" variant="outline" asChild>
            <a href={addServiceHref({ ...ctx, template: undefined })}>Choose another service</a>
          </Button>
        </Panel>
      )}
    </PageContainer>
  );
}

function Catalogue({ ctx, templates, loading }: { ctx: AddServiceContext; templates: StoredTemplate[]; loading: boolean }) {
  return (
    <>
      <PageHeader
        title="Add a service"
        description="Pick the API or MCP server agents need. You choose its vault, what agents may do with it and its access bundle on the next page, then add the secret."
      />
      <TemplateCatalog
        templates={templates}
        loading={loading}
        autoFocus
        onOpen={(t) => {
          window.location.hash = addServiceHref({ ...ctx, template: t.template.id });
        }}
      />
    </>
  );
}

function ServicePage({
  ctx,
  template,
  user,
  back,
}: {
  ctx: AddServiceContext;
  template: ServiceTemplate;
  user: UserSummary;
  back: string;
}) {
  const isAdmin = user.role === "admin";
  const [where, setWhere] = useState<Where>(() => initialWhere(ctx));
  const [result, setResult] = useState<AddServiceProgress | null>(null);
  const progress = useRef<AddServiceProgress>({});
  const variables = useVariableKeys(isAdmin);
  const vaults = useLoad(() => get<Page<Vault>>("/vaults?page_size=100"), []);
  const chosenVault = where.vaultId && where.vaultId !== NEW_VAULT ? where.vaultId : "";
  const bundles = useLoad(
    () =>
      chosenVault ? get<Page<AccessBundle>>(`/vaults/${chosenVault}/bundles?page_size=100`) : Promise.resolve(undefined),
    [chosenVault],
  );
  const bundleItems = useMemo(() => bundles.data?.items ?? [], [bundles.data]);
  const set = (patch: Partial<Where>) => setWhere((w) => ({ ...w, ...patch }));

  // A new vault, or one without bundles, has nothing to join: offer a new one.
  const nothingToJoin = (where.vaultId === NEW_VAULT || bundles.data !== undefined) && bundleItems.length === 0;
  useEffect(() => {
    if (nothingToJoin) setWhere((w) => (w.bundleMode === "existing" ? { ...w, bundleMode: "new" } : w));
  }, [nothingToJoin]);

  const vaultName =
    where.vaultId === NEW_VAULT
      ? where.newVaultName.trim()
      : vaults.data?.items.find((v) => v.id === where.vaultId)?.name;
  const bundleName =
    where.bundleMode === "existing"
      ? bundleItems.find((b) => b.id === where.bundleId)?.name
      : where.bundleMode === "new"
        ? where.newBundleName.trim()
        : undefined;
  const problem = whereProblem(where);

  if (result) {
    return (
      <>
        <PageHeader title={<TemplateTitle template={template} prefix="" suffix=" is ready" />} />
        <Done
          template={template}
          result={result}
          access={where.access}
          back={back}
          another={addServiceHref({ vault: result.vault?.id, bundle: result.bundle?.id, back: ctx.back })}
        />
      </>
    );
  }

  const accessChoices: Choice<AccessPreset>[] =
    template.kind === "mcp"
      ? [{ value: "full", title: "Use every tool", description: "Limit tools afterwards under Rules → Tools." }]
      : [
          {
            value: "full",
            title: "Full access",
            description: `${template.allow.methods.join(", ") === "*" ? "Any method" : template.allow.methods.join(", ")} on ${template.allow.paths.join(", ")}, as the template allows.`,
          },
          {
            value: "read_only",
            title: "Read only",
            description: `${READ_ONLY_METHODS.join(" and ")} only; anything that changes data gets a 403.`,
          },
        ];

  return (
    <>
      <PageHeader
        title={<TemplateTitle template={template} prefix="Add " suffix="" />}
        description={template.description}
        actions={
          <Button type="button" variant="outline" asChild>
            <a href={addServiceHref({ ...ctx, template: undefined })}>Choose another service</a>
          </Button>
        }
      />
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-[minmax(0,1fr)_20rem]">
        <div className="min-w-0 space-y-6">
          <ErrorBanner error={vaults.error ?? bundles.error ?? variables.error} />
          <Panel className="space-y-5 p-5">
            <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
              <div className="space-y-3">
                {ctx.vault ? (
                  <Field label="Vault">
                    {vaultName ? (
                      <p className="flex h-10 items-center text-sm font-medium">{vaultName}</p>
                    ) : vaults.data ? (
                      <p className="text-sm text-destructive">
                        Vault {ctx.vault} does not exist or you cannot see it.{" "}
                        <a href={addServiceHref({ ...ctx, vault: undefined })} className="underline underline-offset-4">
                          Choose another
                        </a>
                      </p>
                    ) : (
                      <Skeleton className="h-10 w-full" />
                    )}
                  </Field>
                ) : vaults.loading && !vaults.data ? (
                  <Skeleton className="h-16 w-full" />
                ) : (
                  <Field
                    label="Vault"
                    htmlFor="add-vault"
                    hint={vaults.data?.items.length === 0 && !isAdmin ? "No vaults yet. Ask an admin to create one." : undefined}
                  >
                    <SelectField
                      id="add-vault"
                      value={where.vaultId}
                      onChange={(vaultId) => set({ vaultId, bundleId: "", bundleMode: "existing" })}
                      placeholder={vaults.data?.items.length === 0 ? "No vaults yet" : "Choose a vault…"}
                      options={[
                        ...(vaults.data?.items ?? []).map((v) => ({ value: v.id, label: v.name })),
                        ...(isAdmin ? [{ value: NEW_VAULT, label: "New vault…" }] : []),
                      ]}
                    />
                  </Field>
                )}
                {where.vaultId === NEW_VAULT && (
                  <Input
                    id="add-vault-name"
                    aria-label="New vault name"
                    value={where.newVaultName}
                    onChange={(e) => set({ newVaultName: e.target.value })}
                    placeholder="New vault name, e.g. agents"
                    autoFocus
                  />
                )}
              </div>
              <div className="space-y-3">
                <Field label="Access bundle" htmlFor="add-bundle" hint={bundleHint(where)}>
                  <SelectField
                    id="add-bundle"
                    value={bundleSelectValue(where)}
                    onChange={(v) => set(fromBundleSelect(v))}
                    placeholder="Choose a bundle…"
                    options={[
                      ...bundleItems.map((b) => ({
                        value: b.id,
                        label: `${b.name} (${b.rule_ids.length} service${b.rule_ids.length === 1 ? "" : "s"})`,
                      })),
                      { value: NEW_BUNDLE, label: "New bundle…" },
                      { value: NO_BUNDLE, label: "No bundle" },
                    ]}
                  />
                </Field>
                {where.bundleMode === "new" && (
                  <Input
                    id="add-bundle-name"
                    aria-label="New bundle name"
                    aria-invalid={where.newBundleName !== "" && !BUNDLE_NAME.test(where.newBundleName.trim())}
                    className="font-mono"
                    value={where.newBundleName}
                    onChange={(e) => set({ newBundleName: e.target.value })}
                    placeholder="code-review"
                  />
                )}
              </div>
            </div>
            <Field label="Agents may" htmlFor="add-access-full" hint={accessChoices.find((c) => c.value === where.access)?.description}>
              <Segmented<AccessPreset> name="add-access" value={where.access} onChange={(access) => set({ access })} choices={accessChoices} />
            </Field>
          </Panel>
          <Panel className="space-y-4 p-5">
            <div className="flex flex-wrap items-baseline justify-between gap-2">
              <h2 className="text-base font-semibold">Credential</h2>
              <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
                <Lock className="size-3.5" />
                Write-only once saved
              </p>
            </div>
            {variables.loading && !variables.data ? (
              <Skeleton className="h-40 w-full" />
            ) : (
              <ServiceForm
                template={template}
                variables={variables.data ?? []}
                isAdmin={isAdmin}
                showTemplate={false}
                blocked={problem}
                submitLabel={bundleName ? `Add to ${bundleName}` : "Add service"}
                backLabel="Cancel"
                onBack={() => {
                  window.location.hash = back;
                }}
                onSubmit={async (body) => {
                  try {
                    const done = await addService(planFor(where, body), liveApi, progress.current);
                    progress.current = done;
                    return done;
                  } catch (e) {
                    if (e instanceof AddServiceError) progress.current = e.progress;
                    throw e;
                  }
                }}
                onSaved={() => setResult(progress.current)}
              />
            )}
          </Panel>
        </div>
        <aside className="lg:sticky lg:top-20 lg:self-start">
          <Summary
            template={template}
            vaultName={vaultName}
            newVault={where.vaultId === NEW_VAULT}
            access={where.access}
            bundleName={bundleName}
            newBundle={where.bundleMode === "new"}
          />
        </aside>
      </div>
    </>
  );
}

function TemplateTitle({ template, prefix, suffix }: { template: ServiceTemplate; prefix: string; suffix: string }) {
  return (
    <span className="flex items-center gap-3">
      <ServiceLogo template={template} />
      <span>
        {prefix}
        {template.name}
        {suffix}
      </span>
    </span>
  );
}

function SummaryRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="space-y-1">
      <dt className="text-xs font-medium text-muted-foreground">{label}</dt>
      <dd className="min-w-0 text-sm">{children}</dd>
    </div>
  );
}

function Summary({
  template,
  vaultName,
  newVault,
  access,
  bundleName,
  newBundle,
}: {
  template: ServiceTemplate;
  vaultName: string | undefined;
  newVault: boolean;
  access: AccessPreset;
  bundleName: string | undefined;
  newBundle: boolean;
}) {
  const pending = <span className="text-muted-foreground">not chosen yet</span>;
  return (
    <Panel className="space-y-4 p-4">
      <p className="text-sm font-medium">What will be created</p>
      <dl className="space-y-3">
        <SummaryRow label="Vault">
          {vaultName ? (
            <>
              {vaultName}
              {newVault && <span className="text-muted-foreground"> (new)</span>}
            </>
          ) : (
            pending
          )}
        </SummaryRow>
        <SummaryRow label="Service">
          {template.name}, its secret encrypted and write-only
        </SummaryRow>
        <SummaryRow label="Rule">
          {access === "read_only" ? `${READ_ONLY_METHODS.join(" and ")} only` : "Full access"}
          <div className="mt-1">
            {template.hosts.length ? <Tags values={template.hosts} /> : <span className="text-muted-foreground">the host you enter</span>}
          </div>
        </SummaryRow>
        <SummaryRow label="Access bundle">
          {bundleName ? (
            <>
              <Mono>{bundleName}</Mono>
              {newBundle && <span className="text-muted-foreground"> (new)</span>}
            </>
          ) : newBundle ? (
            pending
          ) : (
            <span className="text-muted-foreground">none</span>
          )}
        </SummaryRow>
      </dl>
      {bundleName && (
        <div className="space-y-2 border-t pt-4">
          <p className="text-xs text-muted-foreground">Agents then start with</p>
          <CommandSnippet command={runCommand(bundleName)} />
        </div>
      )}
    </Panel>
  );
}

function Done({
  template,
  result,
  access,
  back,
  another,
}: {
  template: ServiceTemplate;
  result: AddServiceProgress;
  access: AccessPreset;
  back: string;
  another: string;
}) {
  const vault = result.vault;
  const items = [
    vault?.created ? (
      <>
        Created vault <span className="font-medium">{vault.name}</span>
      </>
    ) : null,
    result.credential ? (
      <>
        Stored the {template.name} credential as <span className="font-medium">{result.credential.name}</span>
      </>
    ) : null,
    result.rule ? (
      <>
        Rule <span className="font-medium">{result.rule.name}</span>:{" "}
        {access === "read_only" ? `${READ_ONLY_METHODS.join(" and ")} only` : "everything the template allows"} on{" "}
        <Tags values={result.rule.allow.hosts} />
      </>
    ) : null,
    result.bundle ? (
      <>
        In access bundle <span className="font-mono font-medium">{result.bundle.name}</span> ({result.bundle.rule_ids.length}{" "}
        service{result.bundle.rule_ids.length === 1 ? "" : "s"})
      </>
    ) : (
      <span className="text-muted-foreground">Not in an access bundle yet</span>
    ),
  ].filter((x) => x !== null);
  return (
    <Panel className="space-y-5 p-6 text-sm">
      <ul className="space-y-2">
        {items.map((item, i) => (
          <li key={i} className="flex flex-wrap items-center gap-2">
            <Check className="size-4 shrink-0 text-success" />
            {item}
          </li>
        ))}
      </ul>
      {result.bundle ? (
        <div className="space-y-2 rounded-md border bg-muted/40 p-4">
          <p className="font-medium">Run an agent with it</p>
          <CommandSnippet command={runCommand(result.bundle.name)} />
          <p className="text-xs text-muted-foreground">
            The agent gets a local proxy address, never the secret or a session token. It needs a{" "}
            <Mono>session_issuer</Mono> API key for this vault, from{" "}
            <a href="#/api-keys" className="underline underline-offset-4">
              API keys
            </a>
            .
          </p>
        </div>
      ) : (
        <p className="text-muted-foreground">
          Put its rule in an access bundle under{" "}
          <a href="#/bundles" className="underline underline-offset-4">
            Access bundles
          </a>{" "}
          so agents can start with it by name.
        </p>
      )}
      <DialogActions>
        {vault && (
          <Button type="button" variant="outline" asChild>
            <a href={`#/vaults/${vault.id}`}>Open vault</a>
          </Button>
        )}
        <Button type="button" variant="outline" asChild>
          <a href={another}>Add another service</a>
        </Button>
        <Button type="button" asChild>
          <a href={back}>Done</a>
        </Button>
      </DialogActions>
    </Panel>
  );
}
