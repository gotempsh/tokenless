// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// "Add a service" as a page with its own address: the catalogue first, then
// one form for where the service lives, what agents may do with it, the
// access bundle it joins and its credential, with a summary of what will be
// created beside it. Started from the catalogue, a vault or a bundle.

import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Check, ChevronLeft } from "lucide-react";
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
import { CommandSnippet, runCommand } from "./Bundles";
import {
  ChoiceCards,
  DialogActions,
  ErrorBanner,
  Field,
  Mono,
  Panel,
  Section,
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
import { Textarea } from "../components/ui/textarea";

const NEW_VAULT = "__new__";
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
  newBundleDescription: string;
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
    newBundleDescription: "",
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

function planFor(where: Where, credential: CredentialBody): AddServicePlan {
  const vault: AddServicePlan["vault"] =
    where.vaultId === NEW_VAULT
      ? { kind: "new", name: where.newVaultName }
      : { kind: "existing", id: where.vaultId, name: where.vaultId };
  const bundle: BundleChoice =
    where.bundleMode === "existing"
      ? { kind: "existing", id: where.bundleId, name: "" }
      : where.bundleMode === "new"
        ? { kind: "new", name: where.newBundleName, description: where.newBundleDescription }
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
      ? [{ value: "full", title: "Every tool", description: "All of the server's tools. Limit them afterwards under Rules → Tools." }]
      : [
          {
            value: "full",
            title: "Everything the template allows",
            description: `${template.allow.methods.join(", ") === "*" ? "Any method" : template.allow.methods.join(", ")} on ${template.allow.paths.join(", ")}.`,
          },
          {
            value: "read_only",
            title: "Read only",
            description: `Only ${READ_ONLY_METHODS.join(" and ")} requests; anything that changes data is refused with 403.`,
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
        <div className="min-w-0 space-y-8">
          <ErrorBanner error={vaults.error ?? bundles.error ?? variables.error} />
          <Section title="Vault" description="Agents get services from one vault per session.">
            {ctx.vault ? (
              vaultName ? (
                <p className="text-sm font-medium">{vaultName}</p>
              ) : vaults.data ? (
                <p className="text-sm text-destructive">
                  Vault {ctx.vault} does not exist or you cannot see it.{" "}
                  <a href={addServiceHref({ ...ctx, vault: undefined })} className="underline underline-offset-4">
                    Choose another vault
                  </a>
                  .
                </p>
              ) : (
                <Skeleton className="h-5 w-40" />
              )
            ) : vaults.loading && !vaults.data ? (
              <Skeleton className="h-9 w-full" />
            ) : (
              <div className="space-y-4">
                <Field
                  label="Vault"
                  htmlFor="add-vault"
                  hint={
                    vaults.data?.items.length === 0
                      ? isAdmin
                        ? "No vaults yet: name one and it is created with the service."
                        : "No vaults yet. Ask an admin to create one."
                      : undefined
                  }
                >
                  <SelectField
                    id="add-vault"
                    value={where.vaultId}
                    onChange={(vaultId) => set({ vaultId, bundleId: "", bundleMode: "existing" })}
                    placeholder="Choose a vault…"
                    options={[
                      ...(vaults.data?.items ?? []).map((v) => ({ value: v.id, label: v.name })),
                      ...(isAdmin ? [{ value: NEW_VAULT, label: "New vault…" }] : []),
                    ]}
                  />
                </Field>
                {where.vaultId === NEW_VAULT && (
                  <Field label="New vault name" htmlFor="add-vault-name">
                    <Input
                      id="add-vault-name"
                      value={where.newVaultName}
                      onChange={(e) => set({ newVaultName: e.target.value })}
                      placeholder="agents"
                      autoFocus
                    />
                  </Field>
                )}
              </div>
            )}
          </Section>
          <Section title="What agents may do" description="A rule for this service. You can narrow it further under Rules.">
            <ChoiceCards<AccessPreset> name="add-access" value={where.access} onChange={(access) => set({ access })} choices={accessChoices} />
          </Section>
          <Section title="Access bundle" description="The job agents start with by name, such as code-review.">
            <div className="space-y-4">
              <ChoiceCards<BundleChoice["kind"]>
                name="add-bundle"
                value={where.bundleMode}
                onChange={(bundleMode) => set({ bundleMode })}
                choices={[
                  ...(bundleItems.length > 0
                    ? [{ value: "existing" as const, title: "Add to a bundle", description: "Agents started with it get this service too." }]
                    : []),
                  { value: "new" as const, title: "New bundle", description: "Create a bundle for a job and put this service in it." },
                  { value: "none" as const, title: "No bundle", description: "Add it to a bundle later, or pick its rule when minting." },
                ]}
              />
              {where.bundleMode === "existing" && (
                <Field label="Bundle" htmlFor="add-bundle-id">
                  <SelectField
                    id="add-bundle-id"
                    value={where.bundleId}
                    onChange={(bundleId) => set({ bundleId })}
                    placeholder="Choose a bundle…"
                    options={bundleItems.map((b) => ({
                      value: b.id,
                      label: `${b.name} (${b.rule_ids.length} service${b.rule_ids.length === 1 ? "" : "s"})`,
                    }))}
                  />
                </Field>
              )}
              {where.bundleMode === "new" && (
                <>
                  <Field
                    label="Bundle name"
                    htmlFor="add-bundle-name"
                    hint={
                      where.newBundleName && !BUNDLE_NAME.test(where.newBundleName.trim())
                        ? "Letters, digits, '-', '_' and '.', starting with a letter or digit (up to 64)."
                        : "Used on the command line: --bundle <name>."
                    }
                  >
                    <Input
                      id="add-bundle-name"
                      className="font-mono"
                      value={where.newBundleName}
                      onChange={(e) => set({ newBundleName: e.target.value })}
                      placeholder="code-review"
                    />
                  </Field>
                  <Field label="Description" htmlFor="add-bundle-description" hint="Optional: what the job is.">
                    <Textarea
                      id="add-bundle-description"
                      rows={2}
                      value={where.newBundleDescription}
                      onChange={(e) => set({ newBundleDescription: e.target.value })}
                      placeholder="Read pull requests and post review comments"
                    />
                  </Field>
                </>
              )}
            </div>
          </Section>
          <Section
            title="Credential"
            description="Secrets are write-only: once saved, nobody (admins included) can read them back. The proxy adds them to agents' requests."
          >
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
          </Section>
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
          {access === "read_only" ? `${READ_ONLY_METHODS.join(" and ")} only` : "Everything the template allows"}
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
