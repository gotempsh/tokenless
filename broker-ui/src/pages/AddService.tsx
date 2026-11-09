// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// "Add a service" as a page with its own address: the catalogue first, then
// one form for where the service lives, what agents may do with it, the
// access bundles it joins (if any) and its credential, with a summary of what will be
// created beside it. Started from the catalogue, a vault or a bundle.

import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Check, Lock } from "lucide-react";
import {
  get,
  patch,
  post,
  type AccessBundle,
  type CredentialMeta,
  type Page,
  type ProxySession,
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
  BUNDLE_NAME,
  bundlesToJoin,
  chosenBundlesProblem,
  newBundleProblem,
  unlistedBundles,
  READ_ONLY_METHODS,
  sessionsWithout,
  type AccessPreset,
  type AddServiceApi,
  type AddServiceContext,
  type AddServicePlan,
  type AddServiceProgress,
  type CredentialBody,
} from "../addService";
import { latestTemplates } from "../catalog";
import { useLoad } from "../hooks";
import { backCrumbs, useBreadcrumbs } from "../breadcrumbs";
import { cn } from "../lib/utils";

import {
  CheckField,
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
  /** Bundles of the vault to add the service to; none is fine. */
  bundleIds: string[];
  newBundle: boolean;
  newBundleName: string;
}

function initialWhere(ctx: AddServiceContext): Where {
  return {
    vaultId: ctx.vault ?? "",
    newVaultName: "",
    access: "full",
    // Opened from a bundle, the service is meant for it; otherwise it
    // joins nothing until the person checks a bundle.
    bundleIds: ctx.bundle ? [ctx.bundle] : [],
    newBundle: false,
    newBundleName: "",
  };
}

/**
 * What still has to be chosen before the service can be added, if anything.
 * `bundles` is undefined until the chosen vault's bundles have loaded, and
 * `complete` once they are all of the vault's bundles.
 */
function whereProblem(where: Where, bundles: readonly AccessBundle[] | undefined, complete: boolean): string | null {
  if (where.vaultId === "") return "Choose a vault first.";
  if (where.vaultId === NEW_VAULT && where.newVaultName.trim() === "") return "Name the new vault first.";
  const chosen = chosenBundlesProblem(where.bundleIds, bundles, complete);
  if (chosen) return chosen;
  return where.newBundle ? newBundleProblem(where.newBundleName, bundles) : null;
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

function planFor(
  where: Where,
  bundles: readonly AccessBundle[] | undefined,
  credential: CredentialBody,
): AddServicePlan {
  const vault: AddServicePlan["vault"] =
    where.vaultId === NEW_VAULT
      ? { kind: "new", name: where.newVaultName }
      : { kind: "existing", id: where.vaultId, name: where.vaultId };
  return {
    vault,
    credential,
    access: where.access,
    bundles: {
      join: bundlesToJoin(where.bundleIds, bundles),
      create: where.newBundle ? { name: where.newBundleName, description: "" } : undefined,
    },
  };
}

/** Where Back, Cancel and Done return to: the page that opened this one. */
function backHref(ctx: AddServiceContext): string {
  return `#/${ctx.back ?? "templates"}`;
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
  const back = backHref(ctx);
  // The names of the vault or bundle this page was opened from, for the trail.
  const [backSection, backId] = (ctx.back ?? "").split("/");
  const origin = useLoad(
    async () =>
      backId && backSection === "vaults"
        ? (await get<Vault>(`/vaults/${backId}`)).name
        : backId && backSection === "bundles"
          ? (await get<AccessBundle>(`/bundles/${backId}`)).name
          : undefined,
    [backSection, backId],
  );
  const originName = origin.data ?? (origin.error ? (backSection === "vaults" ? "Vault" : "Access bundle") : null);
  useBreadcrumbs([
    ...backCrumbs(ctx.back, { vault: originName, bundle: originName }),
    { label: "Add a service", href: addServiceHref({ ...ctx, template: undefined }) },
    ...(ctx.template ? [{ label: template?.name ?? (templates.loading ? null : ctx.template) }] : []),
  ]);

  return (
    <PageContainer>
      <ErrorBanner error={templates.error} />
      {!ctx.template ? (
        <Catalogue ctx={ctx} templates={templates.data ?? []} loading={templates.loading && !templates.data} />
      ) : templates.loading && !templates.data ? (
        <div className="space-y-4">
          <Skeleton className="h-8 w-64" />
          <Skeleton className="h-64 w-full" />
        </div>
      ) : template ? (
        <ServicePage key={`${template.id}@${template.version}`} ctx={ctx} template={template} user={user} back={back} />
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
  // The vault's bundles once loaded; a new vault has none.
  const loadedBundles = where.vaultId === NEW_VAULT ? [] : bundles.data?.items;
  const bundlesComplete =
    where.vaultId === NEW_VAULT || (bundles.data !== undefined && bundles.data.items.length >= bundles.data.total);
  // Names already used in the vault, so the form can suggest a free one
  // instead of failing on save. A service this page already saved (before
  // a later step failed) is the user's own, not a clash.
  const existing = useLoad(
    () =>
      chosenVault
        ? get<Page<CredentialMeta>>(`/vaults/${chosenVault}/credentials?page_size=100`)
        : Promise.resolve(undefined),
    [chosenVault],
  );
  const takenNames = useMemo(
    () =>
      where.vaultId === NEW_VAULT
        ? []
        : existing.data?.items.map((c) => c.name).filter((n) => n !== progress.current.credential?.name),
    [existing.data, where.vaultId],
  );
  const set = (patch: Partial<Where>) => setWhere((w) => ({ ...w, ...patch }));

  // Pick what there is only one of, so the form asks only real questions.
  const vaultItems = vaults.data?.items;
  useEffect(() => {
    if (vaultItems?.length === 1 && vaultItems[0]) {
      const only = vaultItems[0].id;
      setWhere((w) => (w.vaultId === "" ? { ...w, vaultId: only } : w));
    }
  }, [vaultItems]);
  const vaultName =
    where.vaultId === NEW_VAULT
      ? where.newVaultName.trim()
      : vaults.data?.items.find((v) => v.id === where.vaultId)?.name;
  // The bundles the service will join, by name, for the summary and button.
  const bundleNames = [
    ...bundlesToJoin(where.bundleIds, loadedBundles).map((b) => ({ name: b.name, isNew: false })),
    ...(where.newBundle ? [{ name: where.newBundleName.trim(), isNew: true }] : []),
  ];
  const onlyBundle = bundleNames.length === 1 && bundleNames[0]?.name ? bundleNames[0].name : undefined;
  const problem = whereProblem(where, loadedBundles, bundlesComplete);

  if (result) {
    return (
      <>
        <PageHeader title={<TemplateTitle template={template} prefix="" suffix=" is ready" />} />
        <Done
          template={template}
          result={result}
          access={where.access}
          back={back}
          another={addServiceHref({
            vault: result.vault?.id,
            bundle: result.bundles?.length === 1 ? result.bundles[0]?.id : undefined,
            back: ctx.back,
          })}
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
      />
      <div className="grid grid-cols-1 gap-8 lg:grid-cols-[minmax(0,42rem)_20rem]">
        <div className="min-w-0 space-y-6">
          <ErrorBanner error={vaults.error ?? bundles.error ?? variables.error} />
          <Panel className="space-y-5 p-6">
            <FormSection
              title="Credential"
              aside={
                <span className="flex items-center gap-1.5">
                  <Lock className="size-3.5" />
                  Write-only once saved
                </span>
              }
            />
            {variables.loading && !variables.data ? (
              <Skeleton className="h-40 w-full" />
            ) : (
              <ServiceForm
                template={template}
                variables={variables.data ?? []}
                isAdmin={isAdmin}
                showTemplate={false}
                blocked={problem}
                takenNames={takenNames}
                vaultName={vaultName}
                submitLabel={onlyBundle ? `Add to ${onlyBundle}` : "Add service"}
                backLabel="Cancel"
                onBack={() => {
                  window.location.hash = back;
                }}
                onSubmit={async (body) => {
                  try {
                    const done = await addService(planFor(where, loadedBundles, body), liveApi, progress.current);
                    progress.current = done;
                    return done;
                  } catch (e) {
                    if (e instanceof AddServiceError) progress.current = e.progress;
                    throw e;
                  }
                }}
                onSaved={() => setResult(progress.current)}
              >
                <div className="space-y-5 border-t pt-6">
                  <FormSection
                    title="Who can use it"
                    aside={ctx.vault && vaultName ? <>In vault <span className="font-medium text-foreground">{vaultName}</span></> : undefined}
                  />
                  <div className="space-y-3">
                    {ctx.vault ? (
                      vaultName ? null : vaults.data ? (
                        <p className="text-sm text-destructive">
                          Vault {ctx.vault} does not exist or you cannot see it.{" "}
                          <a href={addServiceHref({ ...ctx, vault: undefined })} className="underline underline-offset-4">
                            Choose another
                          </a>
                        </p>
                      ) : (
                        <Skeleton className="h-5 w-40" />
                      )
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
                          onChange={(vaultId) => set({ vaultId, bundleIds: [] })}
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
                  <BundleChoices
                    where={where}
                    set={set}
                    bundles={where.vaultId === NEW_VAULT ? [] : chosenVault && bundles.data ? bundleItems : undefined}
                    complete={bundlesComplete}
                    vaultChosen={where.vaultId !== ""}
                  />
                  <Field label="Agents may" htmlFor="add-access-full" hint={accessChoices.find((c) => c.value === where.access)?.description}>
                    <div>
                      <Segmented<AccessPreset> name="add-access" value={where.access} onChange={(access) => set({ access })} choices={accessChoices} />
                    </div>
                  </Field>
                </div>
              </ServiceForm>
            )}
          </Panel>
        </div>
        <aside className="lg:sticky lg:top-20 lg:self-start">
          <Summary
            template={template}
            vaultName={vaultName}
            newVault={where.vaultId === NEW_VAULT}
            access={where.access}
            bundles={bundleNames}
          />
        </aside>
      </div>
    </>
  );
}

/**
 * The access bundles the service joins: one checkbox row per bundle of the
 * vault and one to create a bundle. All optional; a service can join a
 * bundle later from the bundle's page.
 */
function BundleChoices({
  where,
  set,
  bundles,
  complete,
  vaultChosen,
}: {
  where: Where;
  set: (patch: Partial<Where>) => void;
  /** The vault's bundles, or `undefined` while they load. */
  bundles: AccessBundle[] | undefined;
  /** `bundles` holds every bundle of the vault. */
  complete: boolean;
  vaultChosen: boolean;
}) {
  const toggle = (id: string, checked: boolean) =>
    set({ bundleIds: checked ? [...where.bundleIds, id] : where.bundleIds.filter((b) => b !== id) });
  const newName = where.newBundleName.trim();
  const badName = newName !== "" && !BUNDLE_NAME.test(newName);
  const taken = bundles?.some((b) => b.name === newName) ?? false;
  return (
    <fieldset className="space-y-2">
      <legend className="text-sm font-medium">
        Access bundles <span className="font-normal text-muted-foreground">(optional)</span>
      </legend>
      {!vaultChosen ? (
        <p className="text-sm text-muted-foreground">Choose a vault to see its bundles.</p>
      ) : bundles === undefined ? (
        <Skeleton className="h-24 w-full rounded-lg" />
      ) : (
        <div className="divide-y rounded-lg border">
          {bundles.map((b) => (
            <div key={b.id} className="px-3 py-3">
              <CheckField
                id={`add-bundle-${b.id}`}
                checked={where.bundleIds.includes(b.id)}
                onChange={(checked) => toggle(b.id, checked)}
                hint={`${b.rule_ids.length} service${b.rule_ids.length === 1 ? "" : "s"}${b.description ? ` · ${b.description}` : ""}`}
              >
                <span className="font-mono">{b.name}</span>
              </CheckField>
            </div>
          ))}
          {unlistedBundles(where.bundleIds, bundles).map((id) => (
            <div key={id} className="px-3 py-3">
              <CheckField
                id={`add-bundle-${id}`}
                checked
                onChange={(checked) => toggle(id, checked)}
                hint={complete ? "Not in this vault any more." : "Not among the bundles listed here."}
              >
                An access bundle from the link
              </CheckField>
            </div>
          ))}
          <div className="space-y-2 px-3 py-3">
            <CheckField id="add-bundle-new" checked={where.newBundle} onChange={(newBundle) => set({ newBundle })}>
              New bundle
            </CheckField>
            {where.newBundle && (
              <div className="space-y-1 pl-7">
                <Input
                  id="add-bundle-name"
                  aria-label="New bundle name"
                  aria-invalid={badName || taken}
                  aria-describedby="add-bundle-name-hint"
                  className="font-mono"
                  value={where.newBundleName}
                  onChange={(e) => set({ newBundleName: e.target.value })}
                  placeholder="triage"
                  autoFocus
                />
                <p id="add-bundle-name-hint" className="text-xs text-muted-foreground">
                  {badName
                    ? "Letters, digits, '-', '_' and '.', starting with a letter or digit."
                    : taken
                      ? `This vault already has ${newName}; check it above.`
                      : "Agents start with it by name: --bundle <name>."}
                </p>
              </div>
            )}
          </div>
        </div>
      )}
      <p className="text-xs text-muted-foreground">Agents started with a checked bundle get this service.</p>
    </fieldset>
  );
}

/** A form section's heading, with an optional note on the right. */
function FormSection({ title, aside }: { title: string; aside?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-baseline justify-between gap-2">
      <h2 className="text-base font-semibold">{title}</h2>
      {aside && <span className="text-xs text-muted-foreground">{aside}</span>}
    </div>
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
  bundles,
}: {
  template: ServiceTemplate;
  vaultName: string | undefined;
  newVault: boolean;
  access: AccessPreset;
  /** The bundles it will join; a new one may not be named yet. */
  bundles: { name: string; isNew: boolean }[];
}) {
  const named = bundles.filter((b) => b.name !== "");
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
        <SummaryRow label={bundles.length > 1 ? "Access bundles" : "Access bundle"}>
          {bundles.length === 0 ? (
            <span className="text-muted-foreground">none</span>
          ) : (
            <ul className="space-y-1">
              {bundles.map((b, i) => (
                <li key={b.isNew ? "new" : b.name || i}>
                  {b.name ? <Mono>{b.name}</Mono> : pending}
                  {b.isNew && <span className="text-muted-foreground"> (new)</span>}
                </li>
              ))}
            </ul>
          )}
        </SummaryRow>
      </dl>
      {named.length > 0 && (
        <div className="space-y-2 border-t pt-4">
          <p className="text-xs text-muted-foreground">
            Agents then get a session from{" "}
            {named.length === 1 ? (
              <span className="font-mono text-foreground">{named[0]?.name}</span>
            ) : (
              "any of these bundles"
            )}
            : its token reaches the service, never the secret.
          </p>
        </div>
      )}
    </Panel>
  );
}

/**
 * Sessions already running from the bundles keep the services they were
 * minted with, so they do not reach the new one: say so, and what to do.
 */
function RunningWithout({
  bundles,
  ruleId,
  service,
}: {
  bundles: AccessBundle[];
  ruleId: string | undefined;
  service: string;
}) {
  const ids = bundles.map((b) => b.id).join(",");
  const counts = useLoad(
    () =>
      ruleId
        ? Promise.all(
            bundles.map(async (bundle) => {
              const sessions = await get<Page<ProxySession>>(`/bundles/${bundle.id}/sessions?page_size=100`);
              return { bundle, running: sessionsWithout(sessions.items, ruleId, new Date()) };
            }),
          )
        : Promise.resolve([]),
    [ids, ruleId],
  );
  const stale = (counts.data ?? []).filter((c) => c.running > 0);
  if (stale.length === 0) return null;
  return (
    <div role="status" className="space-y-1 text-warning-strong">
      {stale.map(({ bundle, running }) => (
        <p key={bundle.id}>
          {running === 1 ? "A session" : `${running} sessions`} running from{" "}
          <span className="font-mono">{bundle.name}</span> {running === 1 ? "doesn't" : "don't"} reach {service}: a
          session keeps the services it started with. Start the agent again with a new session.
        </p>
      ))}
    </div>
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
  const bundles = result.bundles ?? [];
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
    ...(bundles.length > 0
      ? bundles.map((b) => (
          <>
            In access bundle <span className="font-mono font-medium">{b.name}</span> ({b.rule_ids.length} service
            {b.rule_ids.length === 1 ? "" : "s"})
          </>
        ))
      : [<span className="text-muted-foreground">Not in an access bundle</span>]),
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
      <RunningWithout bundles={bundles} ruleId={result.rule?.id} service={result.credential?.name ?? template.name} />
      {bundles.length > 0 ? (
        <div className="space-y-2 rounded-md border bg-muted/40 p-4">
          <p className="font-medium">Run an agent with it</p>
          <p className="text-xs text-muted-foreground">
            Create a session from {bundles.length === 1 ? bundles[0]?.name : "one of its bundles"} and give its token
            to the agent. The agent never sees the secret.
          </p>
          <div className="flex flex-wrap gap-2">
            {bundles.map((b) => (
              <Button key={b.id} type="button" variant="outline" size="sm" asChild>
                <a href={`#/bundles/${b.id}/connect`}>{bundles.length === 1 ? "Run an agent" : `Run with ${b.name}`}</a>
              </Button>
            ))}
          </div>
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
