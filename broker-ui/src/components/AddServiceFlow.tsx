// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// "Add a service": pick it from the catalogue, choose the vault, how much
// of it agents get and which access bundle it joins, then store the
// credential. One flow, started from the catalogue, a vault or a bundle.

import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { Check, Circle } from "lucide-react";
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
  READ_ONLY_METHODS,
  type AccessPreset,
  type AddServiceApi,
  type AddServicePlan,
  type AddServiceProgress,
  type BundleChoice,
  type CredentialBody,
} from "../addService";
import { useLoad } from "../hooks";
import { CommandSnippet, runCommand } from "../pages/Bundles";
import { ChoiceCards, DialogActions, ErrorBanner, Field, FormDialog, Mono, SelectField, Tags, type Choice } from "./common";
import { ServiceForm, useVariableKeys } from "./ServiceForm";
import { ServiceLogo } from "./ServiceLogo";
import { TemplatePicker } from "./TemplatePicker";
import { Button } from "./ui/button-components";
import { Input } from "./ui/input";
import { Skeleton } from "./ui/skeleton";
import { Textarea } from "./ui/textarea";

/** Where the flow starts: anything given is fixed, the rest is asked. */
export interface AddServiceRequest {
  template?: ServiceTemplate;
  vaultId?: string;
  bundleId?: string;
}

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

type Step = "where" | "credential" | "done";

interface Where {
  vaultId: string;
  newVaultName: string;
  access: AccessPreset;
  bundleMode: BundleChoice["kind"];
  bundleId: string;
  newBundleName: string;
  newBundleDescription: string;
}

function initialWhere(request: AddServiceRequest): Where {
  return {
    vaultId: request.vaultId ?? "",
    newVaultName: "",
    access: "full",
    // Joining an existing bundle is the common case; the step switches to
    // "new" when the vault has none.
    bundleMode: "existing",
    bundleId: request.bundleId ?? "",
    newBundleName: "",
    newBundleDescription: "",
  };
}

/**
 * The whole flow. `request` null means closed; a request without a
 * template opens the catalogue first.
 */
export function AddServiceFlow({
  request,
  onClose,
  user,
  onAdded,
}: {
  request: AddServiceRequest | null;
  onClose: () => void;
  user: UserSummary;
  onAdded?: (result: AddServiceProgress) => void;
}) {
  const isAdmin = user.role === "admin";
  const templates = useLoad(
    () => (request ? get<StoredTemplate[]>("/templates") : Promise.resolve([] as StoredTemplate[])),
    [request !== null],
  );
  const [template, setTemplate] = useState<ServiceTemplate | null>(null);
  const [step, setStep] = useState<Step>("where");
  const [where, setWhere] = useState<Where>(() => initialWhere({}));
  const [result, setResult] = useState<AddServiceProgress | null>(null);
  const progress = useRef<AddServiceProgress>({});

  // Every new request starts clean; nothing from a previous run is resumed.
  useEffect(() => {
    if (!request) return;
    setTemplate(request.template ?? null);
    setStep("where");
    setWhere(initialWhere(request));
    setResult(null);
    progress.current = {};
  }, [request]);

  const picking = request !== null && template === null;
  const close = () => {
    progress.current = {};
    onClose();
  };

  return (
    <>
      <TemplatePicker
        open={picking}
        onOpenChange={(o) => {
          if (!o) close();
        }}
        templates={templates.data ?? []}
        loading={templates.loading && !templates.data}
        onPick={(t) => {
          setTemplate(t.template);
          setStep("where");
        }}
      />
      <FormDialog
        open={request !== null && template !== null}
        onOpenChange={(o) => {
          if (!o) close();
        }}
        wide
        title={template ? (step === "done" ? `${template.name} is ready` : `Add ${template.name}`) : "Add a service"}
        description={stepDescription(step)}
      >
        {request && template && (
          <div className="space-y-5">
            <Stepper step={step} />
            {step === "where" && (
              <WhereStep
                template={template}
                request={request}
                where={where}
                onChange={setWhere}
                isAdmin={isAdmin}
                onChangeTemplate={request.template ? undefined : () => setTemplate(null)}
                onCancel={close}
                onNext={() => setStep("credential")}
              />
            )}
            {step === "credential" && (
              <CredentialStep
                template={template}
                isAdmin={isAdmin}
                where={where}
                onBack={() => setStep("where")}
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
                onSaved={() => {
                  setResult(progress.current);
                  setStep("done");
                  onAdded?.(progress.current);
                }}
              />
            )}
            {step === "done" && result && (
              <DoneStep
                template={template}
                result={result}
                access={where.access}
                onAnother={() => {
                  progress.current = {};
                  setResult(null);
                  setTemplate(null);
                  setWhere((w) => ({
                    ...initialWhere(request),
                    vaultId: result.vault?.id ?? w.vaultId,
                    bundleMode: result.bundle ? "existing" : w.bundleMode,
                    bundleId: result.bundle?.id ?? w.bundleId,
                  }));
                }}
                onClose={close}
              />
            )}
          </div>
        )}
      </FormDialog>
    </>
  );
}

function stepDescription(step: Step): string | undefined {
  switch (step) {
    case "where":
      return "Choose where it lives and what agents may do with it.";
    case "credential":
      return "Secrets are write-only: once saved, nobody (admins included) can read them back.";
    case "done":
      return undefined;
  }
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

const STEPS: { value: Step; label: string }[] = [
  { value: "where", label: "Vault and access" },
  { value: "credential", label: "Credential" },
  { value: "done", label: "Ready to use" },
];

function Stepper({ step }: { step: Step }) {
  const current = STEPS.findIndex((s) => s.value === step);
  return (
    <ol className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs" aria-label="Steps">
      {STEPS.map((s, i) => (
        <li
          key={s.value}
          aria-current={i === current ? "step" : undefined}
          className={i <= current ? "flex items-center gap-1.5 font-medium text-foreground" : "flex items-center gap-1.5 text-muted-foreground"}
        >
          {i < current ? <Check className="size-3.5" /> : <Circle className={i === current ? "size-3.5 fill-foreground" : "size-3.5"} />}
          {s.label}
        </li>
      ))}
    </ol>
  );
}

function TemplateSummary({ template, onChange }: { template: ServiceTemplate; onChange?: () => void }) {
  return (
    <div className="flex items-start gap-3 rounded-md border bg-muted/40 p-3">
      <ServiceLogo template={template} />
      <div className="min-w-0 flex-1 space-y-1.5 text-sm">
        <p className="text-muted-foreground">{template.description}</p>
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs font-medium text-muted-foreground">Hosts</span>
          {template.hosts.length ? <Tags values={template.hosts} /> : <span className="text-xs">set on the next step</span>}
        </div>
      </div>
      {onChange && (
        <Button type="button" variant="ghost" size="sm" onClick={onChange}>
          Change
        </Button>
      )}
    </div>
  );
}

function WhereStep({
  template,
  request,
  where,
  onChange,
  isAdmin,
  onChangeTemplate,
  onCancel,
  onNext,
}: {
  template: ServiceTemplate;
  request: AddServiceRequest;
  where: Where;
  onChange: (w: Where) => void;
  isAdmin: boolean;
  onChangeTemplate?: () => void;
  onCancel: () => void;
  onNext: () => void;
}) {
  const vaults = useLoad(() => get<Page<Vault>>("/vaults?page_size=100"), []);
  const chosenVault = where.vaultId && where.vaultId !== NEW_VAULT ? where.vaultId : "";
  const bundles = useLoad(
    () =>
      chosenVault
        ? get<Page<AccessBundle>>(`/vaults/${chosenVault}/bundles?page_size=100`)
        : Promise.resolve(undefined),
    [chosenVault],
  );
  const bundleItems = useMemo(() => bundles.data?.items ?? [], [bundles.data]);
  const set = (patch: Partial<Where>) => onChange({ ...where, ...patch });

  // A new vault, or one without bundles, has nothing to join: offer a new one.
  const nothingToJoin = (where.vaultId === NEW_VAULT || bundles.data !== undefined) && bundleItems.length === 0;
  useEffect(() => {
    if (nothingToJoin && where.bundleMode === "existing") onChange({ ...where, bundleMode: "new" });
  }, [nothingToJoin, where, onChange]);

  const fixedVault = request.vaultId ? vaults.data?.items.find((v) => v.id === request.vaultId) : undefined;
  const bundleProblem =
    where.bundleMode === "new" && where.newBundleName && !BUNDLE_NAME.test(where.newBundleName.trim())
      ? "Letters, digits, '-', '_' and '.', starting with a letter or digit (up to 64)."
      : null;
  const ready =
    (where.vaultId === NEW_VAULT ? where.newVaultName.trim() !== "" : where.vaultId !== "") &&
    (where.bundleMode !== "existing" || where.bundleId !== "") &&
    (where.bundleMode !== "new" || (where.newBundleName.trim() !== "" && bundleProblem === null));

  const accessChoices: Choice<AccessPreset>[] =
    template.kind === "mcp"
      ? [
          {
            value: "full",
            title: "Every tool",
            description: "All of the server's tools. Limit them afterwards under Rules → Tools.",
          },
        ]
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

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (ready) onNext();
  };

  return (
    <form className="space-y-5" onSubmit={submit}>
      <TemplateSummary template={template} onChange={onChangeTemplate} />
      <ErrorBanner error={vaults.error ?? bundles.error} />
      <Field
        label="Vault"
        htmlFor="add-vault"
        hint={
          request.vaultId
            ? undefined
            : vaults.data?.items.length === 0
              ? isAdmin
                ? "No vaults yet: name one and it is created with the service."
                : "No vaults yet. Ask an admin to create one."
              : "Agents get services from one vault per session."
        }
      >
        {request.vaultId ? (
          fixedVault ? (
            <p className="text-sm font-medium">{fixedVault.name}</p>
          ) : (
            <Skeleton className="h-5 w-40" />
          )
        ) : vaults.loading && !vaults.data ? (
          <Skeleton className="h-9 w-full" />
        ) : (
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
        )}
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
      <div className="space-y-2">
        <p className="text-sm font-medium">What agents may do</p>
        <ChoiceCards<AccessPreset> name="add-access" value={where.access} onChange={(access) => set({ access })} choices={accessChoices} />
      </div>
      <div className="space-y-2">
        <p className="text-sm font-medium">Access bundle</p>
        <ChoiceCards<BundleChoice["kind"]>
          name="add-bundle"
          value={where.bundleMode}
          onChange={(bundleMode) => set({ bundleMode })}
          choices={[
            ...(bundleItems.length > 0
              ? [{ value: "existing" as const, title: "Add to a bundle", description: "Agents started with it get this service too." }]
              : []),
            { value: "new" as const, title: "New bundle", description: "A job agents start with, such as code-review." },
            { value: "none" as const, title: "No bundle", description: "Add it to a bundle later, or pick its rule when minting." },
          ]}
        />
      </div>
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
        <div className="space-y-4">
          <Field label="Bundle name" htmlFor="add-bundle-name" hint={bundleProblem ?? "Used on the command line: --bundle <name>."}>
            <Input
              id="add-bundle-name"
              className="font-mono"
              value={where.newBundleName}
              onChange={(e) => set({ newBundleName: e.target.value })}
              placeholder="code-review"
              aria-invalid={bundleProblem !== null}
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
        </div>
      )}
      <DialogActions>
        <Button type="button" variant="outline" onClick={onCancel}>
          Cancel
        </Button>
        <Button type="submit" disabled={!ready || !isAdmin} title={isAdmin ? undefined : "Only admins can add services"}>
          Continue
        </Button>
      </DialogActions>
    </form>
  );
}

function CredentialStep({
  template,
  isAdmin,
  where,
  onBack,
  onSubmit,
  onSaved,
}: {
  template: ServiceTemplate;
  isAdmin: boolean;
  where: Where;
  onBack: () => void;
  onSubmit: (body: CredentialBody) => Promise<unknown>;
  onSaved: () => void;
}) {
  const variables = useVariableKeys(isAdmin);
  const label =
    where.bundleMode === "new" && where.newBundleName.trim()
      ? `Add to ${where.newBundleName.trim()}`
      : where.bundleMode === "existing"
        ? "Add to bundle"
        : "Add service";
  if (variables.loading && !variables.data) return <Skeleton className="h-40 w-full" />;
  return (
    <>
      <ErrorBanner error={variables.error} />
      <ServiceForm
        template={template}
        variables={variables.data ?? []}
        isAdmin={isAdmin}
        showTemplate={false}
        submitLabel={label}
        onBack={onBack}
        onSubmit={onSubmit}
        onSaved={onSaved}
      />
    </>
  );
}

function DoneStep({
  template,
  result,
  access,
  onAnother,
  onClose,
}: {
  template: ServiceTemplate;
  result: AddServiceProgress;
  access: AccessPreset;
  onAnother: () => void;
  onClose: () => void;
}) {
  const vault = result.vault;
  const items = [
    vault?.created ? <>Created vault <span className="font-medium">{vault.name}</span></> : null,
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
        In access bundle <span className="font-medium">{result.bundle.name}</span> ({result.bundle.rule_ids.length} service
        {result.bundle.rule_ids.length === 1 ? "" : "s"})
      </>
    ) : (
      <span className="text-muted-foreground">Not in an access bundle yet</span>
    ),
  ].filter((x) => x !== null);
  return (
    <div className="space-y-5 text-sm">
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
            <a href="#/api-keys" className="underline underline-offset-4" onClick={onClose}>
              API keys
            </a>
            .
          </p>
        </div>
      ) : (
        <p className="text-muted-foreground">
          Put its rule in an access bundle under{" "}
          <a href="#/bundles" className="underline underline-offset-4" onClick={onClose}>
            Access bundles
          </a>{" "}
          so agents can start with it by name.
        </p>
      )}
      <DialogActions>
        {vault && (
          <Button type="button" variant="outline" asChild>
            <a href={`#/vaults/${vault.id}`} onClick={onClose}>
              Open vault
            </a>
          </Button>
        )}
        <Button type="button" variant="outline" onClick={onAnother}>
          Add another service
        </Button>
        <Button type="button" onClick={onClose}>
          Done
        </Button>
      </DialogActions>
    </div>
  );
}
