// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Access bundles: named lists of a vault's rules, one per kind of job, that
// sessions are minted from — by the CLI (`run --bundle code-review`) or the
// Mint session dialog. Shown for one vault (its tab) or for every vault
// (the sidebar page).

import { useMemo, useState, type FormEvent, type ReactNode } from "react";
import { Boxes, Pencil, Plus, Terminal, Trash2 } from "lucide-react";
import {
  api,
  get,
  patch,
  post,
  type AccessBundle,
  type CredentialMeta,
  type Page,
  type Rule,
  type StoredTemplate,
  type UserSummary,
  type Vault,
} from "../api";
import { useAction, useLoad } from "../hooks";
import { addServiceHref } from "../addService";
import {
  CheckField,
  ConfirmDialog,
  CopyButton,
  DialogActions,
  Empty,
  ErrorBanner,
  Field,
  FormDialog,
  Loading,
  Pager,
  Panel,
  Relative,
  RowMenu,
  Section,
  SelectField,
  Status,
  Tags,
  useConfirm,
} from "../components/common";
import { Alert, AlertDescription, AlertTitle } from "../components/ui/alert";
import { Button } from "../components/ui/button-components";
import { Input } from "../components/ui/input";
import { PageContainer, PageHeader } from "../components/ui/page-header";
import { Skeleton } from "../components/ui/skeleton";
import { Textarea } from "../components/ui/textarea";
import { ServiceLogo } from "../components/ServiceLogo";
import { PANEL_GRID } from "../components/layout";
import { templateOf } from "./Services";

const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

/** A command with a copy button. `display` shortens what is shown; the copy is always `command`. */
export function CommandSnippet({ command, display }: { command: string; display?: string }) {
  return (
    <div className="flex items-center gap-2">
      <code className="min-w-0 flex-1 break-all rounded-md border bg-background px-3 py-2 font-mono text-xs text-foreground">
        {display ?? command}
      </code>
      <CopyButton value={command} label="Copy command" />
    </div>
  );
}

interface FormState {
  name: string;
  description: string;
  rule_ids: string[];
}

const EMPTY: FormState = { name: "", description: "", rule_ids: [] };

/** The rules and credentials of the given vaults, for naming a bundle's services. */
function useVaultServices(vaultIds: string[]) {
  const key = vaultIds.join(",");
  return useLoad(async () => {
    const per = await Promise.all(
      vaultIds.map((id) =>
        Promise.all([
          get<Page<Rule>>(`/vaults/${id}/rules?page_size=100`),
          get<Page<CredentialMeta>>(`/vaults/${id}/credentials?page_size=100`),
        ]),
      ),
    );
    return {
      rules: per.flatMap(([rules]) => rules.items),
      credentials: per.flatMap(([, credentials]) => credentials.items),
    };
  }, [key]);
}

/** One vault's bundles when `vaultId` is given, every vault's otherwise. */
export function Bundles({ vaultId, user }: { vaultId?: string; user: UserSummary }) {
  const scoped = vaultId !== undefined;
  const [page, setPage] = useState(1);
  const bundles = useLoad(
    () => get<Page<AccessBundle>>(scoped ? `/vaults/${vaultId}/bundles?page=${page}` : `/bundles?page=${page}`),
    [vaultId, page],
  );
  const vaults = useLoad(
    () => (scoped ? Promise.resolve(undefined) : get<Page<Vault>>("/vaults?page_size=100")),
    [scoped],
  );
  const vaultIds = useMemo(
    () => (vaultId ? [vaultId] : [...new Set((bundles.data?.items ?? []).map((b) => b.vault_id))].sort()),
    [vaultId, bundles.data],
  );
  const services = useVaultServices(vaultIds);
  const templates = useLoad(() => get<StoredTemplate[]>("/templates"), []);
  const [editing, setEditing] = useState<AccessBundle | "new" | null>(null);
  const here = vaultId ? `vaults/${vaultId}/bundles` : "bundles";
  const goAdd = (vault?: string, bundle?: string) => {
    window.location.hash = addServiceHref({ vault, bundle, back: here });
  };
  const confirm = useConfirm<AccessBundle>();
  const action = useAction();

  const ruleById = useMemo(() => new Map((services.data?.rules ?? []).map((r) => [r.id, r])), [services.data]);
  const vaultName = (id: string) => vaults.data?.items.find((v) => v.id === id)?.name ?? id.slice(0, 8);
  const noVaults = !scoped && vaults.data?.items.length === 0;

  const [removed, setRemoved] = useState<{ name: string; sessions: number } | null>(null);
  const remove = async (b: AccessBundle) => {
    const result = await action.run(() => api<{ sessions_revoked: number }>("DELETE", `/bundles/${b.id}`));
    confirm.close();
    if (result) setRemoved({ name: b.name, sessions: result.sessions_revoked });
    bundles.reload();
  };

  const canAdd = user.role === "admin";
  const addServiceButton = (variant: "default" | "outline") => (
    <Button
      type="button"
      variant={variant}
      onClick={() => goAdd(vaultId)}
      disabled={!canAdd}
      title={canAdd ? undefined : "Only admins can add services"}
    >
      <Plus />
      Add a service
    </Button>
  );
  const createButton = (
    <Button
      type="button"
      variant="outline"
      onClick={() => setEditing("new")}
      disabled={noVaults}
      title={noVaults ? "Create a vault first, or add a service: it creates one" : undefined}
    >
      <Boxes />
      Create bundle
    </Button>
  );

  const body = (
    <>
      <ErrorBanner error={bundles.error ?? vaults.error ?? services.error ?? action.error} />
      {removed && (
        <Alert>
          <Boxes className="size-4" />
          <AlertTitle>Deleted bundle "{removed.name}"</AlertTitle>
          <AlertDescription>
            {removed.sessions === 0
              ? "No live sessions were using it."
              : `Ended ${removed.sessions} live session${removed.sessions === 1 ? "" : "s"} minted from it; proxies refuse them at their next policy refresh.`}
          </AlertDescription>
        </Alert>
      )}
      <div className="space-y-4">
        {bundles.loading && !bundles.data ? (
          <Panel>
            <Loading />
          </Panel>
        ) : bundles.data?.items.length === 0 ? (
          <Panel>
          <Empty
            icon={Boxes}
            title="No access bundles yet"
            description={
              <>
                Pick a service from the catalogue and it is stored, given a rule and put in a new bundle in one step.
                Then create a session on the bundle's page and start an agent with its token.
              </>
            }
            action={
              <div className="flex flex-wrap justify-center gap-2">
                {addServiceButton("default")}
                {createButton}
              </div>
            }
          />
          </Panel>
        ) : (
          <div className={PANEL_GRID}>
            {bundles.data?.items.map((b) => (
              <BundlePanel
                key={b.id}
                bundle={b}
                vaultName={scoped ? undefined : vaultName(b.vault_id)}
                rules={b.rule_ids.map((id) => ruleById.get(id)).filter((r) => r !== undefined)}
                credentials={services.data?.credentials ?? []}
                templates={templates.data ?? []}
                loading={services.loading && !services.data}
                menu={
                  <RowMenu
                    label={b.name}
                    items={[
                      { label: "Run an agent", icon: Terminal, onSelect: () => (window.location.hash = `#/bundles/${b.id}/connect`) },
                      {
                        label: "Add a service",
                        icon: Plus,
                        onSelect: () => goAdd(b.vault_id, b.id),
                        disabled: !canAdd,
                        reason: "Only admins can add services",
                      },
                      { label: "Edit bundle", icon: Pencil, onSelect: () => setEditing(b) },
                      { label: "Delete bundle", icon: Trash2, onSelect: () => confirm.ask(b), destructive: true },
                    ]}
                  />
                }
              />
            ))}
          </div>
        )}
        {bundles.data && bundles.data.total > bundles.data.page_size && (
          <Panel>
            <Pager page={bundles.data} onPage={setPage} />
          </Panel>
        )}
      </div>
      <FormDialog
        open={editing !== null}
        onOpenChange={(o) => {
          if (!o) setEditing(null);
        }}
        wide
        title={editing === "new" ? "Create an access bundle" : `Edit ${editing?.name ?? ""}`}
        description="Changes apply to sessions minted afterwards. Running sessions keep the rules they started with; revoke them or disable a rule to cut access now."
      >
        {editing !== null && (
          <BundleForm
            vaultId={editing === "new" ? vaultId : editing.vault_id}
            vaults={vaults.data?.items}
            bundle={editing === "new" ? null : editing}
            onCancel={() => setEditing(null)}
            onSaved={() => {
              setEditing(null);
              bundles.reload();
            }}
          />
        )}
      </FormDialog>
      <ConfirmDialog
        open={confirm.open}
        onOpenChange={confirm.onOpenChange}
        title={`Delete bundle "${confirm.target?.name ?? ""}"?`}
        description="Agents can no longer start with it, and the live sessions minted from it are ended: proxies refuse them at their next policy refresh."
        confirmLabel="Delete bundle"
        destructive
        busy={action.busy}
        onConfirm={() => {
          if (confirm.target) void remove(confirm.target);
        }}
      />
    </>
  );

  const actions: ReactNode = (
    <>
      {createButton}
      {addServiceButton("default")}
    </>
  );
  if (scoped) {
    return (
      <Section title="Access bundles" actions={actions}>
        {body}
      </Section>
    );
  }
  return (
    <PageContainer>
      <PageHeader title="Access bundles" actions={actions} />
      {body}
    </PageContainer>
  );
}

/** How many of a bundle's services its panel names. */
const SHOWN = 4;

/** One bundle: what it is for, its first services and when it changed. */
function BundlePanel({
  bundle: b,
  vaultName,
  rules,
  credentials,
  templates,
  loading,
  menu,
}: {
  bundle: AccessBundle;
  /** Shown when the list spans vaults. */
  vaultName?: string;
  rules: Rule[];
  credentials: CredentialMeta[];
  templates: StoredTemplate[];
  loading: boolean;
  menu: ReactNode;
}) {
  const href = `#/bundles/${b.id}`;
  const off = rules.filter((r) => !r.enabled).length;
  const more = b.rule_ids.length - Math.min(rules.length, SHOWN);
  return (
    <Panel className="relative flex flex-col transition-colors focus-within:border-foreground/40 hover:border-foreground/25">
      <div className="flex items-start justify-between gap-2 px-4 pt-3">
        <div className="min-w-0 pt-1">
          <h2 className="truncate font-mono text-base font-semibold">
            {/* The name's link covers the whole panel. */}
            <a href={href} className="after:absolute after:inset-0 after:rounded-lg focus-visible:outline-none">
              {b.name}
            </a>
          </h2>
          {(b.description || vaultName) && (
            <p className="truncate text-xs text-muted-foreground">
              {[b.description, vaultName && `in ${vaultName}`].filter(Boolean).join(" · ")}
            </p>
          )}
        </div>
        <div className="relative z-10 -mr-2">{menu}</div>
      </div>
      <div className="flex-1 px-4 py-3">
        {b.rule_ids.length === 0 ? (
          <p className="py-1 text-sm text-warning-strong">No services yet</p>
        ) : loading ? (
          <Skeleton className="h-16 w-full" />
        ) : (
          <ul className="space-y-1">
            {rules.slice(0, SHOWN).map((r) => {
              const c = credentials.find((x) => x.id === r.credential_id);
              const tpl = c ? templateOf(templates, c) : undefined;
              return (
                <li key={r.id} className="flex min-w-0 items-center gap-3 py-1">
                  <ServiceLogo template={tpl ?? { id: c?.template_id ?? "", kind: "http" }} size="sm" />
                  <span className="min-w-0 truncate text-sm font-medium">{c?.name ?? r.name}</span>
                  {/* The rule is worth naming only when it is not the service's own name. */}
                  {c && r.name !== c.name && <span className="truncate text-xs text-muted-foreground">{r.name}</span>}
                  {!r.enabled && (
                    <span className="ml-auto shrink-0">
                      <Status tone="warning">Turned off</Status>
                    </span>
                  )}
                </li>
              );
            })}
            {more > 0 && <li className="pl-11 text-xs text-muted-foreground">+{more} more</li>}
          </ul>
        )}
      </div>
      <div className="border-t px-4 py-3 text-xs text-muted-foreground">
        {off > 0 ? (
          <span className="text-warning-strong">
            {off} rule{off === 1 ? " is" : "s are"} turned off
          </span>
        ) : (
          <>
            Updated <Relative at={b.updated_at} />
          </>
        )}
      </div>
    </Panel>
  );
}

function BundleForm({
  vaultId: fixedVault,
  vaults,
  bundle,
  onCancel,
  onSaved,
}: {
  /** The bundle's vault; when absent (a new bundle from the sidebar page) the form asks. */
  vaultId: string | undefined;
  vaults: Vault[] | undefined;
  bundle: AccessBundle | null;
  onCancel: () => void;
  onSaved: () => void;
}) {
  const [chosenVault, setChosenVault] = useState(fixedVault ?? "");
  const vaultId = fixedVault ?? chosenVault;
  const services = useLoad(
    () =>
      vaultId
        ? Promise.all([
            get<Page<Rule>>(`/vaults/${vaultId}/rules?page_size=100`),
            get<Page<CredentialMeta>>(`/vaults/${vaultId}/credentials?page_size=100`),
          ])
        : Promise.resolve(undefined),
    [vaultId],
  );
  const rules = services.data?.[0].items;
  const credName = (id: string) => services.data?.[1].items.find((c) => c.id === id)?.name ?? id.slice(0, 8);
  const [form, setForm] = useState<FormState>(
    bundle ? { name: bundle.name, description: bundle.description, rule_ids: bundle.rule_ids } : EMPTY,
  );
  const action = useAction();
  const nameProblem =
    form.name && !NAME.test(form.name.trim())
      ? "Letters, digits, '-', '_' and '.', starting with a letter or digit (up to 64)."
      : null;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const body = { name: form.name.trim(), description: form.description, rule_ids: form.rule_ids };
    const saved = await action.run(() =>
      bundle ? patch<AccessBundle>(`/bundles/${bundle.id}`, body) : post<AccessBundle>(`/vaults/${vaultId}/bundles`, body),
    );
    if (saved) onSaved();
  };

  return (
    <form className="space-y-4" onSubmit={submit}>
      <ErrorBanner error={action.error ?? services.error} />
      {!fixedVault && (
        <Field label="Vault" htmlFor="bundle-vault" hint="A bundle can only hold services from its own vault.">
          <SelectField
            id="bundle-vault"
            value={chosenVault}
            onChange={(v) => {
              setChosenVault(v);
              setForm({ ...form, rule_ids: [] });
            }}
            placeholder="Choose a vault…"
            options={(vaults ?? []).map((v) => ({ value: v.id, label: v.name }))}
          />
        </Field>
      )}
      <div className="space-y-4">
        <Field label="Name" htmlFor="bundle-name" hint={nameProblem ?? "Used on the command line: --bundle <name>."}>
          <Input
            id="bundle-name"
            value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value })}
            placeholder="code-review"
            className="font-mono"
            aria-invalid={nameProblem !== null}
            required
          />
        </Field>
        <Field label="Description" htmlFor="bundle-description" hint="Optional: what the bundle is for.">
          <Textarea
            id="bundle-description"
            rows={2}
            value={form.description}
            onChange={(e) => setForm({ ...form, description: e.target.value })}
            placeholder="Read pull requests and post review comments"
          />
        </Field>
      </div>
      <div className="space-y-3">
        <p className="text-sm font-medium">Services</p>
        {!vaultId ? (
          <p className="text-sm text-muted-foreground">Choose a vault to see its services.</p>
        ) : rules === undefined ? (
          <Skeleton className="h-6 w-full" />
        ) : rules.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            This vault has no services with a rule yet. Create the bundle empty, then use{" "}
            <span className="font-medium text-foreground">Add service</span> on it to pick one from the catalogue.
          </p>
        ) : (
          <div className="max-h-72 space-y-3 overflow-y-auto rounded-md border p-3">
            {rules.map((r) => (
              <CheckField
                key={r.id}
                id={`bundle-rule-${r.id}`}
                checked={form.rule_ids.includes(r.id)}
                onChange={(checked) =>
                  setForm({
                    ...form,
                    rule_ids: checked ? [...form.rule_ids, r.id] : form.rule_ids.filter((id) => id !== r.id),
                  })
                }
                hint={<Tags values={r.allow.hosts} />}
              >
                <span className="font-medium">{credName(r.credential_id)}</span>
                <span className="text-muted-foreground"> · {r.name}</span>
                {!r.enabled && <span className="text-muted-foreground"> (disabled, skipped when minting)</span>}
              </CheckField>
            ))}
          </div>
        )}
      </div>
      <DialogActions>
        <Button type="button" variant="outline" onClick={onCancel}>
          Cancel
        </Button>
        <Button type="submit" disabled={action.busy || nameProblem !== null || !form.name.trim() || !vaultId}>
          {bundle ? "Save bundle" : "Create bundle"}
        </Button>
      </DialogActions>
    </form>
  );
}
