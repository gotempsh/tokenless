// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// One access bundle: the services it gives an agent, the sessions minted
// from it, and how to start an agent or a script with it.

import { useMemo, useState, type FormEvent, type ReactNode } from "react";
import {
  Bot,
  Boxes,
  Braces,
  ExternalLink,
  ListPlus,
  Pencil,
  Plus,
  SquareTerminal,
  Terminal,
  Timer,
  Trash2,
  X,
} from "lucide-react";
import {
  api,
  get,
  patch,
  post,
  type AccessBundle,
  type CredentialMeta,
  type MintedSession,
  type Page,
  type ProxySession,
  type Rule,
  type StoredTemplate,
  type UserSummary,
  type Vault,
} from "../api";
import { useAction, useLoad } from "../hooks";
import { addServiceHref } from "../addService";
import { AGENTS, envFile, envReferences, execCommand, runAgentCommand, shellQuote, signedInRunCommand } from "../bundleConnect";
import { claudeMcpCommand, DEFAULT_GATEWAY, mcpClientJson, mcpCredentials, mcpEndpoints, tokenServices, type McpEndpoint } from "../mcpConnect";
import {
  fromWidth,
  CheckField,
  ChoiceCards,
  ConfirmDialog,
  CopyButton,
  DialogActions,
  Empty,
  ErrorBanner,
  Exact,
  Field,
  FormDialog,
  Loading,
  Mono,
  Pager,
  Panel,
  RowActions,
  RowMenu,
  Section,
  Status,
  TabSections,
  Tags,
  useConfirm,
  Relative,
} from "../components/common";
import { cn } from "../lib/utils";
import { LogoTile, ServiceLogo } from "../components/ServiceLogo";
import { Button } from "../components/ui/button-components";
import { Input } from "../components/ui/input";
import { PageContainer, PageHeader } from "../components/ui/page-header";
import { Skeleton } from "../components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../components/ui/table";
import { Tabs, TabsList, TabsTrigger } from "../components/ui/tabs";
import { Textarea } from "../components/ui/textarea";
import { useBreadcrumbs } from "../breadcrumbs";
import { SettingsSection } from "../components/layout";
import { CommandSnippet } from "./Bundles";
import { useActorNames } from "./Audit";
import { NewSessionDialog } from "./NewSession";
import { SessionTable, sessionLabel } from "./Sessions";
import { actorName, type ActorNames } from "../audit";

export type BundleTab = "services" | "sessions" | "connect" | "settings";

const TABS: { value: BundleTab; label: string }[] = [
  { value: "services", label: "Services" },
  { value: "sessions", label: "Sessions" },
  { value: "connect", label: "Run an agent" },
  { value: "settings", label: "Settings" },
];

export function bundleTab(raw: string | undefined): BundleTab {
  return TABS.find((t) => t.value === raw)?.value ?? "services";
}

const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

/** What the bundle gives an agent today, in one glance. */
function verdict(bundle: AccessBundle, rules: Rule[] | undefined) {
  if (bundle.rule_ids.length === 0) return <Status tone="warning">No services</Status>;
  if (!rules) return null;
  const enabled = rules.filter((r) => bundle.rule_ids.includes(r.id) && r.enabled).length;
  if (enabled === 0) return <Status tone="warning">Every service disabled</Status>;
  return <Status tone="success">Ready</Status>;
}

export function BundleDetail({ bundleId, tab, user }: { bundleId: string; tab: BundleTab; user: UserSummary }) {
  const bundle = useLoad(() => get<AccessBundle>(`/bundles/${bundleId}`), [bundleId]);
  const vaultId = bundle.data?.vault_id;
  const vault = useLoad(
    () => (vaultId ? get<Vault>(`/vaults/${vaultId}`) : Promise.resolve(undefined)),
    [vaultId],
  );
  const services = useLoad(
    () =>
      vaultId
        ? Promise.all([
            get<Page<Rule>>(`/vaults/${vaultId}/rules?page_size=100`),
            get<Page<CredentialMeta>>(`/vaults/${vaultId}/credentials?page_size=100`),
            get<StoredTemplate[]>("/templates"),
          ]).then(([rules, credentials, templates]) => ({
            rules: rules.items,
            credentials: credentials.items,
            templates,
          }))
        : Promise.resolve(undefined),
    [vaultId],
  );
  const [editing, setEditing] = useState(false);
  const [including, setIncluding] = useState(false);
  const [creating, setCreating] = useState(false);
  const actors = useActorNames(user);
  const [created, setCreated] = useState(0);
  const confirmDelete = useConfirm<AccessBundle>();
  const deleteAction = useAction();

  const canEdit = user.role === "admin" || user.role === "editor";
  const canAdd = user.role === "admin";
  const here = `bundles/${bundleId}`;
  const goTab = (t: BundleTab) => {
    window.location.hash = `#/${here}/${t}`;
  };
  const goAdd = () => {
    window.location.hash = addServiceHref({ vault: vaultId, bundle: bundleId, back: here });
  };

  const remove = async (b: AccessBundle) => {
    const done = await deleteAction.run(() => api<{ sessions_revoked: number }>("DELETE", `/bundles/${b.id}`));
    confirmDelete.close();
    if (done) window.location.hash = "#/bundles";
  };

  const b = bundle.data;
  useBreadcrumbs([
    { label: "Access bundles", href: "#/bundles" },
    { label: b?.name ?? (bundle.error ? "Access bundle" : null), href: `#/bundles/${bundleId}` },
    { label: TABS.find((t) => t.value === tab)?.label ?? null },
  ]);
  const rulesInVault = services.data?.rules;
  const members = useMemo(
    () => (b && rulesInVault ? b.rule_ids.map((id) => rulesInVault.find((r) => r.id === id)).filter((r) => r !== undefined) : []),
    [b, rulesInVault],
  );
  const memberCredentials = useMemo(() => {
    const ids = new Set(members.filter((r) => r.enabled).map((r) => r.credential_id));
    return (services.data?.credentials ?? []).filter((c) => ids.has(c.id));
  }, [members, services.data]);

  return (
    <PageContainer>
      <PageHeader
        title={b ? <span className="font-mono">{b.name}</span> : <Skeleton className="h-8 w-48" />}
        verdict={b ? verdict(b, rulesInVault) : undefined}
        description={
          b && (
            <>
              {b.description && `${b.description} · `}in{" "}
              <a href={`#/vaults/${b.vault_id}/bundles`} className="text-foreground underline-offset-2 hover:underline">
                {vault.data?.name ?? <Mono>{b.vault_id.slice(0, 8)}</Mono>}
              </a>
            </>
          )
        }
        actions={
          b && (
            <>
              <Button
                type="button"
                variant="outline"
                onClick={goAdd}
                disabled={!canAdd}
                title={canAdd ? undefined : "Only admins can add services"}
              >
                <Plus />
                <span className="hidden sm:inline">Add a service</span>
              </Button>
              <Button type="button" onClick={() => goTab("connect")}>
                <Terminal />
                <span className="hidden sm:inline">Run an agent</span>
              </Button>
            </>
          )
        }
      />
      <ErrorBanner error={bundle.error ?? vault.error ?? services.error ?? deleteAction.error} />
      {b && (
        <>
          <Tabs value={tab} onValueChange={(v) => goTab(bundleTab(v))}>
            <TabsList>
              {TABS.map((t) => (
                <TabsTrigger key={t.value} value={t.value}>
                  {t.label}
                </TabsTrigger>
              ))}
            </TabsList>
          </Tabs>
          <TabSections>
            {b && tab === "services" && (
              <BundleServices
                bundle={b}
                services={services.data}
                loading={services.loading && !services.data}
                canEdit={canEdit}
                canAdd={canAdd}
                onAdd={goAdd}
                onInclude={() => setIncluding(true)}
                onChanged={bundle.reload}
              />
            )}
            {b && tab === "sessions" && (
              <BundleSessions
                bundle={b}
                actors={actors}
                canChange={canEdit}
                refresh={created}
                onCreate={() => setCreating(true)}
              />
            )}
          </TabSections>
          {b && tab === "connect" && (
            <div className="space-y-10">
              <McpConnect
                bundle={b}
                vaultName={vault.data?.name}
                servers={mcpCredentials(memberCredentials, services.data?.templates ?? [])}
                canAdd={canAdd}
                onAdd={goAdd}
              />
              <Connect
                bundle={b}
                vaultName={vault.data?.name}
                credentials={memberCredentials}
                empty={members.length === 0}
                canCreate={canEdit}
                onCreate={() => setCreating(true)}
              />
            </div>
          )}
          {tab === "settings" && (
            <BundleSettings
              bundle={b}
              createdBy={actorName(b.created_by, actors)}
              canEdit={canEdit}
              onEdit={() => setEditing(true)}
              onDelete={() => confirmDelete.ask(b)}
            />
          )}
        </>
      )}
      {!b && bundle.loading && <Loading />}
      {b && (
        <NewSessionDialog
          bundle={b}
          open={creating}
          onOpenChange={setCreating}
          onCreated={() => setCreated((n) => n + 1)}
          isAdmin={user.role === "admin"}
        />
      )}
      <FormDialog open={editing} onOpenChange={setEditing} title={b ? `Edit ${b.name}` : "Edit bundle"}>
        {b && editing && (
          <DetailsForm
            bundle={b}
            onCancel={() => setEditing(false)}
            onSaved={() => {
              setEditing(false);
              bundle.reload();
            }}
          />
        )}
      </FormDialog>
      <FormDialog
        open={including}
        onOpenChange={setIncluding}
        title="Include services already in the vault"
        description="Pick rules the vault already has. Sessions minted afterwards get them; running sessions keep what they started with."
      >
        {b && including && (
          <IncludeForm
            bundle={b}
            rules={rulesInVault ?? []}
            credentials={services.data?.credentials ?? []}
            onCancel={() => setIncluding(false)}
            onSaved={() => {
              setIncluding(false);
              bundle.reload();
            }}
          />
        )}
      </FormDialog>
      <ConfirmDialog
        open={confirmDelete.open}
        onOpenChange={confirmDelete.onOpenChange}
        title={`Delete bundle "${confirmDelete.target?.name ?? ""}"?`}
        description="Agents can no longer start with it, and the live sessions minted from it are ended: proxies refuse them at their next policy refresh. The services and their rules stay in the vault."
        confirmLabel="Delete bundle"
        destructive
        busy={deleteAction.busy}
        onConfirm={() => {
          if (confirmDelete.target) void remove(confirmDelete.target);
        }}
      />
    </PageContainer>
  );
}

/** The bundle's own details and the things done to the bundle itself. */
function BundleSettings({
  bundle,
  createdBy,
  canEdit,
  onEdit,
  onDelete,
}: {
  bundle: AccessBundle;
  createdBy: string;
  canEdit: boolean;
  onEdit: () => void;
  onDelete: () => void;
}) {
  const reason = canEdit ? null : <p className="text-xs text-muted-foreground">Only editors and admins can change bundles.</p>;
  return (
    <div className="max-w-[1040px]">
      <SettingsSection title="Name and description">
        <div className="space-y-3">
          <div>
            <p className="font-mono text-sm">{bundle.name}</p>
            <p className="text-sm text-muted-foreground">{bundle.description || "No description"}</p>
          </div>
          <Button type="button" variant="outline" onClick={onEdit} disabled={!canEdit}>
            <Pencil />
            Edit
          </Button>
          {reason}
        </div>
      </SettingsSection>
      <SettingsSection title="History">
        <div className="space-y-1 text-sm">
          <p>
            Created by {createdBy} · <Exact at={bundle.created_at} />
          </p>
          <p className="text-muted-foreground">
            Updated <Relative at={bundle.updated_at} />
          </p>
        </div>
      </SettingsSection>
      <SettingsSection title="Bundle ID">
        <span className="flex items-center gap-1">
          <Mono>{bundle.id}</Mono>
          <CopyButton value={bundle.id} label="Copy bundle ID" iconOnly />
        </span>
      </SettingsSection>
      <SettingsSection
        title="Delete bundle"
        hint="Ends the live sessions started from it. Its services and their rules stay in the vault."
      >
        <div className="space-y-2">
          <Button type="button" variant="outline" className="text-destructive" onClick={onDelete} disabled={!canEdit}>
            <Trash2 />
            Delete bundle
          </Button>
          {reason}
        </div>
      </SettingsSection>
    </div>
  );
}

// ----- services ---------------------------------------------------------------

interface VaultServices {
  rules: Rule[];
  credentials: CredentialMeta[];
  templates: StoredTemplate[];
}

function allowedLabel(rule: Rule): string {
  const methods = rule.allow.methods.includes("*") ? "Any method" : rule.allow.methods.join(", ");
  const paths = rule.allow.paths.length === 1 && rule.allow.paths[0] === "/*" ? "every path" : rule.allow.paths.join(" ");
  return `${methods} · ${paths}`;
}

function BundleServices({
  bundle,
  services,
  loading,
  canEdit,
  canAdd,
  onAdd,
  onInclude,
  onChanged,
}: {
  bundle: AccessBundle;
  services: VaultServices | undefined;
  loading: boolean;
  canEdit: boolean;
  canAdd: boolean;
  onAdd: () => void;
  onInclude: () => void;
  onChanged: () => void;
}) {
  const confirm = useConfirm<Rule>();
  const action = useAction();
  const others = (services?.rules ?? []).filter((r) => !bundle.rule_ids.includes(r.id));
  const removeRule = async (rule: Rule) => {
    // Read the bundle just before writing it, so rules added meanwhile are kept.
    const done = await action.run(async () => {
      const current = await get<AccessBundle>(`/bundles/${bundle.id}`);
      return patch<AccessBundle>(`/bundles/${bundle.id}`, {
        rule_ids: current.rule_ids.filter((id) => id !== rule.id),
      });
    });
    confirm.close();
    if (done) onChanged();
  };
  const credential = (id: string) => services?.credentials.find((c) => c.id === id);
  const template = (c: CredentialMeta | undefined) =>
    c ? services?.templates.find((t) => t.template.id === c.template_id && t.template.version === c.template_version)?.template : undefined;

  const includeButton = (
    <Button
      type="button"
      variant="outline"
      onClick={onInclude}
      disabled={!canEdit || others.length === 0}
      title={
        !canEdit
          ? "Only editors and admins can change bundles"
          : others.length === 0
            ? "Every rule in the vault is already in this bundle"
            : undefined
      }
    >
      <ListPlus />
      Include existing
    </Button>
  );

  return (
    <Section
      title="Services"
      actions={bundle.rule_ids.length > 0 ? includeButton : undefined}
    >
      <ErrorBanner error={action.error} />
      <Panel>
        {loading ? (
          <Loading />
        ) : bundle.rule_ids.length === 0 ? (
          <Empty
            icon={Boxes}
            title="No services in this bundle"
            description="Add one from the catalogue (it is stored in the vault, given a rule and put here in one step), or include a rule the vault already has."
            action={
              <div className="flex flex-wrap justify-center gap-2">
                <Button type="button" onClick={onAdd} disabled={!canAdd} title={canAdd ? undefined : "Only admins can add services"}>
                  <Plus />
                  Add a service
                </Button>
                {includeButton}
              </div>
            }
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Service</TableHead>
                <TableHead className={fromWidth.xl}>Allowed</TableHead>
                <TableHead className={fromWidth["4xl"]}>Hosts</TableHead>
                <TableHead className={fromWidth["3xl"]}>Placeholders</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {bundle.rule_ids.map((id) => {
                const rule = services?.rules.find((r) => r.id === id);
                if (!rule) {
                  return (
                    <TableRow key={id}>
                      <TableCell colSpan={6} className="text-muted-foreground">
                        Rule <Mono>{id.slice(0, 8)}</Mono> is not visible to you.
                      </TableCell>
                    </TableRow>
                  );
                }
                const c = credential(rule.credential_id);
                const t = template(c);
                return (
                  <TableRow key={id}>
                    <TableCell>
                      <div className="flex items-center gap-3">
                        <ServiceLogo template={t ?? (c ? { id: c.template_id, kind: "http" } : undefined)} size="sm" />
                        <div className="min-w-0 [overflow-wrap:anywhere]">
                          <div className="font-medium">{c?.name ?? "Unknown service"}</div>
                          <div className="text-xs text-muted-foreground">
                            {t?.name ?? c?.template_id} · rule {rule.name}
                          </div>
                          <div className="text-xs text-muted-foreground @xl:hidden">{allowedLabel(rule)}</div>
                        </div>
                      </div>
                    </TableCell>
                    <TableCell className={cn(fromWidth.xl, "text-sm")}>
                      {allowedLabel(rule)}
                      {rule.allow.mcp_tools !== undefined && (
                        <div className="text-xs text-muted-foreground">
                          MCP tools: {rule.allow.mcp_tools.length === 0 ? "none" : rule.allow.mcp_tools.join(", ")}
                        </div>
                      )}
                    </TableCell>
                    <TableCell className={fromWidth["4xl"]}>
                      <Tags values={rule.allow.hosts} />
                    </TableCell>
                    <TableCell className={fromWidth["3xl"]}>
                      {c && c.substitutions.length > 0 ? (
                        <div className="flex flex-col gap-1">
                          {c.substitutions.map((s) => (
                            <Mono key={s.placeholder}>{`cb://${c.name}/${s.field}`}</Mono>
                          ))}
                        </div>
                      ) : (
                        <span className="text-xs text-muted-foreground">none</span>
                      )}
                    </TableCell>
                    <TableCell>
                      {rule.enabled ? <Status tone="success">Enabled</Status> : <Status tone="neutral">Disabled</Status>}
                    </TableCell>
                    <TableCell>
                      <RowActions>
                        <RowMenu
                          label={c?.name ?? rule.name}
                          items={[
                            {
                              label: "Open in vault",
                              icon: ExternalLink,
                              onSelect: () => {
                                window.location.hash = `#/vaults/${bundle.vault_id}/rules`;
                              },
                            },
                            {
                              label: "Remove from bundle",
                              icon: X,
                              onSelect: () => confirm.ask(rule),
                              destructive: true,
                              disabled: !canEdit,
                              reason: "Only editors and admins can change bundles",
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
      </Panel>
      <ConfirmDialog
        open={confirm.open}
        onOpenChange={confirm.onOpenChange}
        title={`Remove "${confirm.target ? (credential(confirm.target.credential_id)?.name ?? confirm.target.name) : ""}" from ${bundle.name}?`}
        description="Sessions minted from the bundle afterwards no longer get it. The service and its rule stay in the vault, and running sessions keep what they started with; revoke them to cut access now."
        confirmLabel="Remove from bundle"
        destructive
        busy={action.busy}
        onConfirm={() => {
          if (confirm.target) void removeRule(confirm.target);
        }}
      />
    </Section>
  );
}

function IncludeForm({
  bundle,
  rules,
  credentials,
  onCancel,
  onSaved,
}: {
  bundle: AccessBundle;
  rules: Rule[];
  credentials: CredentialMeta[];
  onCancel: () => void;
  onSaved: () => void;
}) {
  const others = rules.filter((r) => !bundle.rule_ids.includes(r.id));
  const [picked, setPicked] = useState<string[]>([]);
  const action = useAction();
  const credName = (id: string) => credentials.find((c) => c.id === id)?.name ?? id.slice(0, 8);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const saved = await action.run(async () => {
      const current = await get<AccessBundle>(`/bundles/${bundle.id}`);
      return patch<AccessBundle>(`/bundles/${bundle.id}`, {
        rule_ids: [...new Set([...current.rule_ids, ...picked])],
      });
    });
    if (saved) onSaved();
  };
  return (
    <form className="space-y-4" onSubmit={submit}>
      <ErrorBanner error={action.error} />
      <div className="max-h-80 space-y-3 overflow-y-auto rounded-md border p-3">
        {others.map((r) => (
          <CheckField
            key={r.id}
            id={`include-${r.id}`}
            checked={picked.includes(r.id)}
            onChange={(on) => setPicked(on ? [...picked, r.id] : picked.filter((id) => id !== r.id))}
            hint={<Tags values={r.allow.hosts} />}
          >
            <span className="font-medium">{credName(r.credential_id)}</span>
            <span className="text-muted-foreground"> · {r.name}</span>
            {!r.enabled && <span className="text-muted-foreground"> (disabled, skipped when minting)</span>}
          </CheckField>
        ))}
      </div>
      <DialogActions>
        <Button type="button" variant="outline" onClick={onCancel}>
          Cancel
        </Button>
        <Button type="submit" disabled={action.busy || picked.length === 0}>
          {picked.length > 1 ? `Include ${picked.length} services` : "Include service"}
        </Button>
      </DialogActions>
    </form>
  );
}

function DetailsForm({ bundle, onCancel, onSaved }: { bundle: AccessBundle; onCancel: () => void; onSaved: () => void }) {
  const [name, setName] = useState(bundle.name);
  const [description, setDescription] = useState(bundle.description);
  const action = useAction();
  const nameProblem =
    name && !NAME.test(name.trim()) ? "Letters, digits, '-', '_' and '.', starting with a letter or digit (up to 64)." : null;
  const renamed = name.trim() !== bundle.name;
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const saved = await action.run(() =>
      patch<AccessBundle>(`/bundles/${bundle.id}`, { name: name.trim(), description }),
    );
    if (saved) onSaved();
  };
  return (
    <form className="space-y-4" onSubmit={submit}>
      <ErrorBanner error={action.error} />
      <Field
        label="Name"
        htmlFor="bundle-detail-name"
        hint={
          nameProblem ??
          (renamed
            ? `Scripts that start agents with --bundle ${bundle.name} stop working until they use the new name.`
            : "Used on the command line: --bundle <name>.")
        }
      >
        <Input
          id="bundle-detail-name"
          value={name}
          onChange={(e) => setName(e.target.value)}
          className="font-mono"
          aria-invalid={nameProblem !== null}
          required
        />
      </Field>
      <Field label="Description" htmlFor="bundle-detail-description" hint="Optional: what the bundle is for.">
        <Textarea
          id="bundle-detail-description"
          rows={3}
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          placeholder="Read pull requests and post review comments"
        />
      </Field>
      <DialogActions>
        <Button type="button" variant="outline" onClick={onCancel}>
          Cancel
        </Button>
        <Button type="submit" disabled={action.busy || nameProblem !== null || !name.trim()}>
          Save
        </Button>
      </DialogActions>
    </form>
  );
}

// ----- sessions ---------------------------------------------------------------

function BundleSessions({
  bundle,
  actors,
  canChange,
  refresh,
  onCreate,
}: {
  bundle: AccessBundle;
  actors: ActorNames;
  canChange: boolean;
  /** Changes when a session was created elsewhere on the page. */
  refresh: number;
  onCreate: () => void;
}) {
  const [page, setPage] = useState(1);
  const sessions = useLoad(
    () => get<Page<ProxySession>>(`/bundles/${bundle.id}/sessions?page=${page}`),
    [bundle.id, page, refresh],
  );
  const confirm = useConfirm<ProxySession>();
  const action = useAction();
  const revoke = async (s: ProxySession) => {
    await action.run(() => post<ProxySession>(`/sessions/${s.id}/revoke`));
    confirm.close();
    sessions.reload();
  };
  const newButton = (
    <Button
      type="button"
      onClick={onCreate}
      disabled={!canChange}
      title={canChange ? undefined : "Only editors and admins can create sessions"}
    >
      <Plus />
      New session
    </Button>
  );
  return (
    <Section title="Sessions" actions={newButton}>
      <ErrorBanner error={sessions.error ?? action.error} />
      <Panel>
        {sessions.loading && !sessions.data ? (
          <Loading />
        ) : sessions.data?.items.length === 0 ? (
          <Empty
            icon={Timer}
            title="No sessions yet"
            description="Create a session and give its token to an agent. It reaches this bundle's services until it expires or you revoke it."
            action={newButton}
          />
        ) : (
          <SessionTable
            sessions={sessions.data?.items ?? []}
            actors={actors}
            showBundle={false}
            canRevoke={canChange}
            onRevoke={confirm.ask}
          />
        )}
        <Pager page={sessions.data} onPage={setPage} />
      </Panel>
      <ConfirmDialog
        open={confirm.open}
        onOpenChange={confirm.onOpenChange}
        title={`Revoke "${confirm.target ? sessionLabel(confirm.target) : ""}"?`}
        description="Proxies refuse the session at their next policy refresh, so whoever holds its token loses access within seconds."
        confirmLabel="Revoke session"
        busy={action.busy}
        onConfirm={() => {
          if (confirm.target) void revoke(confirm.target);
        }}
      />
    </Section>
  );
}

// ----- connect ----------------------------------------------------------------

function Step({ n, title, children }: { n: number; title: string; children: ReactNode }) {
  return (
    <li className="flex gap-4">
      <span className="flex size-7 shrink-0 items-center justify-center rounded-full border text-xs font-semibold">{n}</span>
      <div className="min-w-0 flex-1 space-y-2">
        <h3 className="text-sm font-medium">{title}</h3>
        {children}
      </div>
    </li>
  );
}

function FileSnippet({ name, contents }: { name: string; contents: string }) {
  return (
    <div className="rounded-md border">
      <div className="flex items-center justify-between gap-2 border-b px-3 py-1.5">
        <Mono>{name}</Mono>
        <CopyButton value={contents} label={`Copy ${name}`} />
      </div>
      <pre className="overflow-x-auto px-3 py-2 font-mono text-xs">{contents}</pre>
    </div>
  );
}

interface McpToken {
  token: string;
  session: ProxySession;
  endpoints: McpEndpoint[];
}

type McpClient = "claude" | "json";

function McpConnect({
  bundle,
  vaultName,
  servers,
  canAdd,
  onAdd,
}: {
  bundle: AccessBundle;
  vaultName?: string;
  servers: CredentialMeta[];
  canAdd: boolean;
  onAdd: () => void;
}) {
  const action = useAction();
  const [minted, setMinted] = useState<McpToken | null>(null);
  const [client, setClient] = useState<McpClient>("claude");
  const create = () =>
    action.run(async () => {
      const m = await post<MintedSession>(`/vaults/${bundle.vault_id}/sessions`, {
        bundle: bundle.id,
        longest: true,
        labels: { client: "mcp" },
      });
      setMinted({ token: m.token, session: m.session, endpoints: mcpEndpoints(await tokenServices(m.token)) });
    });
  const cli = `tokenless mcp${vaultName ? ` --vault ${shellQuote(vaultName)}` : ""} --bundle ${shellQuote(bundle.name)}`;
  return (
    <Section
      title="Connect an MCP client"
      description="Add this to your MCP client's configuration."
    >
      {servers.length === 0 ? (
        <div className="flex flex-col gap-3 rounded-md border border-dashed p-3 text-sm text-muted-foreground sm:flex-row sm:items-center sm:justify-between">
          <span>
            This bundle has no MCP server. Add one, such as GitHub MCP, Supabase MCP or a Custom MCP server, and MCP
            clients can use its tools.
          </span>
          <Button
            type="button"
            variant="outline"
            onClick={onAdd}
            disabled={!canAdd}
            title={canAdd ? undefined : "Only admins can add services"}
          >
            <Plus className="size-4" /> Add an MCP server
          </Button>
        </div>
      ) : (
        <Panel className="p-5">
          <ol className="space-y-6">
            <Step n={1} title="Create a token for the client">
              <p className="text-sm text-muted-foreground">
                One token covers {servers.map((c) => c.name).join(", ")}. It lasts as long as{" "}
                <a href="#/settings" className="underline">
                  Settings
                </a>{" "}
                allow; end it on the Sessions tab to cut the client off.
              </p>
              <ErrorBanner error={action.error} />
              <div className="flex flex-wrap items-center gap-2">
                <Button type="button" onClick={create} disabled={action.busy}>
                  {minted ? "Create another token" : "Create a token"}
                </Button>
                <span className="text-xs text-muted-foreground">
                  or from a terminal: <Mono>{cli}</Mono>
                </span>
              </div>
            </Step>
            <Step n={2} title="Add the servers to the client">
              {!minted ? (
                <p className="text-sm text-muted-foreground">The commands appear here once the token exists.</p>
              ) : minted.endpoints.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  The token reaches no enabled MCP server with a fixed host. Enable the servers' rules, or give a Custom
                  MCP server a host without wildcards.
                </p>
              ) : (
                <>
                  <ChoiceCards
                    name="mcp-client"
                    value={client}
                    onChange={setClient}
                    columns={2}
                    choices={[
                      {
                        value: "claude",
                        title: "Claude Code",
                        description: <Mono>claude mcp add</Mono>,
                        icon: <LogoTile logo="anthropic" fallback={Bot} />,
                      },
                      {
                        value: "json",
                        title: "Another client",
                        description: "An mcpServers JSON block",
                        icon: <LogoTile logo={undefined} fallback={Braces} />,
                      },
                    ]}
                  />
                  {client === "claude" ? (
                    minted.endpoints.map((e) => <CommandSnippet key={e.name} command={claudeMcpCommand(e, minted.token)} />)
                  ) : (
                    <FileSnippet name="mcpServers" contents={mcpClientJson(minted.endpoints, minted.token)} />
                  )}
                  <p className="text-xs text-muted-foreground">
                    Shown once: copy it now. Valid until <Exact at={minted.session.expires_at} />. The proxy serves the
                    gateway at <Mono>{DEFAULT_GATEWAY}</Mono>; for a proxy on another machine, use its{" "}
                    <Mono>--mcp-listen</Mono> address.
                  </p>
                </>
              )}
            </Step>
          </ol>
        </Panel>
      )}
    </Section>
  );
}

function Connect({
  bundle,
  vaultName,
  credentials,
  empty,
  canCreate,
  onCreate,
}: {
  bundle: AccessBundle;
  vaultName?: string;
  credentials: CredentialMeta[];
  empty: boolean;
  canCreate: boolean;
  onCreate: () => void;
}) {
  const [agent, setAgent] = useState(AGENTS[0]?.id ?? "claude");
  const command = AGENTS.find((a) => a.id === agent)?.command ?? "<agent-command>";
  const refs = useMemo(() => envReferences(credentials), [credentials]);
  return (
    <Section
      title={`Run an agent with ${bundle.name}`}
      description="Run this where the agent runs."
    >
      {empty && (
        <p className="rounded-md border border-dashed p-3 text-sm text-muted-foreground">
          This bundle has no services yet, so an agent started with it reaches nothing through the broker. Add one on the
          Services tab first.
        </p>
      )}
      <Panel className="p-5">
        <ol className="space-y-6">
          <Step n={1} title="Create a session for the agent">
            <p className="text-sm text-muted-foreground">
              You get the token and the commands to paste on the agent's machine. The session reaches this bundle's
              services until it expires or you revoke it, and every request it makes is logged on the session's page.
            </p>
            <Button
              type="button"
              onClick={onCreate}
              disabled={!canCreate}
              title={canCreate ? undefined : "Only editors and admins can create sessions"}
            >
              <Plus />
              New session
            </Button>
          </Step>
          <Step n={2} title="Start the agent">
            <ChoiceCards
              name="bundle-agent"
              value={agent}
              onChange={setAgent}
              columns={3}
              choices={AGENTS.map((a) => ({
                value: a.id,
                title: a.label,
                description: a.id === "other" ? "Any program that honours HTTPS_PROXY" : <Mono>{a.command}</Mono>,
                icon: <LogoTile logo={a.logo} fallback={SquareTerminal} />,
              }))}
            />
            <CommandSnippet command="export TOKENLESS_SESSION_TOKEN=v4.public..." />
            <CommandSnippet command={runAgentCommand(command)} />
            <p className="text-xs text-muted-foreground">
              Signed in with <Mono>tokenless login</Mono> on this machine? Skip the token:{" "}
              <Mono>{signedInRunCommand(bundle.name, command, vaultName)}</Mono> creates a session and ends it when the
              agent exits.
            </p>
          </Step>
          <Step n={3} title="Teach the agent how the broker works">
            <p className="text-sm text-muted-foreground">
              The skill tells the agent how to see what it can reach, hand a tool a placeholder instead of a key, and read
              the proxy's 403, 407 and 429 answers instead of working around them.
            </p>
            <CommandSnippet command="tokenless skill --install" />
          </Step>
          <Step n={4} title="Or run a script that reads keys from its environment">
            {refs.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                None of this bundle's services has a placeholder yet. Give one a placeholder on the vault's{" "}
                <a href={`#/vaults/${bundle.vault_id}/credentials`} className="underline">
                  Services
                </a>{" "}
                tab, then fill a variable with <Mono>NAME=cb://&lt;service&gt;/&lt;field&gt;</Mono>.
              </p>
            ) : (
              <>
                <p className="text-sm text-muted-foreground">
                  Each <Mono>cb://</Mono> reference becomes the service's placeholder, which the proxy swaps for the
                  secret on the service's hosts. The script never holds the secret.
                </p>
                <CommandSnippet command={execCommand(refs)} />
                <p className="text-sm text-muted-foreground">
                  Or keep the references in a file next to the script and commit it:
                </p>
                <FileSnippet name=".env.broker" contents={envFile(refs)} />
                <CommandSnippet command="tokenless exec --env-file .env.broker -- ./script.sh" />
              </>
            )}
          </Step>
          <Step n={5} title="Or keep a session open for agents you start yourself">
            <CommandSnippet command="tokenless session start --env-file ./agent.env" />
            <p className="text-xs text-muted-foreground">
              With the session's token in <Mono>TOKENLESS_SESSION_TOKEN</Mono>. Then <Mono>. ./agent.env</Mono> in the
              agent's shell; the agents never see the token. Ctrl-C closes the port.
            </p>
          </Step>
        </ol>
      </Panel>
    </Section>
  );
}
