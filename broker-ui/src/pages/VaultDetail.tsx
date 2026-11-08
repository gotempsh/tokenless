// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { useState, type FormEvent } from "react";
import { ListChecks, Plus, Timer, Trash2, Wrench } from "lucide-react";
import {
  api,
  del,
  get,
  patch,
  post,
  type AccessBundle,
  type CredentialMeta,
  type Page,
  type ProxySession,
  type Rule,
  type UserSummary,
  type Vault,
  type VaultOverview,
} from "../api";
import { SettingsSection } from "../components/layout";
import { useAction, useLoad } from "../hooks";
import { SessionHandoff, useHandoffGuard } from "./SessionHandoff";
import { Bundles } from "./Bundles";
import { Services } from "./Services";
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
  lines,
  Loading,
  Mono,
  Pager,
  Panel,
  Relative,
  RowActions,
  RowMenu,
  Section,
  SelectField,
  Status,
  TabSections,
  Tags,
  useConfirm,
} from "../components/common";
import { allowsLabel, EVERYTHING } from "../rules";
import { useActorNames } from "./Audit";
import { SessionTable } from "./Sessions";
import { Button } from "../components/ui/button-components";
import { Input } from "../components/ui/input";
import { PageContainer, PageHeader } from "../components/ui/page-header";
import { Skeleton } from "../components/ui/skeleton";
import { Switch } from "../components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../components/ui/table";
import { Tabs, TabsList, TabsTrigger } from "../components/ui/tabs";
import { Textarea } from "../components/ui/textarea";
import { useBreadcrumbs } from "../breadcrumbs";

export type Tab = "credentials" | "rules" | "bundles" | "sessions" | "settings";
const TABS: { value: Tab; label: string }[] = [
  { value: "credentials", label: "Services" },
  { value: "rules", label: "Rules" },
  { value: "bundles", label: "Access bundles" },
  { value: "sessions", label: "Sessions" },
  { value: "settings", label: "Settings" },
];

export function vaultTab(raw: string | undefined): Tab {
  return TABS.find((t) => t.value === raw)?.value ?? "credentials";
}

interface VaultDeletion {
  credentials: number;
  rules: number;
  bundles: number;
  sessions_revoked: number;
  api_keys_revoked: number;
}

function DeleteVaultForm({ vault, onCancel }: { vault: Vault; onCancel: () => void }) {
  const [typed, setTyped] = useState("");
  const [force, setForce] = useState(false);
  const action = useAction();
  const busySessions = action.error?.includes("live session") ?? false;
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const done = await action.run(() =>
      api<VaultDeletion>("DELETE", `/vaults/${vault.id}${force ? "?force=true" : ""}`),
    );
    if (done) window.location.hash = "#/vaults";
  };
  return (
    <form className="space-y-4" onSubmit={submit} autoComplete="off">
      <ErrorBanner error={action.error} />
      <p className="text-sm text-muted-foreground">
        Its services and their secrets, rules and access bundles are deleted, and the API keys bound to it are revoked.
        The audit trail is kept. This cannot be undone.
      </p>
      <CheckField
        id="vault-delete-force"
        checked={force}
        onChange={setForce}
        hint={
          busySessions
            ? "Agents are using this vault right now. Tick this to end their sessions and delete anyway."
            : "Without this, deletion is refused while any session is live."
        }
      >
        End live sessions
      </CheckField>
      <Field label={`Type "${vault.name}" to confirm`} htmlFor="vault-delete-name">
        <Input id="vault-delete-name" value={typed} onChange={(e) => setTyped(e.target.value)} />
      </Field>
      <DialogActions>
        <Button type="button" variant="outline" onClick={onCancel}>
          Cancel
        </Button>
        <Button type="submit" variant="destructive" disabled={action.busy || typed !== vault.name}>
          Delete vault
        </Button>
      </DialogActions>
    </form>
  );
}

export function VaultDetail({ vaultId, tab, user }: { vaultId: string; tab: Tab; user: UserSummary }) {
  const vault = useLoad(() => get<VaultOverview>(`/vaults/${vaultId}/overview`), [vaultId]);
  const v = vault.data && vault.data.id === vaultId ? vault.data : undefined;
  const [deleting, setDeleting] = useState(false);
  const isAdmin = user.role === "admin";
  useBreadcrumbs([
    { label: "Vaults", href: "#/vaults" },
    { label: v?.name ?? (vault.error ? "Vault" : null), href: `#/vaults/${vaultId}/credentials` },
    { label: TABS.find((t) => t.value === tab)?.label ?? null },
  ]);
  return (
    <PageContainer>
      <PageHeader
        title={v ? v.name : <Skeleton className="h-8 w-48" />}
        verdict={
          v &&
          (v.live_sessions > 0 ? (
            <a href={`#/vaults/${vaultId}/sessions`}>
              <Status tone="success">{v.live_sessions} live</Status>
            </a>
          ) : (
            <Status tone="neutral">Idle</Status>
          ))
        }
        description={
          v &&
          (v.last_request_at ? (
            <>
              Last request <Relative at={v.last_request_at} />
            </>
          ) : (
            "No requests yet"
          ))
        }
      />
      <ErrorBanner error={vault.error} />
      <Tabs
        value={tab}
        onValueChange={(t) => {
          window.location.hash = `#/vaults/${vaultId}/${t}`;
        }}
      >
        <TabsList>
          {TABS.map((t) => (
            <TabsTrigger key={t.value} value={t.value} count={t.value === "credentials" ? v?.service_count : undefined}>
              {t.label}
            </TabsTrigger>
          ))}
        </TabsList>
      </Tabs>
      <TabSections>
        {tab === "credentials" && <Services vaultId={vaultId} user={user} />}
        {tab === "rules" && <Rules vaultId={vaultId} />}
        {tab === "bundles" && <Bundles vaultId={vaultId} user={user} />}
        {tab === "sessions" && <Sessions vaultId={vaultId} user={user} />}
      </TabSections>
      {tab === "settings" && v && <VaultSettings vault={v} isAdmin={isAdmin} onDelete={() => setDeleting(true)} />}
      <FormDialog
        open={deleting}
        onOpenChange={setDeleting}
        title={v ? `Delete vault "${v.name}"?` : "Delete vault"}
        description="Admins only, with a recent sign-in confirmation."
      >
        {v && <DeleteVaultForm vault={v} onCancel={() => setDeleting(false)} />}
      </FormDialog>
    </PageContainer>
  );
}

/** A vault's own facts and the one thing done to the vault itself: deleting it. */
function VaultSettings({ vault, isAdmin, onDelete }: { vault: VaultOverview; isAdmin: boolean; onDelete: () => void }) {
  return (
    <div className="max-w-[1040px]">
      <SettingsSection title="Vault ID">
        <span className="flex items-center gap-1">
          <Mono>{vault.id}</Mono>
          <CopyButton value={vault.id} label="Copy vault ID" iconOnly />
        </span>
      </SettingsSection>
      <SettingsSection title="Created">
        <p className="text-sm">
          <Exact at={vault.created_at} />
        </p>
      </SettingsSection>
      <SettingsSection title="Delete vault" hint="Deletes its services, rules and access bundles. The audit trail is kept.">
        <div className="space-y-2">
          <Button type="button" variant="outline" className="text-destructive" onClick={onDelete} disabled={!isAdmin}>
            <Trash2 />
            Delete vault
          </Button>
          {!isAdmin && <p className="text-xs text-muted-foreground">Only admins can delete a vault.</p>}
        </div>
      </SettingsSection>
    </div>
  );
}

// ----- rules ---------------------------------------------------------------

const EMPTY_RULE = { name: "", credential_id: "", hosts: "", paths: "", methods: "", tools: "" };

/** "every tool", "no tools" or the list, for a rule's MCP tool limit. */
function toolsLabel(tools: string[] | undefined): string {
  if (tools === undefined) return "every tool";
  if (tools.length === 0) return "no tools";
  return tools.join(", ");
}

function ToolsForm({ rule, onCancel, onDone }: { rule: Rule; onCancel: () => void; onDone: () => void }) {
  const [limited, setLimited] = useState(rule.allow.mcp_tools !== undefined);
  const [text, setText] = useState((rule.allow.mcp_tools ?? []).join("\n"));
  const action = useAction();
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const body = limited ? { mcp_tools: lines(text) } : { allow_all_tools: true };
    if (await action.run(() => patch<Rule>(`/rules/${rule.id}`, body))) onDone();
  };
  return (
    <form className="space-y-4" onSubmit={submit}>
      <ErrorBanner error={action.error} />
      <ChoiceCards<"all" | "limited">
        name="tools"
        value={limited ? "limited" : "all"}
        onChange={(v) => setLimited(v === "limited")}
        choices={[
          { value: "all", title: "Every tool", description: "Any tools/call the MCP server offers." },
          {
            value: "limited",
            title: "Only these tools",
            description: "Other tools/call requests are answered with an MCP error naming the tool and never reach the server.",
          },
        ]}
      />
      {limited && (
        <Field
          label="Allowed tools"
          htmlFor="rule-tools"
          hint="One tool name per line, as the server lists it in tools/list. Leave empty to allow none; other MCP methods still work."
        >
          <Textarea
            id="rule-tools"
            rows={5}
            className="font-mono"
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder={"search_issues\nget_file_contents"}
          />
        </Field>
      )}
      <DialogActions>
        <Button type="button" variant="outline" onClick={onCancel}>
          Cancel
        </Button>
        <Button type="submit" disabled={action.busy}>
          Save tools
        </Button>
      </DialogActions>
    </form>
  );
}

function Rules({ vaultId }: { vaultId: string }) {
  const [page, setPage] = useState(1);
  const rules = useLoad(() => get<Page<Rule>>(`/vaults/${vaultId}/rules?page=${page}`), [vaultId, page]);
  const creds = useLoad(() => get<Page<CredentialMeta>>(`/vaults/${vaultId}/credentials?page_size=100`), [vaultId]);
  const [adding, setAdding] = useState(false);
  const [form, setForm] = useState(EMPTY_RULE);
  const [editingTools, setEditingTools] = useState<Rule | null>(null);
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
        mcp_tools: opt(form.tools),
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
                <TableHead>Rule</TableHead>
                <TableHead className={fromWidth.xl}>Hosts</TableHead>
                <TableHead>On</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rules.data?.items.map((r) => (
                <TableRow key={r.id}>
                  <TableCell>
                    <div className="font-medium">{r.name}</div>
                    {credName(r.credential_id) !== r.name && (
                      <div className="text-xs text-muted-foreground">{credName(r.credential_id)}</div>
                    )}
                  </TableCell>
                  <TableCell className={fromWidth.xl}>
                    <Tags values={r.allow.hosts} />
                    {allowsLabel(r) !== EVERYTHING && <p className="mt-1 text-xs text-muted-foreground">{allowsLabel(r)}</p>}
                    {r.allow.mcp_tools !== undefined && (
                      <p className="mt-1 max-w-64 truncate text-xs text-muted-foreground" title={toolsLabel(r.allow.mcp_tools)}>
                        MCP: {toolsLabel(r.allow.mcp_tools)}
                      </p>
                    )}
                  </TableCell>
                  <TableCell>
                    <Switch
                      checked={r.enabled}
                      disabled={action.busy}
                      onCheckedChange={() => void toggle(r)}
                      aria-label={`${r.enabled ? "Turn off" : "Turn on"} ${r.name}`}
                    />
                  </TableCell>
                  <TableCell>
                    <RowActions>
                      <RowMenu
                        label={r.name}
                        items={[
                          { label: "MCP tools", icon: Wrench, onSelect: () => setEditingTools(r) },
                          { label: "Delete rule", icon: Trash2, onSelect: () => confirm.ask(r), destructive: true },
                        ]}
                      />
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
          <div className="space-y-4">
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
          <div className="space-y-4">
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
          <Field
            label="MCP tools"
            htmlFor="rule-new-tools"
            hint="For MCP servers: optional, one tool per line. Leave empty to allow every tool; otherwise other tools/call requests are refused at the proxy."
          >
            <Textarea
              id="rule-new-tools"
              rows={2}
              className="font-mono"
              value={form.tools}
              onChange={(e) => setForm({ ...form, tools: e.target.value })}
              placeholder="search_issues"
            />
          </Field>
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
      <FormDialog
        open={editingTools !== null}
        onOpenChange={(o) => {
          if (!o) setEditingTools(null);
        }}
        title={editingTools ? `MCP tools for "${editingTools.name}"` : "MCP tools"}
        description="Applies to JSON-RPC requests sent to the rule's hosts. Allowing more tools needs a recent sign-in confirmation."
      >
        {editingTools && (
          <ToolsForm
            rule={editingTools}
            onCancel={() => setEditingTools(null)}
            onDone={() => {
              setEditingTools(null);
              rules.reload();
            }}
          />
        )}
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

function Sessions({ vaultId, user }: { vaultId: string; user: UserSummary }) {
  const actors = useActorNames(user);
  const canChange = user.role === "admin" || user.role === "editor";
  const [page, setPage] = useState(1);
  const sessions = useLoad(() => get<Page<ProxySession>>(`/vaults/${vaultId}/sessions?page=${page}`), [vaultId, page]);
  const rules = useLoad(() => get<Page<Rule>>(`/vaults/${vaultId}/rules?page_size=100`), [vaultId]);
  const bundles = useLoad(() => get<Page<AccessBundle>>(`/vaults/${vaultId}/bundles?page_size=100`), [vaultId]);
  const [open, setOpen] = useState(false);
  const [mode, setMode] = useState<"bundle" | "rules">("bundle");
  const [bundleId, setBundleId] = useState("");
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
        ...(mode === "bundle" ? { bundle: bundleId } : { rule_ids: selected }),
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

  const guard = useHandoffGuard();
  const closeMint = (o: boolean) => {
    // Escape, the close button and an outside click land here too: the
    // token is shown only once, so the first try before copying warns.
    if (!o && minted && !guard.mayClose()) return;
    setOpen(o);
    if (!o) {
      setMinted(null);
      guard.reset();
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
      New session
    </Button>
  );

  return (
    <Section
      title="Proxy sessions"
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
            description="Create a session and give its token to an agent."
            action={mintButton}
          />
        ) : (
          <SessionTable
            sessions={sessions.data?.items ?? []}
            actors={actors}
            canRevoke={canChange}
            onRevoke={confirm.ask}
          />
        )}
        <Pager page={sessions.data} onPage={setPage} />
      </Panel>
      <FormDialog
        open={open}
        onOpenChange={closeMint}
        wide
        title={minted ? "Session created" : "New session"}
        description={minted ? undefined : "Choose the rules the agent may use and how long the session lives."}
      >
        {minted ? (
          <SessionHandoff
            minted={minted}
            reaches={minted.session.bundle ? `${minted.session.bundle.name}'s services` : "the rules you chose"}
            guard={guard}
            onDone={() => closeMint(false)}
          />
        ) : (
          <form className="space-y-4" onSubmit={mint}>
            <ErrorBanner error={mintAction.error} />
            <ChoiceCards
              name="mint-mode"
              value={mode}
              onChange={setMode}
              choices={[
                {
                  value: "bundle",
                  title: "From an access bundle",
                  description: "The services of a bundle such as code-review. Disabled rules are skipped.",
                },
                { value: "rules", title: "Pick rules", description: "Choose individual rules for a one-off session." },
              ]}
            />
            {mode === "bundle" ? (
              <Field
                label="Access bundle"
                htmlFor="mint-bundle"
                hint={
                  bundles.data?.items.length === 0 ? (
                    <>
                      No bundles in this vault yet.{" "}
                      <a href={`#/vaults/${vaultId}/bundles`} className="underline" onClick={() => closeMint(false)}>
                        Create one
                      </a>
                      .
                    </>
                  ) : undefined
                }
              >
                <SelectField
                  id="mint-bundle"
                  value={bundleId}
                  onChange={setBundleId}
                  placeholder="Choose…"
                  options={(bundles.data?.items ?? []).map((b) => ({
                    value: b.id,
                    label: `${b.name} (${b.rule_ids.length} rule${b.rule_ids.length === 1 ? "" : "s"})`,
                  }))}
                />
              </Field>
            ) : (
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
            )}
            <div className="space-y-4">
              <Field
                label="Lifetime (minutes)"
                htmlFor="mint-ttl"
                hint="Up to the cap an admin sets in Settings → Session lifetime (60 by default)."
              >
                <Input
                  id="mint-ttl"
                  type="number"
                  min={1}
                  max={7 * 24 * 60}
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
              <Button
                type="submit"
                disabled={mintAction.busy || (mode === "bundle" ? !bundleId : selected.length === 0)}
              >
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
