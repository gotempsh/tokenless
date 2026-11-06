// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Access bundles: named lists of a vault's rules, one per kind of job, that
// sessions are minted from — by the CLI (`run --bundle code-review`) or the
// Mint session dialog.

import { useMemo, useState, type FormEvent } from "react";
import { Boxes, Pencil, Plus, Terminal, Trash2 } from "lucide-react";
import { api, get, patch, post, type AccessBundle, type CredentialMeta, type Page, type Rule } from "../api";
import { useAction, useLoad } from "../hooks";
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
  Mono,
  Pager,
  Panel,
  RowActions,
  Section,
  Status,
  Tags,
  useConfirm,
  When,
} from "../components/common";
import { Alert, AlertDescription, AlertTitle } from "../components/ui/alert";
import { Button } from "../components/ui/button-components";
import { Input } from "../components/ui/input";
import { Skeleton } from "../components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../components/ui/table";
import { Textarea } from "../components/ui/textarea";

const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

/** The command that runs an agent behind a session port for `bundle`. */
export function runCommand(bundle: string, vault?: string): string {
  const vaultFlag = vault ? ` --vault ${vault}` : "";
  return `credential-broker run${vaultFlag} --bundle ${bundle} -- <agent-command>`;
}

export function CommandSnippet({ command }: { command: string }) {
  return (
    <div className="flex items-center gap-2">
      <code className="min-w-0 flex-1 break-all rounded-md border bg-background px-3 py-2 font-mono text-xs text-foreground">
        {command}
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

export function Bundles({ vaultId }: { vaultId: string }) {
  const [page, setPage] = useState(1);
  const bundles = useLoad(() => get<Page<AccessBundle>>(`/vaults/${vaultId}/bundles?page=${page}`), [vaultId, page]);
  const rules = useLoad(() => get<Page<Rule>>(`/vaults/${vaultId}/rules?page_size=100`), [vaultId]);
  const creds = useLoad(() => get<Page<CredentialMeta>>(`/vaults/${vaultId}/credentials?page_size=100`), [vaultId]);
  const [editing, setEditing] = useState<AccessBundle | "new" | null>(null);
  const [running, setRunning] = useState<AccessBundle | null>(null);
  const confirm = useConfirm<AccessBundle>();
  const action = useAction();

  const ruleById = useMemo(() => new Map((rules.data?.items ?? []).map((r) => [r.id, r])), [rules.data]);
  const credName = (id: string) => creds.data?.items.find((c) => c.id === id)?.name ?? id.slice(0, 8);

  const [removed, setRemoved] = useState<{ name: string; sessions: number } | null>(null);
  const remove = async (b: AccessBundle) => {
    const result = await action.run(() => api<{ sessions_revoked: number }>("DELETE", `/bundles/${b.id}`));
    confirm.close();
    if (result) setRemoved({ name: b.name, sessions: result.sessions_revoked });
    bundles.reload();
  };

  const addButton = (
    <Button type="button" onClick={() => setEditing("new")}>
      <Plus />
      Create bundle
    </Button>
  );

  return (
    <Section
      title="Access bundles"
      description="A bundle is the list of services an agent gets for one kind of job, such as code-review with GitHub and Slack. Agents start with one by name, and each run gets its own session."
      actions={addButton}
    >
      <ErrorBanner error={bundles.error ?? action.error} />
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
      <Panel>
        {bundles.loading && !bundles.data ? (
          <Loading />
        ) : bundles.data?.items.length === 0 ? (
          <Empty
            icon={Boxes}
            title="No access bundles yet"
            description={
              <>
                Group the rules an agent needs, then start it with{" "}
                <Mono>{runCommand("code-review").replace(" -- <agent-command>", " -- claude")}</Mono>.
              </>
            }
            action={addButton}
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Services</TableHead>
                <TableHead className="hidden md:table-cell">Updated</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {bundles.data?.items.map((b) => (
                <TableRow key={b.id}>
                  <TableCell>
                    <div className="font-medium">{b.name}</div>
                    {b.description && <p className="text-xs text-muted-foreground">{b.description}</p>}
                  </TableCell>
                  <TableCell>
                    {b.rule_ids.length === 0 ? (
                      <Status tone="warning">no rules</Status>
                    ) : (
                      <BundleRules ids={b.rule_ids} ruleById={ruleById} credName={credName} />
                    )}
                  </TableCell>
                  <TableCell className="hidden text-muted-foreground md:table-cell">
                    <When at={b.updated_at} />
                  </TableCell>
                  <TableCell>
                    <RowActions>
                      <Button type="button" variant="outline" size="sm" onClick={() => setRunning(b)}>
                        <Terminal />
                        <span className="hidden sm:inline">Run an agent</span>
                      </Button>
                      <Button
                        type="button"
                        variant="ghost"
                        size="sm"
                        aria-label={`Edit ${b.name}`}
                        onClick={() => setEditing(b)}
                      >
                        <Pencil />
                      </Button>
                      <Button
                        type="button"
                        variant="ghost"
                        size="sm"
                        className="text-destructive hover:text-destructive"
                        aria-label={`Delete ${b.name}`}
                        onClick={() => confirm.ask(b)}
                      >
                        <Trash2 />
                      </Button>
                    </RowActions>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
        <Pager page={bundles.data} onPage={setPage} />
      </Panel>
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
            vaultId={vaultId}
            bundle={editing === "new" ? null : editing}
            rules={rules.data?.items}
            credName={credName}
            onCancel={() => setEditing(null)}
            onSaved={() => {
              setEditing(null);
              bundles.reload();
            }}
          />
        )}
      </FormDialog>
      <FormDialog
        open={running !== null}
        onOpenChange={(o) => {
          if (!o) setRunning(null);
        }}
        wide
        title={running ? `Run an agent with ${running.name}` : "Run an agent"}
        description="The CLI mints a session from the bundle, opens a local session port in front of the proxy, starts the agent pointed at it with the broker CA trusted, renews the session while the agent runs and ends it when the agent exits."
      >
        {running && <RunInstructions bundle={running} onClose={() => setRunning(null)} />}
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
    </Section>
  );
}

function BundleRules({
  ids,
  ruleById,
  credName,
}: {
  ids: string[];
  ruleById: Map<string, Rule>;
  credName: (id: string) => string;
}) {
  return (
    <div className="flex flex-wrap gap-1">
      {ids.map((id) => {
        const rule = ruleById.get(id);
        if (!rule) return <Mono key={id}>{id.slice(0, 8)}</Mono>;
        return (
          <span
            key={id}
            className="inline-flex items-center gap-1 rounded border bg-muted/40 px-1.5 py-0.5 text-xs"
            title={rule.allow.hosts.join(", ")}
          >
            {credName(rule.credential_id)}
            <span className="text-muted-foreground">· {rule.name}</span>
            {!rule.enabled && <span className="text-muted-foreground">(disabled)</span>}
          </span>
        );
      })}
    </div>
  );
}

function BundleForm({
  vaultId,
  bundle,
  rules,
  credName,
  onCancel,
  onSaved,
}: {
  vaultId: string;
  bundle: AccessBundle | null;
  rules: Rule[] | undefined;
  credName: (id: string) => string;
  onCancel: () => void;
  onSaved: () => void;
}) {
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
      <ErrorBanner error={action.error} />
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
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
            rows={1}
            value={form.description}
            onChange={(e) => setForm({ ...form, description: e.target.value })}
            placeholder="Read pull requests and post review comments"
          />
        </Field>
      </div>
      <div className="space-y-3">
        <p className="text-sm font-medium">Rules</p>
        {rules === undefined ? (
          <Skeleton className="h-6 w-full" />
        ) : rules.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            This vault has no rules yet.{" "}
            <a href={`#/vaults/${vaultId}/rules`} className="underline" onClick={onCancel}>
              Add a rule
            </a>{" "}
            for a service, then put it in a bundle.
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
        <Button type="submit" disabled={action.busy || nameProblem !== null || !form.name.trim()}>
          {bundle ? "Save bundle" : "Create bundle"}
        </Button>
      </DialogActions>
    </form>
  );
}

function RunInstructions({ bundle, onClose }: { bundle: AccessBundle; onClose: () => void }) {
  return (
    <div className="space-y-5 text-sm">
      <ol className="list-decimal space-y-4 pl-5">
        <li className="space-y-2">
          <p>
            Create a <span className="font-medium">session_issuer</span> API key for this vault under{" "}
            <a href="#/api-keys" className="underline" onClick={onClose}>
              API keys
            </a>{" "}
            and give it to the agent's machine:
          </p>
          <CommandSnippet command="export CREDENTIAL_BROKER_API_KEY=cbk_..." />
          <p className="text-xs text-muted-foreground">
            Off this machine, also set <Mono>CREDENTIAL_BROKER_URL</Mono> to the console's address and{" "}
            <Mono>CREDENTIAL_BROKER_PROXY_ADDRESS</Mono> to a proxy's <Mono>host:port</Mono>.
          </p>
        </li>
        <li className="space-y-2">
          <p>Start the agent behind a session port:</p>
          <CommandSnippet command={runCommand(bundle.name)} />
          <p className="text-xs text-muted-foreground">
            The agent sees a plain <Mono>HTTPS_PROXY=http://127.0.0.1:&lt;port&gt;</Mono> and never the session token.
            Add <Mono>--ca-fingerprint</Mono> with the fingerprint from the{" "}
            <a href="#/proxies" className="underline" onClick={onClose}>
              Proxies
            </a>{" "}
            page to refuse an unexpected CA.
          </p>
        </li>
        <li className="space-y-2">
          <p>Or keep a session port open for agents you start yourself:</p>
          <CommandSnippet command={`credential-broker session start --bundle ${bundle.name} --env-file ./agent.env`} />
          <p className="text-xs text-muted-foreground">
            Then <Mono>source ./agent.env</Mono> in the agent's shell. Ctrl-C ends the session.
          </p>
        </li>
      </ol>
      <DialogActions>
        <Button type="button" onClick={onClose}>
          Done
        </Button>
      </DialogActions>
    </div>
  );
}
