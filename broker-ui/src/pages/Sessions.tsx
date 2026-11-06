// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Proxy sessions across every vault the caller can see, with each
// session's traffic from the audit log.

import { useMemo, useState, type FormEvent, type ReactNode } from "react";
import { Ban, ScrollText, Tags, Timer } from "lucide-react";
import { get, patch, post, type AuditEvent, type Page, type ProxySession, type Vault } from "../api";
import { useAction, useLoad } from "../hooks";
import {
  ConfirmDialog,
  DialogActions,
  Empty,
  ErrorBanner,
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
  Status,
  useConfirm,
  When,
} from "../components/common";
import { Button } from "../components/ui/button-components";
import { PageContainer, PageHeader } from "../components/ui/page-header";
import { Textarea } from "../components/ui/textarea";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../components/ui/table";
import { logRows, type LogRow } from "./sessionLogs";

function outcomeBadge(row: LogRow) {
  switch (row.outcome) {
    case "brokered": {
      const tone = row.status === undefined || row.status < 400 ? "success" : row.status < 500 ? "warning" : "destructive";
      return <Status tone={tone}>brokered{row.status !== undefined ? ` · ${row.status}` : ""}</Status>;
    }
    case "blocked":
      return <Status tone="warning">blocked</Status>;
    case "passthrough":
      return <Status tone="neutral">passthrough</Status>;
    case "error":
      return <Status tone="destructive">error{row.status !== undefined ? ` · ${row.status}` : ""}</Status>;
  }
}

/** The label people set when minting, else the first label, else the id. */
export function sessionLabel(s: ProxySession): string {
  return s.labels.name ?? s.labels.label ?? Object.values(s.labels)[0] ?? `session ${s.id.slice(0, 8)}`;
}

export function sessionStatus(s: ProxySession) {
  if (s.revoked_at) return <Status tone="destructive">Revoked</Status>;
  if (new Date(s.expires_at) <= new Date()) return <Status tone="neutral">Expired</Status>;
  return <Status tone="success">Active</Status>;
}

const isActive = (s: ProxySession) => !s.revoked_at && new Date(s.expires_at) > new Date();

export function Sessions() {
  const [page, setPage] = useState(1);
  const sessions = useLoad(() => get<Page<ProxySession>>(`/sessions?page=${page}`), [page]);
  const vaults = useLoad(() => get<Page<Vault>>("/vaults?page_size=100"), []);
  const names = useMemo(
    () => Object.fromEntries((vaults.data?.items ?? []).map((v) => [v.id, v.name])),
    [vaults.data],
  );
  const [viewing, setViewing] = useState<ProxySession | null>(null);
  const confirm = useConfirm<ProxySession>();
  const action = useAction();

  const revoke = async (s: ProxySession) => {
    await action.run(() => post<void>(`/sessions/${s.id}/revoke`));
    confirm.close();
    setViewing(null);
    sessions.reload();
  };

  return (
    <PageContainer>
      <PageHeader
        title="Sessions"
        description="Short-lived proxy sessions agents use to reach services. Each one is limited to its vault's rules and can be revoked at any time."
      />
      <ErrorBanner error={sessions.error ?? action.error} />
      <Panel>
        {sessions.loading && !sessions.data ? (
          <Loading />
        ) : sessions.data?.items.length === 0 ? (
          <Empty
            icon={Timer}
            title="No sessions yet"
            description={
              <>
                Start an agent with <Mono>credential-broker run --bundle &lt;name&gt; -- &lt;agent-command&gt;</Mono>, or mint
                one from a vault's <span className="font-medium text-foreground">Sessions</span> tab.
              </>
            }
            action={
              <Button type="button" variant="outline" asChild>
                <a href="#/bundles">Open access bundles</a>
              </Button>
            }
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Label</TableHead>
                <TableHead>Vault</TableHead>
                <TableHead className="hidden md:table-cell">Bundle</TableHead>
                <TableHead className="hidden md:table-cell">Created by</TableHead>
                <TableHead>Created</TableHead>
                <TableHead>Expires</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {sessions.data?.items.map((s) => (
                <TableRow key={s.id}>
                  <TableCell>
                    <button
                      type="button"
                      className="text-left font-medium underline-offset-4 hover:underline"
                      title="Open this session's logs"
                      onClick={() => setViewing(s)}
                    >
                      {sessionLabel(s)}
                    </button>
                  </TableCell>
                  <TableCell>
                    <a href={`#/vaults/${s.vault_id}/sessions`} className="hover:underline">
                      {names[s.vault_id] ?? <Mono>{s.vault_id.slice(0, 8)}</Mono>}
                    </a>
                  </TableCell>
                  <TableCell className="hidden md:table-cell">
                    {s.bundle ? s.bundle.name : <span className="text-muted-foreground">—</span>}
                  </TableCell>
                  <TableCell className="hidden text-muted-foreground md:table-cell">{s.created_by}</TableCell>
                  <TableCell className="text-muted-foreground">
                    <Relative at={s.created_at} />
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    <Relative at={s.expires_at} />
                  </TableCell>
                  <TableCell>{sessionStatus(s)}</TableCell>
                  <TableCell>
                    <RowActions>
                      <RowMenu
                        label={sessionLabel(s)}
                        items={[
                          { label: "View logs", icon: ScrollText, onSelect: () => setViewing(s) },
                          ...(isActive(s)
                            ? [{ label: "Revoke session", icon: Ban, onSelect: () => confirm.ask(s), destructive: true }]
                            : []),
                        ]}
                      />
                    </RowActions>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
        <Pager page={sessions.data} onPage={setPage} />
      </Panel>
      <FormDialog
        open={viewing !== null}
        onOpenChange={(o) => {
          if (!o) setViewing(null);
        }}
        wide
        title={viewing ? sessionLabel(viewing) : "Session"}
      >
        {viewing && (
          <SessionDetail
            session={viewing}
            vaultName={names[viewing.vault_id]}
            onRevoke={() => confirm.ask(viewing)}
            onClose={() => setViewing(null)}
            onChanged={(s) => {
              setViewing(s);
              sessions.reload();
            }}
          />
        )}
      </FormDialog>
      <ConfirmDialog
        open={confirm.open}
        onOpenChange={confirm.onOpenChange}
        title={`Revoke "${confirm.target ? sessionLabel(confirm.target) : ""}"?`}
        description="Proxies refuse the session at their next policy refresh. Agents using it lose access immediately after."
        confirmLabel="Revoke session"
        busy={action.busy}
        onConfirm={() => {
          if (confirm.target) void revoke(confirm.target);
        }}
      />
    </PageContainer>
  );
}

function Meta({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="space-y-1">
      <dt className="text-xs font-medium text-muted-foreground">{label}</dt>
      <dd className="text-sm">{children}</dd>
    </div>
  );
}

export function SessionDetail({
  session,
  vaultName,
  onRevoke,
  onClose,
  onChanged,
}: {
  session: ProxySession;
  vaultName?: string;
  onRevoke: () => void;
  onClose: () => void;
  /** Called with the updated record after its labels are saved. */
  onChanged?: (session: ProxySession) => void;
}) {
  const [labelText, setLabelText] = useState<string | null>(null);
  const labelAction = useAction();
  const saveLabels = async (e: FormEvent) => {
    e.preventDefault();
    const labels = Object.fromEntries(
      lines(labelText ?? "").map((l) => {
        const i = l.indexOf("=");
        return i < 0 ? [l.trim(), ""] : [l.slice(0, i).trim(), l.slice(i + 1).trim()];
      }),
    );
    const saved = await labelAction.run(() => patch<ProxySession>(`/sessions/${session.id}`, { labels }));
    if (saved) {
      setLabelText(null);
      onChanged?.(saved);
    }
  };
  const [page, setPage] = useState(1);
  const logs = useLoad(
    () => get<Page<AuditEvent>>(`/audit?session_id=${session.id}&page=${page}&page_size=50`),
    [session.id, page],
  );
  const rows = useMemo(() => logRows(logs.data?.items ?? []), [logs.data]);
  return (
    <div className="space-y-5">
      <dl className="grid grid-cols-2 gap-4 rounded-md border p-4 sm:grid-cols-4">
        <Meta label="Vault">{vaultName ?? <Mono>{session.vault_id.slice(0, 8)}</Mono>}</Meta>
        <Meta label="Access bundle">{session.bundle?.name ?? "none"}</Meta>
        <Meta label="Created">
          <When at={session.created_at} />
        </Meta>
        <Meta label="Expires">
          <Relative at={session.expires_at} />
        </Meta>
        <Meta label="Status">{sessionStatus(session)}</Meta>
        <Meta label="Created by">{session.created_by}</Meta>
        <Meta label="Rules">{session.rule_ids.length}</Meta>
        <Meta label="Request limit">{session.request_limit ?? "none"}</Meta>
        <Meta label="Session">
          <Mono>{session.id.slice(0, 8)}</Mono>
        </Meta>
      </dl>
      {labelText === null ? (
        <div className="flex flex-wrap items-center gap-1.5">
          {Object.entries(session.labels).map(([k, v]) => (
            <Mono key={k}>
              {k}={v}
            </Mono>
          ))}
          {Object.keys(session.labels).length === 0 && <span className="text-sm text-muted-foreground">No labels</span>}
          {onChanged && (
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={() =>
                setLabelText(
                  Object.entries(session.labels)
                    .map(([k, v]) => `${k}=${v}`)
                    .join("\n"),
                )
              }
            >
              <Tags className="size-4" />
              Edit labels
            </Button>
          )}
        </div>
      ) : (
        <form className="space-y-2" onSubmit={saveLabels}>
          <ErrorBanner error={labelAction.error} />
          <Field
            label="Labels"
            htmlFor="session-labels"
            hint="key=value, one per line. This updates the session record; traffic already logged, and traffic still to come, keeps the labels the session was minted with."
          >
            <Textarea
              id="session-labels"
              rows={3}
              className="font-mono"
              value={labelText}
              onChange={(e) => setLabelText(e.target.value)}
            />
          </Field>
          <div className="flex justify-end gap-2">
            <Button type="button" variant="outline" size="sm" onClick={() => setLabelText(null)}>
              Cancel
            </Button>
            <Button type="submit" size="sm" disabled={labelAction.busy}>
              Save labels
            </Button>
          </div>
        </form>
      )}
      <div className="space-y-2">
        <div className="text-sm font-medium">Session logs</div>
        <ErrorBanner error={logs.error} />
        <div className="rounded-md border">
          {logs.loading && !logs.data ? (
            <Loading rows={3} />
          ) : logs.data?.items.length === 0 ? (
            <Empty
              icon={ScrollText}
              title="No traffic yet"
              description="Requests the proxies broker, block or tunnel for this session appear here, with the status each API answered. Proxies report them every few seconds."
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Time</TableHead>
                  <TableHead>Outcome</TableHead>
                  <TableHead>Request</TableHead>
                  <TableHead className="text-right">Time taken</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((r) => (
                  <TableRow key={r.key}>
                    <TableCell className="text-muted-foreground">
                      <Relative at={r.at} />
                    </TableCell>
                    <TableCell>{outcomeBadge(r)}</TableCell>
                    <TableCell className="max-w-80">
                      <Mono className="block truncate">{r.request}</Mono>
                      {r.mcp && <p className="mt-1 text-xs">MCP {r.mcp}</p>}
                      {r.reason && <p className="mt-1 text-xs text-muted-foreground">{r.reason}</p>}
                      {r.substituted && (
                        <p className="mt-1 text-xs text-muted-foreground">Filled in {r.substituted}</p>
                      )}
                      {r.bodySkipped && (
                        <p className="mt-1 text-xs text-muted-foreground">Body not searched: {r.bodySkipped}</p>
                      )}
                    </TableCell>
                    <TableCell className="text-right text-muted-foreground">
                      {r.durationMs !== undefined ? `${r.durationMs} ms` : ""}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
          <Pager page={logs.data} onPage={setPage} />
        </div>
      </div>
      <DialogActions>
        {isActive(session) && (
          <Button type="button" variant="destructive" onClick={onRevoke}>
            Revoke session
          </Button>
        )}
        <Button type="button" variant="outline" onClick={onClose}>
          Close
        </Button>
      </DialogActions>
    </div>
  );
}
