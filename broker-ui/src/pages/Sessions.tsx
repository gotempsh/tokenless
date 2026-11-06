// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Proxy sessions across every vault the caller can see, with each
// session's traffic from the audit log.

import { useMemo, useState, type ReactNode } from "react";
import { ScrollText, Timer } from "lucide-react";
import { get, post, type AuditEvent, type Page, type ProxySession, type Vault } from "../api";
import { useAction, useLoad } from "../hooks";
import {
  ConfirmDialog,
  DialogActions,
  Empty,
  ErrorBanner,
  FormDialog,
  Loading,
  Mono,
  Pager,
  Panel,
  Relative,
  RowActions,
  Status,
  useConfirm,
  When,
} from "../components/common";
import { Button } from "../components/ui/button-components";
import { PageContainer, PageHeader } from "../components/ui/page-header";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../components/ui/table";

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
                Mint one from a vault's <span className="font-medium text-foreground">Sessions</span> tab, or with an API
                key from your agent's launcher.
              </>
            }
            action={
              <Button type="button" variant="outline" asChild>
                <a href="#/vaults">Open vaults</a>
              </Button>
            }
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Label</TableHead>
                <TableHead>Vault</TableHead>
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
                  <TableCell className="font-medium">{sessionLabel(s)}</TableCell>
                  <TableCell>
                    <a href={`#/vaults/${s.vault_id}/sessions`} className="hover:underline">
                      {names[s.vault_id] ?? <Mono>{s.vault_id.slice(0, 8)}</Mono>}
                    </a>
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
                      <Button type="button" variant="outline" size="sm" onClick={() => setViewing(s)}>
                        <ScrollText />
                        <span className="hidden sm:inline">Logs</span>
                      </Button>
                      {isActive(s) && (
                        <Button type="button" variant="ghost" size="sm" onClick={() => confirm.ask(s)}>
                          Revoke
                        </Button>
                      )}
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
}: {
  session: ProxySession;
  vaultName?: string;
  onRevoke: () => void;
  onClose: () => void;
}) {
  const [page, setPage] = useState(1);
  const logs = useLoad(
    () => get<Page<AuditEvent>>(`/audit?session_id=${session.id}&page=${page}&page_size=25`),
    [session.id, page],
  );
  return (
    <div className="space-y-5">
      <dl className="grid grid-cols-2 gap-4 rounded-md border p-4 sm:grid-cols-4">
        <Meta label="Vault">{vaultName ?? <Mono>{session.vault_id.slice(0, 8)}</Mono>}</Meta>
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
      {Object.keys(session.labels).length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {Object.entries(session.labels).map(([k, v]) => (
            <Mono key={k}>
              {k}={v}
            </Mono>
          ))}
        </div>
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
              description="Requests the proxies inject into, deny or tunnel for this session appear here. Proxies report them every few seconds."
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Time</TableHead>
                  <TableHead>Event</TableHead>
                  <TableHead>Request</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {logs.data?.items.map((e) => (
                  <TableRow key={e.id}>
                    <TableCell className="text-muted-foreground">
                      <Relative at={e.at} />
                    </TableCell>
                    <TableCell>
                      <Status tone={e.outcome === "success" ? "success" : e.outcome === "denied" ? "warning" : "destructive"}>
                        {e.action.replace(/^proxy\./, "")}
                      </Status>
                    </TableCell>
                    <TableCell className="max-w-80">
                      <Mono className="block truncate">
                        {[e.detail.method, e.detail.host, e.detail.path].filter(Boolean).join(" ")}
                      </Mono>
                      {e.detail.reason && <p className="mt-1 text-xs text-muted-foreground">{e.detail.reason}</p>}
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
