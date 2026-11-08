// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// One session: whether it still works, what it was given, every request
// it made and everything done to it, from the audit log.

import { useMemo, useState, type FormEvent, type ReactNode } from "react";
import { Ban, History, ScrollText, Tags } from "lucide-react";
import { ApiError, get, patch, post, type AuditEvent, type Page, type ProxySession, type UserSummary, type Vault } from "../api";
import { actorLabel, actorName, sessionHistoryPhrase, type ActorNames } from "../audit";
import { useBreadcrumbs } from "../breadcrumbs";
import { useAction, useLoad, usePolling } from "../hooks";
import {
  ConfirmDialog,
  DialogActions,
  Empty,
  ErrorBanner,
  Exact,
  Field,
  FormDialog,
  fromWidth,
  lines,
  Loading,
  Mono,
  Pager,
  Panel,
  RowMenu,
  useConfirm,
  When,
} from "../components/common";
import { cn } from "../lib/utils";
import { Button } from "../components/ui/button-components";
import { PageContainer, PageHeader } from "../components/ui/page-header";
import { Skeleton } from "../components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../components/ui/table";
import { Tabs, TabsList, TabsTrigger } from "../components/ui/tabs";
import { Textarea } from "../components/ui/textarea";
import { useActorNames } from "./Audit";
import { logRows } from "./sessionLogs";
import { isActive, outcomeBadge, sessionLabel, sessionStatus } from "./Sessions";

export type SessionTab = "requests" | "history";

const TABS: { value: SessionTab; label: string }[] = [
  { value: "requests", label: "Requests" },
  { value: "history", label: "History" },
];

export function sessionTab(raw: string | undefined): SessionTab {
  return raw === "history" ? raw : "requests";
}

/** Proxies report traffic every few seconds; a live session's page follows it. */
const REFRESH_MS = 5_000;

export function SessionPage({ sessionId, tab, user }: { sessionId: string; tab: SessionTab; user: UserSummary }) {
  // A session that does not exist loads as null, not as an error.
  const session = useLoad(
    () =>
      get<ProxySession>(`/sessions/${sessionId}`).catch((e: unknown) => {
        if (e instanceof ApiError && e.problem.status === 404) return null;
        throw e;
      }),
    [sessionId],
  );
  const s = session.data && session.data.id === sessionId ? session.data : undefined;
  const missing = session.data === null && !session.loading;
  const vaultId = s?.vault_id;
  const vault = useLoad(
    () => (vaultId ? get<Vault>(`/vaults/${vaultId}`) : Promise.resolve(undefined)),
    [vaultId],
  );
  const names = useActorNames(user);
  const [editing, setEditing] = useState(false);
  const confirm = useConfirm<ProxySession>();
  const action = useAction();
  const canChange = user.role === "admin" || user.role === "editor";
  const active = s ? isActive(s) : false;

  useBreadcrumbs([
    { label: "Sessions", href: "#/sessions" },
    { label: s ? sessionLabel(s) : session.error || missing ? "Session" : null, href: `#/sessions/${sessionId}` },
    { label: TABS.find((t) => t.value === tab)?.label ?? null },
  ]);

  const revoke = async (target: ProxySession) => {
    await action.run(() => post<ProxySession>(`/sessions/${target.id}/revoke`));
    confirm.close();
    session.reload();
  };

  return (
    <PageContainer>
      <PageHeader
        title={s ? sessionLabel(s) : session.error || missing ? "Session" : <Skeleton className="h-8 w-48" />}
        verdict={s ? sessionStatus(s) : undefined}
        actions={
          s && (
            <RowMenu
              label={sessionLabel(s)}
              items={[
                {
                  label: "Edit labels",
                  icon: Tags,
                  onSelect: () => setEditing(true),
                  disabled: !canChange,
                  reason: "Only editors and admins can change sessions",
                },
                ...(active
                  ? [
                      {
                        label: "Revoke session",
                        icon: Ban,
                        onSelect: () => confirm.ask(s),
                        destructive: true,
                        disabled: !canChange,
                        reason: "Only editors and admins can revoke sessions",
                      },
                    ]
                  : []),
              ]}
            />
          )
        }
      />
      <ErrorBanner error={session.error ?? action.error} />
      {missing && (
        <Panel>
          <Empty
            icon={History}
            title="No such session"
            description="It may belong to a vault you can't see."
            action={
              <Button type="button" variant="outline" asChild>
                <a href="#/sessions">All sessions</a>
              </Button>
            }
          />
        </Panel>
      )}
      {s && (
        <dl className="grid grid-cols-2 gap-4 rounded-lg border p-4 md:grid-cols-5">
          <SessionFact label="Access bundle">
            {s.bundle ? (
              <a href={`#/bundles/${s.bundle.id}`} className="text-primary hover:text-primary/80">
                {s.bundle.name}
              </a>
            ) : (
              `${s.rule_ids.length} rule${s.rule_ids.length === 1 ? "" : "s"}`
            )}
          </SessionFact>
          <SessionFact label="Vault">{vault.data?.name ?? <Mono>{s.vault_id.slice(0, 8)}</Mono>}</SessionFact>
          <SessionFact label="Created by">{actorName(s.created_by, names)}</SessionFact>
          <SessionFact label={s.revoked_at ? "Revoked" : new Date(s.expires_at) <= new Date() ? "Expired" : "Expires"}>
            <When at={s.revoked_at ?? s.expires_at} />
          </SessionFact>
          <SessionFact label="Request limit">{s.request_limit ?? "None"}</SessionFact>
        </dl>
      )}
      {s && (
        <Tabs value={tab} onValueChange={(v) => (window.location.hash = `#/sessions/${sessionId}/${sessionTab(v)}`)}>
          <TabsList>
            {TABS.map((t) => (
              <TabsTrigger key={t.value} value={t.value}>
                {t.label}
              </TabsTrigger>
            ))}
          </TabsList>
        </Tabs>
      )}
      {s && tab === "requests" && <Requests session={s} live={active} />}
      {s && tab === "history" && <SessionHistory session={s} names={names} />}
      {!s && session.loading && <Loading />}
      <FormDialog open={editing} onOpenChange={setEditing} title="Edit labels">
        {s && editing && (
          <LabelsForm
            session={s}
            onCancel={() => setEditing(false)}
            onSaved={() => {
              setEditing(false);
              session.reload();
            }}
          />
        )}
      </FormDialog>
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
    </PageContainer>
  );
}

function SessionFact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0 space-y-1">
      <dt className="text-xs font-medium text-muted-foreground">{label}</dt>
      <dd className="truncate text-sm">{children}</dd>
    </div>
  );
}

function Requests({ session, live }: { session: ProxySession; live: boolean }) {
  const [page, setPage] = useState(1);
  const logs = useLoad(
    () => get<Page<AuditEvent>>(`/audit?session_id=${session.id}&action_prefix=proxy.&page=${page}&page_size=50`),
    [session.id, page],
  );
  usePolling(logs.reload, REFRESH_MS, live && page === 1);
  const rows = useMemo(() => logRows(logs.data?.items ?? []), [logs.data]);
  return (
    <Panel>
      <ErrorBanner error={logs.error} />
      {logs.loading && !logs.data ? (
        <Loading rows={3} />
      ) : rows.length === 0 ? (
        <Empty
          icon={ScrollText}
          title="No requests yet"
          description={
            live
              ? "Requests made with this session appear here a few seconds after a proxy handles them."
              : "This session made no requests."
          }
        />
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className={fromWidth.xl}>Time</TableHead>
              <TableHead>Request</TableHead>
              <TableHead>Result</TableHead>
              <TableHead className={cn(fromWidth.lg, "text-right")}>Took</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map((r) => (
              <TableRow key={r.key}>
                <TableCell className={cn(fromWidth.xl, "text-muted-foreground")}>
                  <When at={r.at} />
                </TableCell>
                <TableCell className="max-w-96">
                  <Mono className="block truncate">{r.request}</Mono>
                  <p className="mt-1 text-xs text-muted-foreground @xl:hidden">
                    <When at={r.at} />
                  </p>
                  {r.mcp && <p className="mt-1 text-xs">MCP {r.mcp}</p>}
                  {r.reason && <p className="mt-1 text-xs text-muted-foreground">{r.reason}</p>}
                  {r.substituted && <p className="mt-1 text-xs text-muted-foreground">Filled in {r.substituted}</p>}
                  {r.bodySkipped && (
                    <p className="mt-1 text-xs text-muted-foreground">Body not searched: {r.bodySkipped}</p>
                  )}
                </TableCell>
                <TableCell>{outcomeBadge(r)}</TableCell>
                <TableCell className={cn(fromWidth.lg, "text-right tabular-nums text-muted-foreground")}>
                  {r.durationMs !== undefined ? `${r.durationMs} ms` : ""}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
      <Pager page={logs.data} onPage={setPage} />
    </Panel>
  );
}

function SessionHistory({ session, names }: { session: ProxySession; names: ActorNames }) {
  const [page, setPage] = useState(1);
  const events = useLoad(
    () => get<Page<AuditEvent>>(`/audit?session_id=${session.id}&action_prefix=session.&page=${page}&page_size=50`),
    [session.id, page, session.revoked_at],
  );
  return (
    <Panel>
      <ErrorBanner error={events.error} />
      {events.loading && !events.data ? (
        <Loading rows={3} />
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Time</TableHead>
              <TableHead>What happened</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {events.data?.items.map((e) => (
              <TableRow key={e.id}>
                <TableCell className="w-32 text-muted-foreground">
                  <When at={e.at} />
                </TableCell>
                <TableCell>
                  <span className="font-medium">{actorLabel(e, names)}</span> {sessionHistoryPhrase(e)}
                  {e.action === "session.mint" && e.detail.expires_at && (
                    <p className="mt-1 text-xs text-muted-foreground">
                      Valid until <Exact at={e.detail.expires_at} />
                    </p>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
      <Pager page={events.data} onPage={setPage} />
    </Panel>
  );
}

function LabelsForm({
  session,
  onCancel,
  onSaved,
}: {
  session: ProxySession;
  onCancel: () => void;
  onSaved: (s: ProxySession) => void;
}) {
  const [text, setText] = useState(
    Object.entries(session.labels)
      .map(([k, v]) => `${k}=${v}`)
      .join("\n"),
  );
  const action = useAction();
  const save = async (e: FormEvent) => {
    e.preventDefault();
    const labels = Object.fromEntries(
      lines(text).map((l) => {
        const i = l.indexOf("=");
        return i < 0 ? [l.trim(), ""] : [l.slice(0, i).trim(), l.slice(i + 1).trim()];
      }),
    );
    const saved = await action.run(() => patch<ProxySession>(`/sessions/${session.id}`, { labels }));
    if (saved) onSaved(saved);
  };
  return (
    <form className="space-y-4" onSubmit={save}>
      <ErrorBanner error={action.error} />
      <Field
        label="Labels"
        htmlFor="session-labels"
        hint="key=value, one per line; name=… is the session's name. Requests keep the labels the session was created with."
      >
        <Textarea
          id="session-labels"
          rows={4}
          className="font-mono"
          value={text}
          onChange={(e) => setText(e.target.value)}
        />
      </Field>
      <DialogActions>
        <Button type="button" variant="outline" onClick={onCancel}>
          Cancel
        </Button>
        <Button type="submit" disabled={action.busy}>
          Save labels
        </Button>
      </DialogActions>
    </form>
  );
}
