// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// One session: what it is, whether it still works, and its whole log:
// every request it made and everything done to it, from the audit log.

import { useMemo, useState, type FormEvent, type ReactNode } from "react";
import { Ban, Check, History, Pencil, ScrollText, Tags, X } from "lucide-react";
import { ApiError, get, patch, post, type AuditEvent, type Page, type ProxySession, type UserSummary, type Vault } from "../api";
import { actorLabel, actorName, sessionHistoryPhrase, type ActorNames } from "../audit";
import { useBreadcrumbs } from "../breadcrumbs";
import { useAction, useLoad, usePolling } from "../hooks";
import {
  ConfirmDialog,
  CopyButton,
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
  Relative,
  RowMenu,
  rowOpener,
  Section,
  Tags as TagList,
  useConfirm,
  When,
} from "../components/common";
import { cn } from "../lib/utils";
import { Button } from "../components/ui/button-components";
import { Input } from "../components/ui/input";
import { PageContainer, PageHeader } from "../components/ui/page-header";
import { Skeleton } from "../components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../components/ui/table";
import { Textarea } from "../components/ui/textarea";
import { EventDetails, useActorNames } from "./Audit";
import { sessionLog, type SessionLogEntry } from "./sessionLogs";
import { isActive, outcomeBadge, sessionLabel, sessionStatus } from "./Sessions";

/** Proxies report traffic every few seconds; a live session's page follows it. */
const REFRESH_MS = 5_000;

export function SessionPage({ sessionId, user }: { sessionId: string; user: UserSummary }) {
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
  const [editingLabels, setEditingLabels] = useState(false);
  const confirm = useConfirm<ProxySession>();
  const action = useAction();
  const canChange = user.role === "admin" || user.role === "editor";
  const active = s ? isActive(s) : false;

  useBreadcrumbs([
    { label: "Sessions", href: "#/sessions" },
    { label: s ? sessionLabel(s) : session.error || missing ? "Session" : null },
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
                  onSelect: () => setEditingLabels(true),
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
        <SessionInfo
          session={s}
          vaultName={vault.data?.name}
          names={names}
          canChange={canChange}
          onChanged={session.reload}
          onEditLabels={() => setEditingLabels(true)}
        />
      )}
      {s && <SessionLogs session={s} names={names} live={active} />}
      {!s && session.loading && <Loading />}
      <FormDialog open={editingLabels} onOpenChange={setEditingLabels} title="Edit labels">
        {s && editingLabels && (
          <LabelsForm
            session={s}
            onCancel={() => setEditingLabels(false)}
            onSaved={() => {
              setEditingLabels(false);
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

// ----- info -------------------------------------------------------------------

function InfoItem({ label, children, className }: { label: string; children: ReactNode; className?: string }) {
  return (
    <div className={cn("min-w-0 space-y-1", className)}>
      <dt className="text-xs font-medium text-muted-foreground">{label}</dt>
      <dd className="text-sm [overflow-wrap:anywhere]">{children}</dd>
    </div>
  );
}

/** When the session stopped working, or will. */
function endFact(s: ProxySession): { label: string; at: string } {
  if (s.revoked_at) return { label: "Revoked", at: s.revoked_at };
  if (new Date(s.expires_at) <= new Date()) return { label: "Expired", at: s.expires_at };
  return { label: "Expires", at: s.expires_at };
}

function SessionInfo({
  session: s,
  vaultName,
  names,
  canChange,
  onChanged,
  onEditLabels,
}: {
  session: ProxySession;
  vaultName?: string;
  names: ActorNames;
  canChange: boolean;
  onChanged: () => void;
  onEditLabels: () => void;
}) {
  const end = endFact(s);
  const others = Object.entries(s.labels).filter(([k]) => k !== "name");
  return (
    <Panel>
      <dl className="grid grid-cols-2 gap-x-6 gap-y-4 p-4 md:grid-cols-4">
        <InfoItem label="Created by">{actorName(s.created_by, names)}</InfoItem>
        <InfoItem label="Access bundle">
          {s.bundle ? (
            <a href={`#/bundles/${s.bundle.id}`} className="text-primary hover:text-primary/80">
              {s.bundle.name}
            </a>
          ) : (
            `${s.rule_ids.length} rule${s.rule_ids.length === 1 ? "" : "s"}, chosen one by one`
          )}
        </InfoItem>
        <InfoItem label="Vault">{vaultName ?? <Mono>{s.vault_id.slice(0, 8)}</Mono>}</InfoItem>
        <InfoItem label="Request limit">{s.request_limit ?? "None"}</InfoItem>
        <InfoItem label="Created">
          <Exact at={s.created_at} />
        </InfoItem>
        <InfoItem label={end.label}>
          <Exact at={end.at} />
          <span className="text-muted-foreground">
            {" "}
            (<Relative at={end.at} />)
          </span>
        </InfoItem>
        <InfoItem label="Session ID" className="col-span-2">
          <span className="flex items-center gap-1">
            <Mono>{s.id}</Mono>
            <CopyButton value={s.id} label="Copy session ID" iconOnly />
          </span>
        </InfoItem>
      </dl>
      <div className="grid gap-4 border-t p-4 md:grid-cols-2">
        <NameField session={s} canChange={canChange} onChanged={onChanged} />
        <div className="min-w-0 space-y-1">
          <div className="text-xs font-medium text-muted-foreground">Labels</div>
          <div className="flex flex-wrap items-center gap-2 text-sm">
            {others.length > 0 ? (
              <TagList values={others.map(([k, v]) => `${k}=${v}`)} />
            ) : (
              <span className="text-muted-foreground">None</span>
            )}
            {canChange && (
              <Button type="button" variant="ghost" size="sm" onClick={onEditLabels}>
                Edit
              </Button>
            )}
          </div>
        </div>
      </div>
    </Panel>
  );
}

/** The session's name, editable in place. It is the `name` label. */
function NameField({ session, canChange, onChanged }: { session: ProxySession; canChange: boolean; onChanged: () => void }) {
  const [draft, setDraft] = useState<string | null>(null);
  const action = useAction();
  const save = async (e: FormEvent) => {
    e.preventDefault();
    const name = (draft ?? "").trim();
    const labels = { ...session.labels };
    if (name) labels.name = name;
    else delete labels.name;
    const saved = await action.run(() => patch<ProxySession>(`/sessions/${session.id}`, { labels }));
    if (saved) {
      setDraft(null);
      onChanged();
    }
  };
  if (draft !== null) {
    return (
      <form className="min-w-0 space-y-1" onSubmit={save}>
        <label htmlFor="session-name-edit" className="text-xs font-medium text-muted-foreground">
          Name
        </label>
        <div className="flex items-center gap-1">
          <Input
            id="session-name-edit"
            autoFocus
            value={draft}
            maxLength={256}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Escape") setDraft(null);
            }}
          />
          <Button type="submit" variant="ghost" size="icon" aria-label="Save name" disabled={action.busy}>
            <Check />
          </Button>
          <Button type="button" variant="ghost" size="icon" aria-label="Cancel" onClick={() => setDraft(null)}>
            <X />
          </Button>
        </div>
        <ErrorBanner error={action.error} />
      </form>
    );
  }
  return (
    <div className="min-w-0 space-y-1">
      <div className="text-xs font-medium text-muted-foreground">Name</div>
      <div className="flex items-center gap-1 text-sm">
        <span className={session.labels.name ? undefined : "text-muted-foreground"}>
          {session.labels.name ?? "None"}
        </span>
        {canChange && (
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="size-7"
            aria-label="Rename session"
            title="Rename"
            onClick={() => setDraft(session.labels.name ?? "")}
          >
            <Pencil className="size-3.5" />
          </Button>
        )}
      </div>
    </div>
  );
}

// ----- logs -------------------------------------------------------------------

function SessionLogs({ session, names, live }: { session: ProxySession; names: ActorNames; live: boolean }) {
  const [page, setPage] = useState(1);
  const events = useLoad(
    () => get<Page<AuditEvent>>(`/audit?session_id=${session.id}&page=${page}&page_size=50`),
    [session.id, page, session.revoked_at, JSON.stringify(session.labels)],
  );
  usePolling(events.reload, REFRESH_MS, live && page === 1);
  const log = useMemo(() => sessionLog(events.data?.items ?? []), [events.data]);
  const [open, setOpen] = useState<SessionLogEntry | null>(null);
  return (
    <Section
      title="Logs"
      actions={live ? <span className="text-xs text-muted-foreground">Updates every few seconds</span> : undefined}
    >
      <Panel>
        <ErrorBanner error={events.error} />
        {events.loading && !events.data ? (
          <Loading rows={4} />
        ) : log.length === 0 ? (
          <Empty
            icon={ScrollText}
            title="Nothing logged yet"
            description="Requests made with this session appear here a few seconds after a proxy handles them."
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className={fromWidth.xl}>Time</TableHead>
                <TableHead>What happened</TableHead>
                <TableHead>Result</TableHead>
                <TableHead className={cn(fromWidth.lg, "text-right")}>Took</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {log.map((entry) => (
                <LogLine key={entryKey(entry)} entry={entry} names={names} onOpen={() => setOpen(entry)} />
              ))}
            </TableBody>
          </Table>
        )}
        <Pager page={events.data} onPage={setPage} />
      </Panel>
      <FormDialog
        open={open !== null}
        onOpenChange={(o) => {
          if (!o) setOpen(null);
        }}
        wide
        title={open?.kind === "request" ? open.row.request : "Log entry"}
      >
        {open && (
          <div className="space-y-6">
            {(open.kind === "request" ? open.row.events : [open.event]).map((e, i) => (
              <div key={e.id} className={cn(i > 0 && "border-t pt-6")}>
                <EventDetails event={e} names={names} />
              </div>
            ))}
            <DialogActions>
              <Button type="button" variant="outline" onClick={() => setOpen(null)}>
                Close
              </Button>
            </DialogActions>
          </div>
        )}
      </FormDialog>
    </Section>
  );
}

function entryKey(entry: SessionLogEntry): string {
  return entry.kind === "request" ? entry.row.key : entry.event.id;
}

function LogLine({ entry, names, onOpen }: { entry: SessionLogEntry; names: ActorNames; onOpen: () => void }) {
  const at = entry.kind === "request" ? entry.row.at : entry.event.at;
  const time = <When at={at} />;
  return (
    <TableRow title="Show everything recorded" {...rowOpener(onOpen)}>
      <TableCell className={cn(fromWidth.xl, "w-32 text-muted-foreground")}>{time}</TableCell>
      {entry.kind === "request" ? (
        <>
          <TableCell className="max-w-96">
            <Mono className="inline-block max-w-full truncate align-bottom">{entry.row.request}</Mono>
            {entry.row.mcp && <p className="mt-1 text-xs">MCP {entry.row.mcp}</p>}
            {entry.row.reason && <p className="mt-1 text-xs text-muted-foreground">{entry.row.reason}</p>}
            {entry.row.substituted && (
              <p className="mt-1 text-xs text-muted-foreground">Filled in {entry.row.substituted}</p>
            )}
            <p className="mt-1 text-xs text-muted-foreground @xl:hidden">{time}</p>
          </TableCell>
          <TableCell>{outcomeBadge(entry.row)}</TableCell>
          <TableCell className={cn(fromWidth.lg, "text-right tabular-nums text-muted-foreground")}>
            {entry.row.durationMs !== undefined ? `${entry.row.durationMs} ms` : ""}
          </TableCell>
        </>
      ) : (
        <>
          <TableCell>
            <span className="font-medium">{actorLabel(entry.event, names)}</span> {sessionHistoryPhrase(entry.event)}
            <p className="mt-1 text-xs text-muted-foreground @xl:hidden">{time}</p>
          </TableCell>
          <TableCell />
          <TableCell className={fromWidth.lg} />
        </>
      )}
    </TableRow>
  );
}

// ----- labels -----------------------------------------------------------------

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
