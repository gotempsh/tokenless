// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// One session: what it is, whether it still works, and its whole log:
// every request it made and everything done to it, from the audit log.

import { useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode } from "react";
import { Ban, History, Pencil, Route, ScrollText } from "lucide-react";
import {
  ApiError,
  get,
  patch,
  post,
  type AuditEvent,
  type DiscoveredService,
  type Page,
  type ProxySession,
  type UserSummary,
  type Vault,
} from "../api";
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
  Status,
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
import { outcomeLabel, outcomeSentence, requestUsage, sessionLog, type LogRow, type SessionLogEntry } from "./sessionLogs";
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
  const services = useLoad(() => get<DiscoveredService[]>(`/sessions/${sessionId}/services`), [sessionId]);
  const names = useActorNames(user);
  const [editing, setEditing] = useState(false);
  const confirm = useConfirm<ProxySession>();
  const action = useAction();
  const canChange = user.role === "admin" || user.role === "editor";
  const active = s ? isActive(s) : false;
  // A live session can end elsewhere (revoked by someone else, ended by
  // the agent's own `tokenless run`, or expired): follow it, so the
  // header, the Revoke action and the log's polling stop with it.
  usePolling(session.reload, REFRESH_MS, active);
  // Requests the session has had a credential added to, for its limit.
  const used = useLoad(
    () =>
      get<Page<AuditEvent>>(`/audit?session_id=${sessionId}&action_prefix=proxy.inject&page_size=1`).then(
        (p) => p.total,
      ),
    [sessionId],
  );
  usePolling(used.reload, REFRESH_MS, active);
  const rules = useMemo(() => new Map((services.data ?? []).map((svc) => [svc.rule_id, svc])), [services.data]);

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
                  label: "Edit name and labels",
                  icon: Pencil,
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
        <SessionInfo
          session={s}
          vaultName={vault.data?.name}
          used={used.data}
          names={names}
          canChange={canChange}
          onEdit={() => setEditing(true)}
        />
      )}
      {s && <Reaches session={s} services={services.data} error={services.error} />}
      {s && <SessionLogs session={s} names={names} rules={rules} live={active} />}
      {!s && session.loading && <Loading />}
      <FormDialog open={editing} onOpenChange={setEditing} title="Edit name and labels">
        {s && editing && (
          <DetailsForm
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
  used,
  names,
  canChange,
  onEdit,
}: {
  session: ProxySession;
  vaultName?: string;
  /** Requests with a credential added so far; undefined while loading. */
  used?: number;
  names: ActorNames;
  canChange: boolean;
  onEdit: () => void;
}) {
  const end = endFact(s);
  const others = Object.entries(s.labels).filter(([k]) => k !== "name");
  const usage = used === undefined ? undefined : requestUsage(used, s.request_limit);
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
        <InfoItem label="Requests">
          {usage ? (
            <span className={cn(usage.near && "font-medium text-warning-strong")}>{usage.text}</span>
          ) : (
            <Skeleton className="h-5 w-24" />
          )}
        </InfoItem>
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
      <div className="flex items-start gap-4 border-t p-4">
        <dl className="grid min-w-0 flex-1 gap-4 md:grid-cols-2">
          <InfoItem label="Name">
            <span className={s.labels.name ? undefined : "text-muted-foreground"}>{s.labels.name ?? "None"}</span>
          </InfoItem>
          <InfoItem label="Labels">
            {others.length > 0 ? (
              <TagList values={others.map(([k, v]) => `${k}=${v}`)} />
            ) : (
              <span className="text-muted-foreground">None</span>
            )}
          </InfoItem>
        </dl>
        {canChange && (
          <Button type="button" variant="ghost" size="sm" onClick={onEdit}>
            <Pencil />
            Edit
          </Button>
        )}
      </div>
    </Panel>
  );
}

// ----- reaches ----------------------------------------------------------------

/** Paths worth naming: a rule limited to some of the host. */
function narrowedPaths(svc: DiscoveredService): string | undefined {
  const paths = svc.paths.filter((p) => p !== "/**" && p !== "/*" && p !== "*");
  return paths.length > 0 ? paths.join(", ") : undefined;
}

/** The services the session's token gets a credential for, rule by rule. */
function Reaches({
  session,
  services,
  error,
}: {
  session: ProxySession;
  services?: DiscoveredService[];
  error: string | null;
}) {
  const gone = services ? session.rule_ids.length - services.length : 0;
  return (
    <Section title="Reaches">
      <Panel>
        <ErrorBanner error={error} title="Couldn't load what the session reaches" />
        {!services ? (
          !error && <Loading rows={2} />
        ) : services.length === 0 ? (
          <Empty
            icon={Route}
            title="Nothing any more"
            description="Every rule this session was created with has been deleted, so it gets no credential."
          />
        ) : (
          <ul className="divide-y">
            {services.map((svc) => {
              const paths = narrowedPaths(svc);
              return (
                <li key={svc.rule_id} className="flex flex-col gap-1 px-4 py-3 @lg:flex-row @lg:items-baseline @lg:gap-6">
                  <div className="min-w-0 @lg:w-64 @lg:shrink-0">
                    <div className="flex flex-wrap items-center gap-2 text-sm font-medium">
                      {svc.credential}
                      {svc.kind === "mcp" && <Status tone="neutral">MCP</Status>}
                      {!svc.enabled && <Status tone="warning">Rule turned off</Status>}
                    </div>
                    <div className="text-xs text-muted-foreground">
                      {svc.service !== svc.credential && `${svc.service} · `}rule{" "}
                      <a href={`#/vaults/${session.vault_id}/rules`} className="underline-offset-2 hover:underline">
                        {svc.rule}
                      </a>
                    </div>
                  </div>
                  <div className="min-w-0 text-sm [overflow-wrap:anywhere]">
                    <span className="font-mono text-xs">
                      {svc.hosts.join(", ")}
                      {svc.kind === "mcp" && svc.mcp_path}
                    </span>
                    {(paths || svc.methods.length > 0) && (
                      <span className="text-xs text-muted-foreground">
                        {" "}
                        · {svc.methods.length > 0 ? svc.methods.join(", ") : "any method"}
                        {paths && <> on {paths}</>}
                      </span>
                    )}
                  </div>
                </li>
              );
            })}
          </ul>
        )}
        {gone > 0 && (
          <p className="border-t px-4 py-3 text-xs text-muted-foreground">
            {gone} rule{gone === 1 ? " it was" : "s it was"} created with {gone === 1 ? "has" : "have"} been deleted since.
          </p>
        )}
      </Panel>
    </Section>
  );
}

// ----- logs -------------------------------------------------------------------

function SessionLogs({
  session,
  names,
  rules,
  live,
}: {
  session: ProxySession;
  names: ActorNames;
  rules: Map<string, DiscoveredService>;
  live: boolean;
}) {
  const [page, setPage] = useState(1);
  const events = useLoad(
    () => get<Page<AuditEvent>>(`/audit?session_id=${session.id}&page=${page}&page_size=50`),
    [session.id, page, session.revoked_at, JSON.stringify(session.labels)],
  );
  usePolling(events.reload, REFRESH_MS, live && page === 1);
  const log = useMemo(() => sessionLog(events.data?.items ?? []), [events.data]);
  const [open, setOpen] = useState<SessionLogEntry | null>(null);
  const announcement = useNewestRequest(live && page === 1 ? log[0] : undefined);
  return (
    <Section
      title="Logs"
      actions={live ? <span className="text-xs text-muted-foreground">Updates every few seconds</span> : undefined}
    >
      <Panel>
        <p className="sr-only" aria-live="polite">
          {announcement}
        </p>
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
            {open.kind === "request" ? (
              <RequestDetails row={open.row} names={names} rules={rules} />
            ) : (
              <EventDetails event={open.event} names={names} />
            )}
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

/**
 * What a screen reader hears when a new request lands at the top of a live
 * log; nothing for the first load, so opening the page stays quiet.
 */
function useNewestRequest(newest: SessionLogEntry | undefined): string {
  const [said, setSaid] = useState("");
  const seen = useRef<string | null>(null);
  const key = newest ? entryKey(newest) : null;
  useEffect(() => {
    if (key === null) return;
    if (seen.current !== null && seen.current !== key && newest?.kind === "request") {
      setSaid(`New request: ${newest.row.request}, ${outcomeLabel(newest.row)}`);
    }
    seen.current = key;
  }, [key, newest]);
  return said;
}

/** A request in words first: what happened, then its facts, then the raw events. */
function RequestDetails({
  row,
  names,
  rules,
}: {
  row: LogRow;
  names: ActorNames;
  rules: Map<string, DiscoveredService>;
}) {
  const decision = row.events[0];
  const rule = row.ruleId ? rules.get(row.ruleId) : undefined;
  const labels = Object.entries(decision?.detail ?? {})
    .filter(([k]) => k.startsWith("label."))
    .map(([k, v]) => `${k.slice(6)}=${v}`);
  return (
    <div className="space-y-5">
      <div className="space-y-2">
        <div>{outcomeBadge(row)}</div>
        <p className="text-sm">{outcomeSentence(row, rule?.rule)}</p>
        {row.reason && <p className="text-sm text-muted-foreground [overflow-wrap:anywhere]">{row.reason}</p>}
      </div>
      <dl className="grid gap-x-6 gap-y-4 sm:grid-cols-2">
        <InfoItem label="When">
          <Exact at={row.at} />
        </InfoItem>
        {decision && <InfoItem label="Handled by">{actorLabel(decision, names)}</InfoItem>}
        {rule && (
          <InfoItem label="Credential">
            {rule.credential}
            <span className="text-muted-foreground"> · rule {rule.rule}</span>
          </InfoItem>
        )}
        {row.durationMs !== undefined && <InfoItem label="Took">{row.durationMs} ms</InfoItem>}
        {row.mcp && (
          <InfoItem label="MCP call">
            <Mono>{row.mcp}</Mono>
          </InfoItem>
        )}
        {row.substituted && (
          <InfoItem label="Filled in">
            <Mono>{row.substituted}</Mono>
          </InfoItem>
        )}
        {row.bodySkipped && <InfoItem label="Body not searched">{row.bodySkipped}</InfoItem>}
        {labels.length > 0 && (
          <InfoItem label="Session labels then" className="sm:col-span-2">
            <TagList values={labels} />
          </InfoItem>
        )}
      </dl>
      <details className="rounded-md border">
        <summary className="cursor-pointer px-3 py-2 text-sm text-muted-foreground">
          Recorded event{row.events.length === 1 ? "" : "s"}
        </summary>
        <div className="space-y-6 border-t p-3">
          {row.events.map((e, i) => (
            <div key={e.id} className={cn(i > 0 && "border-t pt-6")}>
              <EventDetails event={e} names={names} />
            </div>
          ))}
        </div>
      </details>
    </div>
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

// ----- name and labels --------------------------------------------------------

function DetailsForm({
  session,
  onCancel,
  onSaved,
}: {
  session: ProxySession;
  onCancel: () => void;
  onSaved: (s: ProxySession) => void;
}) {
  const [name, setName] = useState(session.labels.name ?? "");
  const [text, setText] = useState(
    Object.entries(session.labels)
      .filter(([k]) => k !== "name")
      .map(([k, v]) => `${k}=${v}`)
      .join("\n"),
  );
  const action = useAction();
  const save = async (e: FormEvent) => {
    e.preventDefault();
    const labels: Record<string, string> = Object.fromEntries(
      lines(text).map((l) => {
        const i = l.indexOf("=");
        return i < 0 ? [l.trim(), ""] : [l.slice(0, i).trim(), l.slice(i + 1).trim()];
      }),
    );
    // The Name field is the `name` label; it wins over a name= line.
    delete labels.name;
    if (name.trim()) labels.name = name.trim();
    const saved = await action.run(() => patch<ProxySession>(`/sessions/${session.id}`, { labels }));
    if (saved) onSaved(saved);
  };
  return (
    <form className="space-y-4" onSubmit={save}>
      <ErrorBanner error={action.error} />
      <Field label="Name" htmlFor="session-name-edit">
        <Input
          id="session-name-edit"
          autoFocus
          value={name}
          maxLength={256}
          placeholder="laptop-claude"
          onChange={(e) => setName(e.target.value)}
        />
      </Field>
      <Field
        label="Labels"
        htmlFor="session-labels"
        hint="key=value, one per line. Requests keep the labels the session was created with."
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
          Save
        </Button>
      </DialogActions>
    </form>
  );
}
