// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// A record's log from the audit log: the requests proxies handled for it,
// each joined with the API's answer, and everything done to the record
// itself. A session's page and a service's page show one each.

import { useEffect, useMemo, useRef, useState } from "react";
import { ScrollText } from "lucide-react";
import { get, type AuditEvent, type Page } from "../api";
import { actorLabel, type ActorNames } from "../audit";
import { usePolling, useLoad } from "../hooks";
import {
  DialogActions,
  Empty,
  ErrorBanner,
  Exact,
  FormDialog,
  fromWidth,
  Loading,
  Mono,
  Pager,
  Panel,
  rowOpener,
  Section,
  Tags as TagList,
  When,
} from "../components/common";
import { cn } from "../lib/utils";
import { Button } from "../components/ui/button-components";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../components/ui/table";
import { EventDetails } from "./Audit";
import { Fact } from "../components/layout";
import { outcomeLabel, outcomeSentence, sessionLog, type LogRow, type SessionLogEntry } from "./sessionLogs";
import { outcomeBadge } from "./Sessions";

/** Proxies report traffic every few seconds; a live log follows it. */
const REFRESH_MS = 5_000;

/** The rule a request matched, as the log names it. */
export interface LogRule {
  credential: string;
  rule: string;
}

export function RequestLog({
  query,
  deps = [],
  names,
  rules,
  live = false,
  phrase,
  empty,
  showSession = false,
}: {
  /** Audit filters, e.g. `session_id=…` or `vault_id=…&credential_id=…`. */
  query: string;
  /** Anything else that should reload the log when it changes. */
  deps?: unknown[];
  names: ActorNames;
  rules: Map<string, LogRule>;
  live?: boolean;
  /** What an event that is not a request did, after its actor. */
  phrase: (e: AuditEvent) => string;
  empty: string;
  /** Name the session behind each request (a service's log mixes them). */
  showSession?: boolean;
}) {
  const [page, setPage] = useState(1);
  const events = useLoad(
    () => get<Page<AuditEvent>>(`/audit?${query}&page=${page}&page_size=50`),
    [query, page, ...deps],
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
          <Empty icon={ScrollText} title="Nothing logged yet" description={empty} />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className={fromWidth.xl}>Time</TableHead>
                <TableHead>What happened</TableHead>
                {showSession && <TableHead className={fromWidth["2xl"]}>Session</TableHead>}
                <TableHead className={fromWidth.md}>Result</TableHead>
                <TableHead className={cn(fromWidth.lg, "text-right")}>Took</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {log.map((entry) => (
                <LogLine
                  key={entryKey(entry)}
                  entry={entry}
                  names={names}
                  phrase={phrase}
                  showSession={showSession}
                  onOpen={() => setOpen(entry)}
                />
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
              <RequestDetails row={open.row} names={names} rules={rules} showSession={showSession} />
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

function sessionName(session: NonNullable<LogRow["session"]>): string {
  return session.name ?? `session ${session.id.slice(0, 8)}`;
}

/** A request in words first: what happened, then its facts, then the raw events. */
function RequestDetails({
  row,
  names,
  rules,
  showSession,
}: {
  row: LogRow;
  names: ActorNames;
  rules: Map<string, LogRule>;
  showSession: boolean;
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
        <Fact label="When">
          <Exact at={row.at} />
        </Fact>
        {decision && <Fact label="Handled by">{actorLabel(decision, names)}</Fact>}
        {showSession && row.session && (
          <Fact label="Session">
            <a href={`#/sessions/${row.session.id}`} className="font-medium underline-offset-4 hover:underline">
              {sessionName(row.session)}
            </a>
          </Fact>
        )}
        {rule && (
          <Fact label="Credential">
            {rule.credential}
            <span className="text-muted-foreground"> · rule {rule.rule}</span>
          </Fact>
        )}
        {row.durationMs !== undefined && <Fact label="Took">{row.durationMs} ms</Fact>}
        {row.mcp && (
          <Fact label="MCP call">
            <Mono>{row.mcp}</Mono>
          </Fact>
        )}
        {row.substituted && (
          <Fact label="Filled in">
            <Mono>{row.substituted}</Mono>
          </Fact>
        )}
        {row.bodySkipped && <Fact label="Body not searched">{row.bodySkipped}</Fact>}
        {labels.length > 0 && (
          <Fact label="Session labels then" className="sm:col-span-2">
            <TagList values={labels} />
          </Fact>
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

function LogLine({
  entry,
  names,
  phrase,
  showSession,
  onOpen,
}: {
  entry: SessionLogEntry;
  names: ActorNames;
  phrase: (e: AuditEvent) => string;
  showSession: boolean;
  onOpen: () => void;
}) {
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
            {showSession && entry.row.session && (
              <p className="mt-1 text-xs text-muted-foreground @2xl:hidden">By {sessionName(entry.row.session)}</p>
            )}
            <div className="mt-1 @md:hidden">{outcomeBadge(entry.row)}</div>
            <p className="mt-1 text-xs text-muted-foreground @xl:hidden">{time}</p>
          </TableCell>
          {showSession && (
            <TableCell className={cn(fromWidth["2xl"], "max-w-48 truncate text-muted-foreground")}>
              {entry.row.session ? sessionName(entry.row.session) : ""}
            </TableCell>
          )}
          <TableCell className={fromWidth.md}>{outcomeBadge(entry.row)}</TableCell>
          <TableCell className={cn(fromWidth.lg, "whitespace-nowrap text-right tabular-nums text-muted-foreground")}>
            {entry.row.durationMs !== undefined ? `${entry.row.durationMs} ms` : ""}
          </TableCell>
        </>
      ) : (
        <>
          <TableCell>
            <span className="font-medium">{actorLabel(entry.event, names)}</span> {phrase(entry.event)}
            <p className="mt-1 text-xs text-muted-foreground @xl:hidden">{time}</p>
          </TableCell>
          {showSession && <TableCell className={fromWidth["2xl"]} />}
          <TableCell className={fromWidth.md} />
          <TableCell className={fromWidth.lg} />
        </>
      )}
    </TableRow>
  );
}
