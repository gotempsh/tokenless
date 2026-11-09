// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { useMemo, useState, type ReactNode } from "react";
import { ScrollText } from "lucide-react";
import { get, type ApiKey, type AuditEvent, type NodeInfo, type Page, type UserSummary } from "../api";
import { ALL_EVENTS, AUDIT_CATEGORIES, actionPhrase, actorLabel, type ActorNames } from "../audit";
import { useLoad } from "../hooks";
import {
  fromWidth,
  DialogActions,
  Empty,
  ErrorBanner,
  Exact,
  FormDialog,
  Loading,
  Mono,
  Pager,
  Panel,
  rowOpener,
  Status,
  When,
} from "../components/common";
import { cn } from "../lib/utils";
import { Button } from "../components/ui/button-components";
import { PageContainer, PageHeader } from "../components/ui/page-header";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "../components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../components/ui/table";

const OUTCOME_LABEL: Record<string, string> = { denied: "Denied", failure: "Failed" };

/** Names for the users, API keys and proxies events refer to; admins only. */
export function useActorNames(me: UserSummary): ActorNames {
  const isAdmin = me.role === "admin";
  const none = () => Promise.resolve(undefined);
  const users = useLoad(() => (isAdmin ? get<Page<UserSummary>>("/users?page_size=100") : none()), [isAdmin]);
  const keys = useLoad(() => (isAdmin ? get<Page<ApiKey>>("/api-keys?page_size=100") : none()), [isAdmin]);
  const nodes = useLoad(() => (isAdmin ? get<Page<NodeInfo>>("/nodes?page_size=100") : none()), [isAdmin]);
  return useMemo(
    () => ({
      meId: me.id,
      users: new Map(users.data?.items.map((u) => [u.id, u.username])),
      apiKeys: new Map(keys.data?.items.map((k) => [k.prefix, k.name])),
      nodes: new Map(nodes.data?.items.map((n) => [n.id, n.name])),
    }),
    [me.id, users.data, keys.data, nodes.data],
  );
}

/** One sentence per event; open a row for everything it recorded. */
export function Audit({ me }: { me: UserSummary }) {
  const [page, setPage] = useState(1);
  const [category, setCategory] = useState(ALL_EVENTS);
  const [viewing, setViewing] = useState<AuditEvent | null>(null);
  const names = useActorNames(me);
  const events = useLoad(
    () => get<Page<AuditEvent>>(`/audit?page=${page}&page_size=50&action_prefix=${encodeURIComponent(category.prefix)}`),
    [page, category],
  );
  const filtered = category.prefix !== "";

  return (
    <PageContainer width="settings">
      <PageHeader title="Audit log" />
      <Select
        value={category.label}
        onValueChange={(label) => {
          setCategory(AUDIT_CATEGORIES.find((c) => c.label === label) ?? ALL_EVENTS);
          setPage(1);
        }}
      >
        <SelectTrigger className="w-full sm:w-56" aria-label="Show events">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {AUDIT_CATEGORIES.map((c) => (
            <SelectItem key={c.label} value={c.label}>
              {c.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <ErrorBanner error={events.error} />
      <Panel>
        {events.loading && !events.data ? (
          <Loading rows={6} />
        ) : events.data?.items.length === 0 ? (
          <Empty
            icon={ScrollText}
            title={filtered ? `No events in ${category.label}` : "No events yet"}
            description="Events appear here as soon as anything changes."
            action={
              filtered ? (
                <Button type="button" variant="outline" size="sm" onClick={() => setCategory(ALL_EVENTS)}>
                  Show all events
                </Button>
              ) : undefined
            }
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Event</TableHead>
                <TableHead className={cn(fromWidth.md, "text-right")}>When</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {events.data?.items.map((e) => (
                <TableRow key={e.id} {...rowOpener(() => setViewing(e))}>
                  <TableCell>
                    <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                      <span className="[overflow-wrap:anywhere]">
                        <span className="font-medium">{actorLabel(e, names)}</span> {actionPhrase(e)}
                      </span>
                      {e.outcome !== "success" && (
                        <Status tone="destructive">{OUTCOME_LABEL[e.outcome] ?? e.outcome}</Status>
                      )}
                    </div>
                    {/* A narrow table folds the time in here. */}
                    <div className="mt-1 text-xs text-muted-foreground @md:hidden">
                      <When at={e.at} />
                    </div>
                  </TableCell>
                  <TableCell className={cn(fromWidth.md, "text-right text-muted-foreground")}>
                    <When at={e.at} />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
        <Pager page={events.data} onPage={setPage} />
      </Panel>
      <FormDialog
        open={viewing !== null}
        onOpenChange={(o) => {
          if (!o) setViewing(null);
        }}
        title="Event"
      >
        {viewing && <EventDetails event={viewing} names={names} onClose={() => setViewing(null)} />}
      </FormDialog>
    </PageContainer>
  );
}

/** Everything the event recorded, including the raw identifiers the list leaves out. */
export function EventDetails({ event, names, onClose }: { event: AuditEvent; names: ActorNames; onClose?: () => void }) {
  return (
    <div className="space-y-4">
      <p className="text-sm">
        <span className="font-medium">{actorLabel(event, names)}</span> {actionPhrase(event)}
      </p>
      <dl className="space-y-3">
        <Fact label="When">
          <Exact at={event.at} />
        </Fact>
        <Fact label="Outcome">
          <Status tone={event.outcome === "success" ? "success" : "destructive"}>
            {OUTCOME_LABEL[event.outcome] ?? "Succeeded"}
          </Status>
        </Fact>
        <Fact label="Action">
          <Mono>{event.action}</Mono>
        </Fact>
        <Fact label="Actor">
          <Mono>{event.actor}</Mono>
        </Fact>
        {event.target && (
          <Fact label="Target">
            <Mono>{event.target}</Mono>
          </Fact>
        )}
        {event.vault_id && (
          <Fact label="Vault">
            <Mono>{event.vault_id}</Mono>
          </Fact>
        )}
        {Object.entries(event.detail).map(([k, v]) => (
          <Fact key={k} label={k}>
            {v ? <Mono>{v}</Mono> : <span className="text-muted-foreground">none</span>}
          </Fact>
        ))}
      </dl>
      {onClose && (
        <DialogActions>
          <Button type="button" variant="outline" onClick={onClose}>
            Close
          </Button>
        </DialogActions>
      )}
    </div>
  );
}

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="space-y-1">
      <dt className="text-xs font-medium text-muted-foreground">{label}</dt>
      <dd className="min-w-0 break-all text-sm">{children}</dd>
    </div>
  );
}
