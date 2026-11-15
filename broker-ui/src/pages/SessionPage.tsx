// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// One session: what it is, whether it still works, and its whole log:
// every request it made and everything done to it, from the audit log.

import { useMemo, useState, type FormEvent } from "react";
import { Ban, History, Pencil, Route } from "lucide-react";
import {
  ApiError,
  get,
  patch,
  post,
  type AuditEvent,
  type DiscoveredService,
  type Page,
  type ProxySession,
  type Vault,
} from "../api";
import { can, onlyFor, type Me } from "../access";
import { actorName, sessionHistoryPhrase, type ActorNames } from "../audit";
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
  lines,
  Loading,
  Mono,
  Panel,
  Relative,
  RowMenu,
  Section,
  Status,
  Tags as TagList,
  useConfirm,
} from "../components/common";
import { cn } from "../lib/utils";
import { Button } from "../components/ui/button-components";
import { Input } from "../components/ui/input";
import { PageContainer, PageHeader } from "../components/ui/page-header";
import { Skeleton } from "../components/ui/skeleton";
import { Textarea } from "../components/ui/textarea";
import { SessionAlerts } from "./Alerts";
import { useActorNames } from "./Audit";
import { DetailLayout, Fact, FactList } from "../components/layout";
import { RequestLog } from "./RequestLog";
import { requestUsage } from "./sessionLogs";
import { isActive, sessionLabel, sessionStatus } from "./Sessions";

/** Proxies report traffic every few seconds; a live session's page follows it. */
const REFRESH_MS = 5_000;

export function SessionPage({ sessionId, user }: { sessionId: string; user: Me }) {
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
  // Relabelling is part of starting sessions; revoking one is stopping it.
  const canChange = can(user, vaultId, "start");
  const canRevoke = can(user, vaultId, "stop");
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
                  reason: onlyFor("edit"),
                },
                ...(active
                  ? [
                      {
                        label: "Revoke session",
                        icon: Ban,
                        onSelect: () => confirm.ask(s),
                        destructive: true,
                        disabled: !canRevoke,
                        reason: onlyFor("stop"),
                      },
                    ]
                  : []),
              ]}
            />
          )
        }
      />
      <ErrorBanner error={session.error ?? action.error} />
      {s && <SessionAlerts sessionId={s.id} />}
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
        <DetailLayout
          facts={
            <SessionInfo
              session={s}
              vaultName={vault.data?.name}
              used={used.data}
              names={names}
              canChange={canChange}
              onEdit={() => setEditing(true)}
            />
          }
        >
          <Reaches session={s} services={services.data} error={services.error} />
          <RequestLog
            query={`session_id=${s.id}`}
            deps={[s.revoked_at, JSON.stringify(s.labels)]}
            names={names}
            rules={rules}
            live={active}
            phrase={sessionHistoryPhrase}
            empty="Requests made with this session appear here a few seconds after a proxy handles them."
          />
        </DetailLayout>
      )}
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
    <FactList
      title="Details"
      action={
        canChange && (
          <Button type="button" variant="ghost" size="sm" className="-my-1" onClick={onEdit}>
            <Pencil />
            Edit
          </Button>
        )
      }
    >
      <Fact label="Requests">
        {usage ? (
          <span className={cn(usage.near && "font-medium text-warning-strong")}>{usage.text}</span>
        ) : (
          <Skeleton className="h-5 w-24" />
        )}
      </Fact>
      <Fact label={end.label}>
        <Exact at={end.at} />
        <span className="text-muted-foreground">
          {" "}
          (<Relative at={end.at} />)
        </span>
      </Fact>
      <Fact label="Access bundle">
        {s.bundle ? (
          <a href={`#/bundles/${s.bundle.id}`} className="underline-offset-2 hover:underline">
            {s.bundle.name}
          </a>
        ) : (
          `${s.rule_ids.length} rule${s.rule_ids.length === 1 ? "" : "s"}, chosen one by one`
        )}
      </Fact>
      <Fact label="Vault">
        <a href={`#/vaults/${s.vault_id}/credentials`} className="underline-offset-2 hover:underline">
          {vaultName ?? <Mono>{s.vault_id.slice(0, 8)}</Mono>}
        </a>
      </Fact>
      <Fact label="Created">
        {actorName(s.created_by, names)} · <Exact at={s.created_at} />
      </Fact>
      <Fact label="Name">
        <span className={s.labels.name ? undefined : "text-muted-foreground"}>{s.labels.name ?? "None"}</span>
      </Fact>
      <Fact label="Labels">
        {others.length > 0 ? (
          <TagList values={others.map(([k, v]) => `${k}=${v}`)} />
        ) : (
          <span className="text-muted-foreground">None</span>
        )}
      </Fact>
      <Fact label="Session ID">
        <span className="flex items-center gap-1">
          <Mono className="truncate">{s.id}</Mono>
          <CopyButton value={s.id} label="Copy session ID" iconOnly />
        </span>
      </Fact>
    </FactList>
  );
}

// ----- reaches ----------------------------------------------------------------

/** Paths worth naming: a rule limited to some of the host. */
function narrowedPaths(svc: DiscoveredService): string | undefined {
  const paths = svc.paths.filter((p) => p !== "/**" && p !== "/*" && p !== "*");
  return paths.length > 0 ? paths.join(", ") : undefined;
}

/** Methods worth naming: empty or `*` means any. */
function narrowedMethods(svc: DiscoveredService): string | undefined {
  const methods = svc.methods.filter((m) => m !== "*");
  return methods.length > 0 ? methods.join(", ") : undefined;
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
              const methods = narrowedMethods(svc);
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
                    {(paths || methods) && (
                      <span className="text-xs text-muted-foreground">
                        {" "}
                        · {methods ?? "any method"}
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
