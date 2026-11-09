// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Sessions across every vault the caller can see. Each one opens its own
// page with its requests and history.

import { useMemo, useState } from "react";
import { Ban, Plus, Timer } from "lucide-react";
import { get, post, type AccessBundle, type Page, type ProxySession, type UserSummary, type Vault } from "../api";
import { actorName, type ActorNames } from "../audit";
import { useAction, useLoad } from "../hooks";
import {
  fromWidth,
  ConfirmDialog,
  Empty,
  ErrorBanner,
  Loading,
  Mono,
  Pager,
  Panel,
  Relative,
  RowActions,
  RowMenu,
  rowLink,
  Status,
  useConfirm,
} from "../components/common";
import { cn } from "../lib/utils";
import { Button } from "../components/ui/button-components";
import { PageContainer, PageHeader } from "../components/ui/page-header";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../components/ui/table";
import { useActorNames } from "./Audit";
import { NewSessionDialog } from "./NewSession";
import { outcomeLabel, type LogRow } from "./sessionLogs";

export function outcomeBadge(row: LogRow) {
  const tone =
    row.outcome === "blocked"
      ? "warning"
      : row.outcome === "passthrough"
        ? "neutral"
        : row.outcome === "error" || (row.status !== undefined && row.status >= 500)
          ? "destructive"
          : row.status !== undefined && row.status >= 400
            ? "warning"
            : "success";
  return <Status tone={tone}>{outcomeLabel(row)}</Status>;
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

export const isActive = (s: ProxySession) => !s.revoked_at && new Date(s.expires_at) > new Date();

/**
 * Sessions as rows that open their page. `vaultNames` adds a vault column
 * (the list across vaults); a live session's menu revokes it.
 */
export function SessionTable({
  sessions,
  actors,
  vaultNames,
  showBundle = true,
  canRevoke,
  onRevoke,
}: {
  sessions: ProxySession[];
  actors: ActorNames;
  vaultNames?: Record<string, string>;
  showBundle?: boolean;
  canRevoke: boolean;
  onRevoke: (s: ProxySession) => void;
}) {
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Name</TableHead>
          {vaultNames && <TableHead className={fromWidth["2xl"]}>Vault</TableHead>}
          {showBundle && <TableHead className={fromWidth["3xl"]}>Bundle</TableHead>}
          <TableHead className={fromWidth["4xl"]}>Created by</TableHead>
          <TableHead className={fromWidth.xl}>Created</TableHead>
          <TableHead className={fromWidth.lg}>Expires</TableHead>
          <TableHead>Status</TableHead>
          <TableHead className="text-right">Actions</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {sessions.map((s) => {
          // Where the vault and bundle columns are hidden, they show under the name.
          const where = [vaultNames?.[s.vault_id], showBundle ? s.bundle?.name : undefined].filter(Boolean).join(" · ");
          return (
            <TableRow key={s.id} {...rowLink(`#/sessions/${s.id}`)}>
              <TableCell>
                <div className="font-medium">{sessionLabel(s)}</div>
                {where && <div className="text-xs text-muted-foreground @3xl:hidden">{where}</div>}
              </TableCell>
              {vaultNames && (
                <TableCell className={fromWidth["2xl"]}>
                  {vaultNames[s.vault_id] ?? <Mono>{s.vault_id.slice(0, 8)}</Mono>}
                </TableCell>
              )}
              {showBundle && (
                <TableCell className={fromWidth["3xl"]}>
                  {s.bundle ? s.bundle.name : <span className="text-muted-foreground">—</span>}
                </TableCell>
              )}
              <TableCell className={cn(fromWidth["4xl"], "text-muted-foreground")}>
                {actorName(s.created_by, actors)}
              </TableCell>
              <TableCell className={cn(fromWidth.xl, "text-muted-foreground")}>
                <Relative at={s.created_at} />
              </TableCell>
              <TableCell className={cn(fromWidth.lg, "text-muted-foreground")}>
                <Relative at={s.expires_at} />
              </TableCell>
              <TableCell>{sessionStatus(s)}</TableCell>
              <TableCell>
                <RowActions>
                  {isActive(s) && (
                    <RowMenu
                      label={sessionLabel(s)}
                      items={[
                        {
                          label: "Revoke session",
                          icon: Ban,
                          onSelect: () => onRevoke(s),
                          destructive: true,
                          disabled: !canRevoke,
                          reason: "Only editors and admins can revoke sessions",
                        },
                      ]}
                    />
                  )}
                </RowActions>
              </TableCell>
            </TableRow>
          );
        })}
      </TableBody>
    </Table>
  );
}

export function Sessions({ me }: { me: UserSummary }) {
  const [page, setPage] = useState(1);
  const sessions = useLoad(() => get<Page<ProxySession>>(`/sessions?page=${page}`), [page]);
  const vaults = useLoad(() => get<Page<Vault>>("/vaults?page_size=100"), []);
  const names = useMemo(
    () => Object.fromEntries((vaults.data?.items ?? []).map((v) => [v.id, v.name])),
    [vaults.data],
  );
  const actors = useActorNames(me);
  const canRevoke = me.role === "admin" || me.role === "editor";
  const [creating, setCreating] = useState(false);
  const bundles = useLoad(
    () => (creating ? get<Page<AccessBundle>>("/bundles?page_size=100") : Promise.resolve(undefined)),
    [creating],
  );
  const newButton = (
    <Button
      type="button"
      onClick={() => setCreating(true)}
      disabled={!canRevoke}
      title={canRevoke ? undefined : "Only editors and admins can create sessions"}
    >
      <Plus />
      New session
    </Button>
  );
  const confirm = useConfirm<ProxySession>();
  const action = useAction();

  const revoke = async (s: ProxySession) => {
    await action.run(() => post<void>(`/sessions/${s.id}/revoke`));
    confirm.close();
    sessions.reload();
  };

  return (
    <PageContainer>
      <PageHeader title="Sessions" actions={newButton} />
      <ErrorBanner error={sessions.error ?? action.error} />
      <Panel>
        {sessions.loading && !sessions.data ? (
          <Loading />
        ) : sessions.data?.items.length === 0 ? (
          <Empty
            icon={Timer}
            title="No sessions yet"
            description="Create one and give its token to an agent. It reaches an access bundle's services until it expires or you revoke it."
            action={newButton}
          />
        ) : (
          <SessionTable
            sessions={sessions.data?.items ?? []}
            actors={actors}
            vaultNames={names}
            canRevoke={canRevoke}
            onRevoke={confirm.ask}
          />
        )}
        <Pager page={sessions.data} onPage={setPage} />
      </Panel>
      <NewSessionDialog
        choices={bundles.data?.items}
        choicesTotal={bundles.data?.total}
        vaultNames={names}
        open={creating}
        onOpenChange={setCreating}
        onCreated={() => sessions.reload()}
        isAdmin={me.role === "admin"}
      />
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
