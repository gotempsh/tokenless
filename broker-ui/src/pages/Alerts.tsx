// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Alerts: what the proxies reported that someone should look at now, and
// the banners that point to them from the overview and a session's page.

import { useState } from "react";
import { BellRing, Check, Webhook } from "lucide-react";
import { get, post, type Alert as AlertRecord, type AlertSummary, type AuditDestination, type Page, type UserSummary } from "../api";
import { alertDestinations, bannerTitle, KIND_LABEL } from "../alerts";
import { useAction, useLoad } from "../hooks";
import {
  fromWidth,
  Empty,
  ErrorBanner,
  Loading,
  Pager,
  Panel,
  RowActions,
  RowMenu,
  Status,
  When,
} from "../components/common";
import { cn } from "../lib/utils";
import { Alert, AlertDescription, AlertTitle } from "../components/ui/alert";
import { Button } from "../components/ui/button-components";
import { PageContainer, PageHeader } from "../components/ui/page-header";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../components/ui/table";
import { NEW_DESTINATION_HREF } from "./AuditExport";

export const ALERTS_HREF = "#/alerts";

/** Where alerts go besides this page: the webhooks that carry them, or how to add one. */
function Delivery({ destinations }: { destinations: AuditDestination[] }) {
  const n = alertDestinations(destinations).length;
  return (
    <Button asChild variant="outline" size="sm">
      <a href={n === 0 ? NEW_DESTINATION_HREF : "#/settings"}>
        <Webhook />
        {n === 0 ? "Send alerts to a webhook" : n === 1 ? "Sent to 1 webhook" : `Sent to ${n} webhooks`}
      </a>
    </Button>
  );
}

export function Alerts({ me }: { me: UserSummary }) {
  const [page, setPage] = useState(1);
  const [showAll, setShowAll] = useState(false);
  const action = useAction();
  const alerts = useLoad(
    () => get<Page<AlertRecord>>(`/alerts?open=${!showAll}&page=${page}&page_size=50`),
    [page, showAll],
  );
  const isAdmin = me.role === "admin";
  const canAck = me.role !== "viewer";
  const destinations = useLoad(
    () => (isAdmin ? get<AuditDestination[]>("/audit-export/destinations") : Promise.resolve(undefined)),
    [isAdmin],
  );

  const acknowledge = async (a: AlertRecord) => {
    const done = await action.run(() => post<AlertRecord>(`/alerts/${a.id}/acknowledge`));
    if (done) alerts.reload();
  };

  const toggle = (
    <Button
      type="button"
      variant="outline"
      size="sm"
      onClick={() => {
        setShowAll((v) => !v);
        setPage(1);
      }}
    >
      {showAll ? "Show open only" : "Show acknowledged too"}
    </Button>
  );

  return (
    <PageContainer width="settings">
      <PageHeader
        title="Alerts"
        actions={destinations.data && <Delivery destinations={destinations.data} />}
      />
      <ErrorBanner error={alerts.error ?? action.error} />
      {/* The empty state offers it itself. */}
      {(showAll || (alerts.data?.items.length ?? 0) > 0) && <div className="flex justify-end">{toggle}</div>}
      <Panel>
        {alerts.loading && !alerts.data ? (
          <Loading rows={4} />
        ) : alerts.data?.items.length === 0 ? (
          <Empty
            icon={BellRing}
            title={showAll ? "No alerts yet" : "No open alerts"}
            description="A session that sends a tripwire, is cut off for probing, is refused again and again or is used through a second proxy raises an alert here."
            action={showAll ? undefined : toggle}
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>What happened</TableHead>
                <TableHead className={fromWidth.md}>Raised</TableHead>
                <TableHead className={fromWidth.lg}>Status</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {alerts.data?.items.map((a) => (
                <TableRow key={a.id}>
                  <TableCell>
                    <div className="font-medium">{KIND_LABEL[a.kind]}</div>
                    <div className="text-sm text-muted-foreground [overflow-wrap:anywhere]">{a.summary}</div>
                    {a.session_id && (
                      <a className="text-sm underline" href={`#/sessions/${a.session_id}`}>
                        Review the session
                      </a>
                    )}
                    <div className="mt-1 text-xs text-muted-foreground @md:hidden">
                      <When at={a.raised_at} />
                    </div>
                    <div className="mt-1 @lg:hidden">
                      <AlertStatus alert={a} />
                    </div>
                  </TableCell>
                  <TableCell className={cn(fromWidth.md, "text-muted-foreground")}>
                    <When at={a.raised_at} />
                  </TableCell>
                  <TableCell className={fromWidth.lg}>
                    <AlertStatus alert={a} />
                  </TableCell>
                  <TableCell>
                    <RowActions>
                      {a.acknowledged_at === null && (
                        <RowMenu
                          label={`Actions for ${KIND_LABEL[a.kind]}`}
                          items={[
                            {
                              label: "Acknowledge",
                              icon: Check,
                              onSelect: () => void acknowledge(a),
                              disabled: !canAck || action.busy,
                              reason: "Only editors and admins can acknowledge alerts",
                            },
                          ]}
                        />
                      )}
                    </RowActions>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
        <Pager page={alerts.data} onPage={setPage} />
      </Panel>
    </PageContainer>
  );
}

function AlertStatus({ alert }: { alert: AlertRecord }) {
  return alert.acknowledged_at ? (
    <Status tone="neutral">acknowledged</Status>
  ) : (
    <Status tone="destructive">open</Status>
  );
}

/** Open alerts, on the overview: the newest and the way to the rest. */
export function OpenAlertsBanner() {
  const summary = useLoad(() => get<AlertSummary>("/alerts/summary"), []);
  const s = summary.data;
  if (!s || s.open === 0) return null;
  return (
    <Alert variant="destructive">
      <BellRing className="size-4" />
      <AlertTitle>{bannerTitle(s.open, s.latest)}</AlertTitle>
      <AlertDescription>
        {s.latest && <p className="[overflow-wrap:anywhere]">{s.latest.summary}</p>}
        <a className="underline" href={ALERTS_HREF}>
          {s.open === 1 ? "See the alert" : "See them all"}
        </a>
      </AlertDescription>
    </Alert>
  );
}

/** This session's open alerts, at the top of its page. */
export function SessionAlerts({ sessionId }: { sessionId: string }) {
  const alerts = useLoad(
    () => get<Page<AlertRecord>>(`/alerts?open=true&session_id=${sessionId}&page_size=10`),
    [sessionId],
  );
  const items = alerts.data?.items ?? [];
  if (items.length === 0) return null;
  return (
    <Alert variant="destructive">
      <BellRing className="size-4" />
      <AlertTitle>{items.length === 1 && items[0] ? KIND_LABEL[items[0].kind] : `${items.length} open alerts`}</AlertTitle>
      <AlertDescription>
        {items.map((a) => (
          <p key={a.id} className="[overflow-wrap:anywhere]">
            {a.summary}
          </p>
        ))}
        <a className="underline" href={ALERTS_HREF}>
          Acknowledge on the Alerts page
        </a>
      </AlertDescription>
    </Alert>
  );
}
