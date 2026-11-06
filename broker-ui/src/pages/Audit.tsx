// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { useState } from "react";
import { ScrollText, Search } from "lucide-react";
import { get, type AuditEvent, type Page } from "../api";
import { useLoad } from "../hooks";
import { Empty, ErrorBanner, Loading, Mono, Pager, Panel, Status, Tags, When } from "../components/common";
import { Button } from "../components/ui/button-components";
import { Input } from "../components/ui/input";
import { PageContainer, PageHeader } from "../components/ui/page-header";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../components/ui/table";

const QUICK_FILTERS = ["proxy.", "credential.", "rule.", "session.", "auth.", "user."];

export function Audit() {
  const [page, setPage] = useState(1);
  const [prefix, setPrefix] = useState("");
  const [applied, setApplied] = useState("");
  const events = useLoad(
    () => get<Page<AuditEvent>>(`/audit?page=${page}&page_size=50&action_prefix=${encodeURIComponent(applied)}`),
    [page, applied],
  );
  const apply = (value: string) => {
    setPrefix(value);
    setPage(1);
    setApplied(value);
  };
  return (
    <PageContainer>
      <PageHeader
        title="Audit log"
        description="Every change, every injection and every denial, newest first. Entries are written in the same transaction as the change they describe."
      />
      <div className="flex flex-col gap-2 sm:flex-row sm:flex-wrap sm:items-center">
        <form
          className="flex w-full gap-2 sm:w-auto"
          onSubmit={(e) => {
            e.preventDefault();
            apply(prefix);
          }}
        >
          <div className="relative w-full sm:w-80">
            <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              className="pl-9"
              placeholder="Action prefix, e.g. proxy."
              value={prefix}
              onChange={(e) => setPrefix(e.target.value)}
              aria-label="Filter by action prefix"
            />
          </div>
          <Button type="submit" variant="outline">
            Filter
          </Button>
        </form>
        <div className="flex flex-wrap gap-1">
          {QUICK_FILTERS.map((f) => (
            <Button
              key={f}
              type="button"
              size="sm"
              variant={applied === f ? "secondary" : "ghost"}
              className="font-mono text-xs"
              onClick={() => apply(applied === f ? "" : f)}
            >
              {f}
            </Button>
          ))}
        </div>
      </div>
      <ErrorBanner error={events.error} />
      <Panel>
        {events.loading && !events.data ? (
          <Loading rows={6} />
        ) : events.data?.items.length === 0 ? (
          <Empty
            icon={ScrollText}
            title={applied ? "No matching events" : "No events yet"}
            description={
              applied ? `Nothing recorded with an action starting with "${applied}".` : "Events appear here as soon as anything changes."
            }
            action={
              applied ? (
                <Button type="button" variant="outline" size="sm" onClick={() => apply("")}>
                  Clear filter
                </Button>
              ) : undefined
            }
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>When</TableHead>
                <TableHead>Actor</TableHead>
                <TableHead>Action</TableHead>
                <TableHead>Outcome</TableHead>
                <TableHead>Target</TableHead>
                <TableHead>Detail</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {events.data?.items.map((e) => (
                <TableRow key={e.id}>
                  <TableCell className="text-muted-foreground">
                    <When at={e.at} />
                  </TableCell>
                  <TableCell>
                    <Mono>{e.actor}</Mono>
                  </TableCell>
                  <TableCell>
                    <Mono>{e.action}</Mono>
                  </TableCell>
                  <TableCell>
                    <Status tone={e.outcome === "success" ? "success" : "destructive"}>{e.outcome}</Status>
                  </TableCell>
                  <TableCell>{e.target && <Mono>{e.target}</Mono>}</TableCell>
                  <TableCell className="max-w-md">
                    <Tags values={Object.entries(e.detail).map(([k, v]) => `${k}=${v}`)} />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
        <Pager page={events.data} onPage={setPage} />
      </Panel>
    </PageContainer>
  );
}
