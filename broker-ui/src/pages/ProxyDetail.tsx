// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { useEffect, useRef } from "react";
import { AlertTriangle, Ban, Server } from "lucide-react";
import { ApiError, get, post, type NodeInfo } from "../api";
import { useBreadcrumbs } from "../breadcrumbs";
import { useAction, useLoad } from "../hooks";
import {
  ConfirmDialog,
  CopyButton,
  Empty,
  ErrorBanner,
  Exact,
  Fact,
  Facts,
  Mono,
  Panel,
  Relative,
  useConfirm,
} from "../components/common";
import { Alert, AlertDescription, AlertTitle } from "../components/ui/alert";
import { Button } from "../components/ui/button-components";
import { PageContainer, PageHeader } from "../components/ui/page-header";
import { Skeleton } from "../components/ui/skeleton";
import { ProxyStatus, REFRESH_MS, problemText } from "./Nodes";

/** One proxy: whether it is serving agents, and the identifiers to check it by. */
export function ProxyDetail({ nodeId }: { nodeId: string }) {
  // A proxy that does not exist (or no longer does) loads as null, not as an error.
  const node = useLoad(
    () =>
      get<NodeInfo>(`/nodes/${nodeId}`).catch((e: unknown) => {
        if (e instanceof ApiError && e.problem.status === 404) return null;
        throw e;
      }),
    [nodeId],
  );
  const action = useAction();
  const confirm = useConfirm<NodeInfo>();

  const reload = useRef(node.reload);
  reload.current = node.reload;
  useEffect(() => {
    const timer = window.setInterval(() => reload.current(), REFRESH_MS);
    return () => window.clearInterval(timer);
  }, []);

  // Ignore what is still loaded for another proxy while this one loads.
  const n = node.data && node.data.id === nodeId ? node.data : undefined;
  const missing = node.data === null && !node.loading;
  useBreadcrumbs([
    { label: "Proxies", href: "#/proxies" },
    { label: n?.name ?? (node.error || missing ? "Proxy" : null) },
  ]);

  const revoke = async (target: NodeInfo) => {
    await action.run(() => post<void>(`/nodes/${target.id}/revoke`));
    confirm.close();
    node.reload();
  };

  const now = new Date();
  const problem = n ? problemText(n, now) : null;

  return (
    <PageContainer>
      <PageHeader
        title={n ? n.name : node.error || missing ? "Proxy" : <Skeleton className="h-8 w-48" />}
        verdict={n ? <ProxyStatus node={n} now={now} /> : undefined}
        actions={
          n &&
          !n.revoked_at && (
            <Button type="button" variant="outline" onClick={() => confirm.ask(n)}>
              <Ban />
              Revoke proxy
            </Button>
          )
        }
      />
      <ErrorBanner error={node.error ?? action.error} />
      {problem && (
        <Alert variant="warning">
          <AlertTriangle className="size-4" />
          <AlertTitle>This proxy is not serving agents</AlertTitle>
          <AlertDescription>{problem}</AlertDescription>
        </Alert>
      )}
      {missing ? (
        <Panel>
          <Empty
            icon={Server}
            title="This proxy doesn't exist"
            description="It may have been removed, or the link is wrong."
            action={
              <Button type="button" variant="outline" size="sm" asChild>
                <a href="#/proxies">Back to proxies</a>
              </Button>
            }
          />
        </Panel>
      ) : !n && !node.error ? (
        <Skeleton className="h-72 w-full rounded-lg" />
      ) : (
        n && (
          <Facts>
            <Fact label="Last seen">
              <Relative at={n.last_seen_at} />
            </Fact>
            <Fact label="Enrolled">
              <Exact at={n.enrolled_at} />
            </Fact>
            {n.revoked_at && (
              <Fact label="Revoked">
                <Exact at={n.revoked_at} />
              </Fact>
            )}
            <Fact label="Certificate">
              Valid until <Exact at={n.cert_not_after} />, renewed automatically
            </Fact>
            <Fact label="Proxy ID">
              <span className="flex min-w-0 items-center gap-1">
                <Mono className="min-w-0">{n.id}</Mono>
                <CopyButton value={n.id} label="Copy proxy ID" iconOnly />
              </span>
            </Fact>
            <Fact label="Certificate serial">
              <Mono>{n.cert_serial}</Mono>
            </Fact>
            <Fact label="Sealing key">
              <Mono>{n.seal_public_key}</Mono>
            </Fact>
          </Facts>
        )
      )}
      <ConfirmDialog
        open={confirm.open}
        onOpenChange={confirm.onOpenChange}
        title={`Revoke proxy "${confirm.target?.name ?? ""}"?`}
        description="It stops receiving policy and fails closed when its lease lapses. To use that machine again, add it as a proxy again."
        confirmLabel="Revoke proxy"
        busy={action.busy}
        onConfirm={() => {
          if (confirm.target) void revoke(confirm.target);
        }}
      />
    </PageContainer>
  );
}
