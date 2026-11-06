// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { useState } from "react";
import { Download, Plus, Server, ShieldCheck } from "lucide-react";
import { get, post, type NodeInfo, type Page, type Settings } from "../api";
import { useAction, useLoad } from "../hooks";
import {
  ConfirmDialog,
  CopyButton,
  DialogActions,
  Empty,
  ErrorBanner,
  FormDialog,
  Loading,
  Mono,
  OneTimeSecret,
  Pager,
  Panel,
  RowActions,
  Status,
  useConfirm,
  When,
} from "../components/common";
import { Button } from "../components/ui/button-components";
import { PageContainer, PageHeader } from "../components/ui/page-header";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../components/ui/table";

/** A proxy polls for policy every few seconds; two leases without contact means it is gone. */
const HEALTHY_WITHIN_MS = 2 * 60 * 1000;

function nodeStatus(n: NodeInfo) {
  if (n.revoked_at) return <Status tone="destructive">Revoked</Status>;
  if (new Date(n.cert_not_after) <= new Date()) return <Status tone="warning">Certificate expired</Status>;
  if (!n.last_seen_at) return <Status tone="neutral">Never connected</Status>;
  if (Date.now() - new Date(n.last_seen_at).getTime() > HEALTHY_WITHIN_MS)
    return <Status tone="warning">Not connected</Status>;
  return <Status tone="success">Healthy</Status>;
}

/** SHA-256 of the interception CA certificate, as agents' trust stores show it. */
async function caFingerprint(): Promise<{ pem: string; sha256: string }> {
  const response = await fetch("/api/v1/ca/interception.pem", { credentials: "same-origin", cache: "no-store" });
  if (!response.ok) throw new Error(`Could not load the interception CA (${response.status})`);
  const pem = await response.text();
  const b64 = pem.replace(/-----(BEGIN|END) CERTIFICATE-----/g, "").replace(/\s+/g, "");
  const der = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", der));
  const sha256 = [...digest].map((b) => b.toString(16).padStart(2, "0").toUpperCase()).join(":");
  return { pem, sha256 };
}

export function Nodes() {
  const [page, setPage] = useState(1);
  const nodes = useLoad(() => get<Page<NodeInfo>>(`/nodes?page=${page}`), [page]);
  const settings = useLoad(() => get<Settings>("/settings"), []);
  const ca = useLoad(caFingerprint, []);
  const policy =
    settings.data === undefined
      ? "…"
      : settings.data.unmatched_host_policy === "passthrough"
        ? "Any host"
        : "Rule hosts only";
  const [joinToken, setJoinToken] = useState<string | null>(null);
  const confirm = useConfirm<NodeInfo>();
  const tokenAction = useAction();
  const action = useAction();

  const createToken = async () => {
    const r = await tokenAction.run(() => post<{ token: string; expires_at: string }>("/nodes/join-tokens", {}));
    if (r) setJoinToken(r.token);
  };

  const revoke = async (n: NodeInfo) => {
    await action.run(() => post<void>(`/nodes/${n.id}/revoke`));
    confirm.close();
    nodes.reload();
  };

  const createButton = (
    <Button type="button" onClick={() => void createToken()} disabled={tokenAction.busy}>
      <Plus />
      Create join token
    </Button>
  );

  return (
    <PageContainer>
      <PageHeader
        title="Proxies"
        description="Proxies are the data plane agents connect to. They receive credentials sealed to their own key, add them to agents' requests and fail closed when their policy lease lapses."
        actions={createButton}
      />
      <ErrorBanner error={nodes.error ?? ca.error ?? action.error ?? tokenAction.error} />
      <Panel className="flex flex-col gap-3 p-4 sm:flex-row sm:items-center">
        <span className="flex size-10 shrink-0 items-center justify-center rounded-lg border bg-muted/40">
          <ShieldCheck className="size-5 text-muted-foreground" />
        </span>
        <div className="min-w-0 flex-1 space-y-1">
          <div className="text-sm font-medium">Interception CA</div>
          <p className="text-xs text-muted-foreground">
            Agents trust this certificate so the proxies can add credentials to HTTPS requests. Check the fingerprint
            matches before installing it.
          </p>
          <div className="flex min-w-0 items-center gap-2">
            <span className="text-xs text-muted-foreground">SHA-256</span>
            <Mono className="truncate">{ca.data?.sha256 ?? "…"}</Mono>
            {ca.data && <CopyButton value={ca.data.sha256} label="Copy fingerprint" />}
          </div>
        </div>
        <Button type="button" variant="outline" size="sm" asChild>
          <a href="/api/v1/ca/interception.pem" download="credential-broker-ca.pem">
            <Download />
            Download CA
          </a>
        </Button>
      </Panel>
      <Panel>
        {nodes.loading && !nodes.data ? (
          <Loading />
        ) : nodes.data?.items.length === 0 ? (
          <Empty
            icon={Server}
            title="No proxies connected"
            description={
              <p className="text-sm text-muted-foreground">
                Create a join token and run <Mono>credential-broker node join</Mono> on the data plane host.
              </p>
            }
            action={createButton}
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Node</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Traffic policy</TableHead>
                <TableHead className="hidden md:table-cell">Certificate until</TableHead>
                <TableHead>Last seen</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {nodes.data?.items.map((n) => (
                <TableRow key={n.id}>
                  <TableCell className="font-medium">{n.name}</TableCell>
                  <TableCell>
                    <Mono>{n.id.slice(0, 8)}</Mono>
                  </TableCell>
                  <TableCell>{nodeStatus(n)}</TableCell>
                  <TableCell>
                    <a href="#/settings" className="text-sm hover:underline" title="Change under Settings">
                      {policy}
                    </a>
                  </TableCell>
                  <TableCell className="hidden text-muted-foreground md:table-cell">
                    <When at={n.cert_not_after} />
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    <When at={n.last_seen_at} />
                  </TableCell>
                  <TableCell>
                    <RowActions>
                      {!n.revoked_at && (
                        <Button type="button" variant="outline" size="sm" onClick={() => confirm.ask(n)}>
                          Revoke
                        </Button>
                      )}
                    </RowActions>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
        <Pager page={nodes.data} onPage={setPage} />
      </Panel>
      <FormDialog
        open={joinToken !== null}
        onOpenChange={(o) => {
          if (!o) setJoinToken(null);
        }}
        wide
        title="Join token created"
        description="Use it once, within the hour, to enrol a proxy."
      >
        {joinToken && (
          <div className="space-y-4">
            <OneTimeSecret
              label="Join token (single use)"
              value={joinToken}
              hint={
                <code className="block break-all rounded-md border bg-background px-3 py-2 font-mono text-xs">
                  credential-broker node join --control-url https://&lt;this-host&gt;:8443 --token {joinToken.slice(0, 12)}…
                </code>
              }
            />
            <DialogActions>
              <Button
                type="button"
                onClick={() => {
                  setJoinToken(null);
                  nodes.reload();
                }}
              >
                Done
              </Button>
            </DialogActions>
          </div>
        )}
      </FormDialog>
      <ConfirmDialog
        open={confirm.open}
        onOpenChange={confirm.onOpenChange}
        title={`Revoke proxy "${confirm.target?.name ?? ""}"?`}
        description="It stops receiving policy and fails closed when its lease lapses. A revoked proxy has to be enrolled again with a new join token."
        confirmLabel="Revoke proxy"
        busy={action.busy}
        onConfirm={() => {
          if (confirm.target) void revoke(confirm.target);
        }}
      />
    </PageContainer>
  );
}
