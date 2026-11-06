// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { useEffect, useRef, useState, type ReactNode } from "react";
import { AlertTriangle, Ban, Download, Info, Plus, Server, ShieldCheck } from "lucide-react";
import { get, post, type NodeInfo, type Page } from "../api";
import { useAction, useLoad } from "../hooks";
import { proxyAttention, proxyState, type Attention, type ProxyState } from "../proxyHealth";
import {
  fromWidth,
  ConfirmDialog,
  CopyButton,
  DialogActions,
  Empty,
  ErrorBanner,
  FormDialog,
  Loading,
  Mono,
  Pager,
  Panel,
  Exact,
  Relative,
  RowActions,
  RowMenu,
  rowOpener,
  Status,
  useConfirm,
  type Tone,
} from "../components/common";
import { cn } from "../lib/utils";
import { Alert, AlertDescription, AlertTitle } from "../components/ui/alert";
import { CommandSnippet } from "./Bundles";
import { Button } from "../components/ui/button-components";
import { PageContainer, PageHeader } from "../components/ui/page-header";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../components/ui/table";

const STATUS: Record<ProxyState, { tone: Tone; label: string }> = {
  healthy: { tone: "success", label: "Connected" },
  offline: { tone: "warning", label: "Not connected" },
  never_connected: { tone: "neutral", label: "Never connected" },
  certificate_expired: { tone: "destructive", label: "Certificate expired" },
  revoked: { tone: "neutral", label: "Revoked" },
};

/** Proxies check in every few seconds; refresh often enough that the page tells the truth. */
const REFRESH_MS = 15_000;

function ProxyStatus({ node, now }: { node: NodeInfo; now: Date }) {
  const s = STATUS[proxyState(node, now)];
  return <Status tone={s.tone}>{s.label}</Status>;
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
  const ca = useLoad(caFingerprint, []);
  const [joinToken, setJoinToken] = useState<string | null>(null);
  const [viewing, setViewing] = useState<NodeInfo | null>(null);
  const [showRevoked, setShowRevoked] = useState(false);
  const confirm = useConfirm<NodeInfo>();
  const tokenAction = useAction();
  const action = useAction();

  const reload = useRef(nodes.reload);
  reload.current = nodes.reload;
  useEffect(() => {
    const timer = window.setInterval(() => reload.current(), REFRESH_MS);
    return () => window.clearInterval(timer);
  }, []);

  const now = new Date();
  const all = nodes.data?.items ?? [];
  const revokedCount = all.filter((n) => n.revoked_at).length;
  const rows = showRevoked ? all : all.filter((n) => !n.revoked_at);
  // Only the first page knows whether anything is enrolled at all.
  const attention = nodes.data && page === 1 ? proxyAttention(all, now) : null;

  const createToken = async () => {
    const r = await tokenAction.run(() => post<{ token: string; expires_at: string }>("/nodes/join-tokens", {}));
    if (r) setJoinToken(r.token);
  };

  const revoke = async (n: NodeInfo) => {
    await action.run(() => post<void>(`/nodes/${n.id}/revoke`));
    confirm.close();
    setViewing(null);
    nodes.reload();
  };

  const createButton = () => (
    <Button type="button" onClick={() => void createToken()} disabled={tokenAction.busy}>
      <Plus />
      Add a proxy
    </Button>
  );

  return (
    <PageContainer>
      <PageHeader
        title="Proxies"
        actions={rows.length === 0 ? undefined : createButton()}
      />
      <ErrorBanner error={nodes.error ?? ca.error ?? action.error ?? tokenAction.error} />
      {attention && attention.level !== "ok" && attention.kind !== "none_enrolled" && (
        <AttentionBanner attention={attention} now={now} onRevoke={(n) => confirm.ask(n)} />
      )}
      <Panel className="flex flex-col gap-3 p-4 sm:flex-row sm:items-center">
        <span className="flex size-10 shrink-0 items-center justify-center rounded-lg border bg-muted/40">
          <ShieldCheck className="size-5 text-muted-foreground" />
        </span>
        <div className="min-w-0 flex-1 space-y-1">
          <div className="text-sm font-medium">Interception CA</div>
          <p className="text-xs text-muted-foreground">Agents trust it so proxies can add credentials to HTTPS requests.</p>
          <div className="flex min-w-0 items-center gap-2">
            <span className="shrink-0 text-xs text-muted-foreground">SHA-256</span>
            <Mono className="truncate">{ca.data?.sha256 ?? "…"}</Mono>
            {ca.data && <CopyButton value={ca.data.sha256} label="Copy fingerprint" />}
          </div>
        </div>
        <Button type="button" variant="outline" size="sm" asChild>
          <a href="/api/v1/ca/interception.pem" download="tokenless-ca.pem">
            <Download />
            Download CA
          </a>
        </Button>
      </Panel>
      <Panel>
        {revokedCount > 0 && (
          <div className="flex justify-end border-b px-4 py-2">
            <Button type="button" variant="ghost" size="sm" onClick={() => setShowRevoked(!showRevoked)}>
              {showRevoked ? "Hide revoked" : `Show revoked (${revokedCount})`}
            </Button>
          </div>
        )}
        {nodes.loading && !nodes.data ? (
          <Loading />
        ) : rows.length === 0 ? (
          <Empty
            icon={Server}
            title="Add your first proxy"
            description="Agents reach services through a proxy, so none can until one runs. Any machine your agents can reach will do, this one included."
            action={createButton()}
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className={fromWidth.md}>Last seen</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((n) => (
                <TableRow key={n.id} {...rowOpener(() => setViewing(n), n.revoked_at && "text-muted-foreground")}>
                  <TableCell className="font-medium">{n.name}</TableCell>
                  <TableCell>
                    <ProxyStatus node={n} now={now} />
                  </TableCell>
                  <TableCell className={cn(fromWidth.md, "text-muted-foreground")}>
                    <Relative at={n.last_seen_at} />
                  </TableCell>
                  <TableCell>
                    <RowActions>
                      <RowMenu
                        label={n.name}
                        items={[
                          { label: "View details", icon: Info, onSelect: () => setViewing(n) },
                          ...(n.revoked_at
                            ? []
                            : [{ label: "Revoke proxy", icon: Ban, onSelect: () => confirm.ask(n), destructive: true }]),
                        ]}
                      />
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
        open={viewing !== null}
        onOpenChange={(o) => {
          if (!o) setViewing(null);
        }}
        title={viewing?.name ?? "Proxy"}
      >
        {viewing && (
          <ProxyDetails
            node={all.find((n) => n.id === viewing.id) ?? viewing}
            now={now}
            onRevoke={(n) => confirm.ask(n)}
            onClose={() => setViewing(null)}
          />
        )}
      </FormDialog>
      <FormDialog
        open={joinToken !== null}
        onOpenChange={(o) => {
          if (!o) setJoinToken(null);
        }}
        wide
        title="Add a proxy"
        description="Run these on the machine that will be the proxy. The command carries a one-time token that lets that machine enrol: it works once, expires in an hour and is not shown again."
      >
        {joinToken && (
          <div className="space-y-4">
            <ol className="list-decimal space-y-4 pl-5 text-sm">
              <li className="space-y-2">
                <p>Enrol the machine:</p>
                <CommandSnippet command={joinCommand(joinToken)} />
                <p className="text-xs text-muted-foreground">
                  If the console's node API is not on port 8443 of this host, change <Mono>--control-url</Mono> to
                  match <Mono>--node-listen</Mono>.
                </p>
              </li>
              <li className="space-y-2">
                <p>Start the proxy:</p>
                <CommandSnippet command="tokenless node run" />
                <p className="text-xs text-muted-foreground">It shows as connected on this page within seconds.</p>
              </li>
            </ol>
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

/** The enrol command for `token`, pointed at this console's node API. */
function joinCommand(token: string): string {
  return `tokenless node join --control-url https://${window.location.hostname}:8443 --token ${token}`;
}

/** What is wrong with a proxy, and what to do about it. */
function problemText(n: NodeInfo, now: Date): ReactNode {
  switch (proxyState(n, now)) {
    case "offline":
      return (
        <>
          Not heard from since <Relative at={n.last_seen_at} />. Start it on its host with{" "}
          <Mono>tokenless node run</Mono>, or revoke it if the host is gone.
        </>
      );
    case "never_connected":
      return (
        <>
          Enrolled <Relative at={n.enrolled_at} /> but never connected. Run <Mono>tokenless node run</Mono> on
          its host.
        </>
      );
    case "certificate_expired":
      return (
        <>
          Its certificate expired <Relative at={n.cert_not_after} /> without being renewed. Revoke it, then add the machine
          again with Add a proxy.
        </>
      );
    case "healthy":
    case "revoked":
      return null;
  }
}

function AttentionBanner({
  attention,
  now,
  onRevoke,
}: {
  attention: Exclude<Attention, { level: "ok" } | { kind: "none_enrolled" }>;
  now: Date;
  onRevoke: (n: NodeInfo) => void;
}) {
  const critical = attention.level === "critical";
  const title =
    attention.kind === "none_connected"
        ? "No proxy is connected"
        : `${attention.problems.length} of your proxies ${attention.problems.length === 1 ? "is" : "are"} not serving agents`;
  const description =
    attention.kind === "none_connected"
        ? "Every agent request fails until a proxy checks in."
        : "Agents routed to them fail; the others keep working.";
  return (
    <Alert variant={critical ? "destructive" : "warning"}>
      <AlertTriangle className="size-4" />
      <AlertTitle>{title}</AlertTitle>
      <AlertDescription className="space-y-3">
        <p>{description}</p>
        <ul className="space-y-2 text-foreground">
            {attention.problems.map((n) => (
              <li key={n.id} className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
                <span className="text-sm">
                  <span className="font-medium">{n.name}</span>: {problemText(n, now)}
                </span>
                <Button type="button" variant="outline" size="sm" className="shrink-0" onClick={() => onRevoke(n)}>
                  Revoke
                </Button>
              </li>
            ))}
        </ul>
      </AlertDescription>
    </Alert>
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

function ProxyDetails({
  node,
  now,
  onRevoke,
  onClose,
}: {
  node: NodeInfo;
  now: Date;
  onRevoke: (n: NodeInfo) => void;
  onClose: () => void;
}) {
  const problem = problemText(node, now);
  return (
    <div className="space-y-4">
      {problem && <p className="rounded-md border border-warning/50 bg-warning/10 p-3 text-sm">{problem}</p>}
      <dl className="space-y-3">
        <Fact label="Status">
          <ProxyStatus node={node} now={now} />
        </Fact>
        <Fact label="Last seen">
          <Exact at={node.last_seen_at} />
        </Fact>
        <Fact label="Enrolled">
          <Exact at={node.enrolled_at} />
        </Fact>
        {node.revoked_at && (
          <Fact label="Revoked">
            <Exact at={node.revoked_at} />
          </Fact>
        )}
        <Fact label="Certificate">
          renewed automatically, current one valid until <Exact at={node.cert_not_after} />
        </Fact>
        <Fact label="Proxy ID">
          <span className="flex items-center gap-2">
            <Mono>{node.id}</Mono>
            <CopyButton value={node.id} label="Copy ID" />
          </span>
        </Fact>
        <Fact label="Certificate serial">
          <Mono>{node.cert_serial}</Mono>
        </Fact>
        <Fact label="Sealing key">
          <Mono>{node.seal_public_key}</Mono>
        </Fact>
      </dl>
      <DialogActions>
        {!node.revoked_at && (
          <Button type="button" variant="destructive" onClick={() => onRevoke(node)}>
            Revoke proxy
          </Button>
        )}
        <Button type="button" variant="outline" onClick={onClose}>
          Close
        </Button>
      </DialogActions>
    </div>
  );
}
