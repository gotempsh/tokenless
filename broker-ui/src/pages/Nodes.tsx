// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { useState } from "react";
import { Plus, Server } from "lucide-react";
import { get, post, type NodeInfo, type Page } from "../api";
import { useAction, useLoad } from "../hooks";
import {
  ConfirmDialog,
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

function nodeStatus(n: NodeInfo) {
  if (n.revoked_at) return <Status tone="destructive">revoked</Status>;
  if (new Date(n.cert_not_after) <= new Date()) return <Status tone="warning">certificate expired</Status>;
  if (!n.last_seen_at) return <Status tone="neutral">never seen</Status>;
  return <Status tone="success">enrolled</Status>;
}

export function Nodes() {
  const [page, setPage] = useState(1);
  const nodes = useLoad(() => get<Page<NodeInfo>>(`/nodes?page=${page}`), [page]);
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
        title="Data plane nodes"
        description="Nodes run the proxy that agents connect to. They receive credentials sealed to their own key and fail closed when their policy lease lapses."
        actions={createButton}
      />
      <ErrorBanner error={nodes.error ?? action.error ?? tokenAction.error} />
      <Panel>
        {nodes.loading && !nodes.data ? (
          <Loading />
        ) : nodes.data?.items.length === 0 ? (
          <Empty
            icon={Server}
            title="No nodes enrolled"
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
                <TableHead>Certificate until</TableHead>
                <TableHead>Last seen</TableHead>
                <TableHead>Status</TableHead>
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
                  <TableCell className="text-muted-foreground">
                    <When at={n.cert_not_after} />
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    <When at={n.last_seen_at} />
                  </TableCell>
                  <TableCell>{nodeStatus(n)}</TableCell>
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
        description="Use it once, within the hour, to enrol a data plane node."
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
        title={`Revoke node "${confirm.target?.name ?? ""}"?`}
        description="It stops receiving policy and fails closed when its lease lapses. A revoked node has to be enrolled again with a new join token."
        confirmLabel="Revoke node"
        busy={action.busy}
        onConfirm={() => {
          if (confirm.target) void revoke(confirm.target);
        }}
      />
    </PageContainer>
  );
}
