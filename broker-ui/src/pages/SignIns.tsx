// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Where the signed-in person is signed in: their browsers and CLI logins,
// with a way to end one, or all but this one.

import { useState } from "react";
import { Globe, LogOut, Terminal } from "lucide-react";
import { get, post, type Page, type SignIn, type SignInsRevoked } from "../api";
import { useAction, useLoad } from "../hooks";
import { fromWidth, ConfirmDialog, ErrorBanner, Loading, Panel, RowActions, Status, useConfirm, When } from "../components/common";
import { cn } from "../lib/utils";
import { Button } from "../components/ui/button-components";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../components/ui/table";
import { revokedMessage } from "../signIns";

export function SignIns() {
  const list = useLoad(() => get<Page<SignIn>>("/auth/sign-ins?page_size=100"), []);
  const action = useAction();
  const confirm = useConfirm<SignIn>();
  const [everywhere, setEverywhere] = useState(false);
  const [done, setDone] = useState<string | null>(null);
  const others = list.data?.items.filter((s) => !s.current).length ?? 0;

  const revoke = async (s: SignIn) => {
    const ok = await action.run(async () => {
      await post<void>(`/auth/sign-ins/${s.id}/revoke`);
      return true;
    });
    confirm.close();
    if (ok) setDone(`Signed out ${s.device}.`);
    list.reload();
  };

  const revokeOthers = async () => {
    const result = await action.run(() => post<SignInsRevoked>("/auth/sign-ins/revoke-others"));
    setEverywhere(false);
    if (result) setDone(revokedMessage(result.revoked));
    list.reload();
  };

  return (
    <div className="space-y-3">
      <ErrorBanner error={list.error ?? action.error} />
      {done && (
        <p className="text-sm text-muted-foreground" role="status">
          {done}
        </p>
      )}
      <Panel>
        {list.loading && !list.data ? (
          <Loading rows={2} />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Client</TableHead>
                <TableHead className={fromWidth.xl}>Signed in</TableHead>
                <TableHead className={fromWidth.md}>Last used</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {list.data?.items.map((s) => {
                const Icon = s.client === "cli" ? Terminal : Globe;
                return (
                  <TableRow key={s.id}>
                    <TableCell>
                      <div className="flex items-center gap-2 font-medium" title={s.user_agent ?? undefined}>
                        <Icon className="size-4 shrink-0 text-muted-foreground" aria-hidden />
                        {s.device}
                        {s.current && <Status tone="success">this one</Status>}
                      </div>
                      <div className="text-xs text-muted-foreground @md:hidden">
                        last used <When at={s.last_used_at} />
                      </div>
                    </TableCell>
                    <TableCell className={cn(fromWidth.xl, "text-muted-foreground")}>
                      <When at={s.created_at} />
                    </TableCell>
                    <TableCell className={cn(fromWidth.md, "text-muted-foreground")}>
                      <When at={s.last_used_at} />
                    </TableCell>
                    <TableCell>
                      <RowActions>
                        {!s.current && (
                          <Button type="button" variant="outline" size="sm" onClick={() => confirm.ask(s)}>
                            Sign out
                          </Button>
                        )}
                      </RowActions>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        )}
      </Panel>
      <Button
        type="button"
        variant="outline"
        onClick={() => setEverywhere(true)}
        disabled={others === 0}
        title={others === 0 ? "You are signed in only here" : undefined}
      >
        <LogOut />
        Sign out everywhere else
      </Button>
      <ConfirmDialog
        open={confirm.open}
        onOpenChange={confirm.onOpenChange}
        title={`Sign out ${confirm.target?.device ?? "this client"}?`}
        description="Its next request has to sign in again. Agent sessions it already started keep running until they expire."
        confirmLabel="Sign out"
        destructive
        busy={action.busy}
        onConfirm={() => {
          if (confirm.target) void revoke(confirm.target);
        }}
      />
      <ConfirmDialog
        open={everywhere}
        onOpenChange={setEverywhere}
        title="Sign out everywhere else?"
        description={`Ends your ${others} other sign-in${others === 1 ? "" : "s"}, browsers and CLI logins alike. This one stays signed in.`}
        confirmLabel="Sign out others"
        destructive
        busy={action.busy}
        onConfirm={() => void revokeOthers()}
      />
    </div>
  );
}
