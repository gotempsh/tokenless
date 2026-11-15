// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
import { useState } from "react";
import { get, post } from "../api";
import { useAction, useLoad } from "../hooks";
import { ErrorBanner, Loading } from "../components/common";
import { Button } from "../components/ui/button-components";
import { AuthLayout } from "./Auth";

export function CliLogin({ code, username }: { code: string; username: string }) {
  const details = useLoad(() => get<{ provider: string; manage: boolean }>(`/auth/cli/details?code=${encodeURIComponent(code)}`), [code]);
  const action = useAction();
  const [approved, setApproved] = useState(false);
  return (
    <AuthLayout title={approved ? "Sign-in approved" : "Sign in to your terminal"}>
      <div className="space-y-4">
        <ErrorBanner error={details.error ?? action.error} />
        {approved ? <p>Return to your terminal to continue. You can close this tab.</p> : details.data ? <>
          <p>Approve this sign-in as <strong>{username}</strong> through {details.data.provider}.</p>
          <p className="text-sm text-muted-foreground">Only continue if you started this request and this code matches the one in your terminal.</p>
          <p className="rounded-md border p-4 text-center font-mono text-xl" aria-label="Confirmation code">{code}</p>
          <p className="text-sm">{details.data.manage ? "This terminal can manage Tokenless with your permissions for up to one hour." : "This terminal can start agents with your vault permissions. It cannot manage Tokenless."}</p>
          <div className="flex flex-wrap justify-end gap-2">
            <Button variant="outline" onClick={() => { window.location.hash = "#/vaults"; }}>Cancel</Button>
            <Button disabled={action.busy} onClick={async () => {
              const ok = await action.run(() => post<void>("/auth/cli/approve", { code }).then(() => true));
              if (ok) setApproved(true);
            }}>Approve sign-in</Button>
          </div>
        </> : details.loading ? <Loading /> : null}
      </div>
    </AuthLayout>
  );
}
