// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { useEffect, useMemo, useState, type FormEvent } from "react";
import { FolderLock as VaultIcon, Plus } from "lucide-react";
import { get, post, type StoredTemplate, type Page, type Vault, type VaultOverview } from "../api";
import { fallbackPage, hasPager } from "../paging";
import { addServiceHref } from "../addService";
import { targetHosts } from "../catalog";
import { useAction, useLoad } from "../hooks";
import { DialogActions, Empty, ErrorBanner, Field, FormDialog, Pager, Panel, Relative, Status } from "../components/common";
import { ServiceLogo } from "../components/ServiceLogo";
import { PANEL_GRID as GRID } from "../components/layout";
import { Button } from "../components/ui/button-components";
import { Input } from "../components/ui/input";
import { PageContainer, PageHeader } from "../components/ui/page-header";
import { Skeleton } from "../components/ui/skeleton";
import { templateOf } from "./Services";

export function Vaults({ canCreate }: { canCreate: boolean }) {
  const [page, setPage] = useState(1);
  const vaults = useLoad(() => get<Page<VaultOverview>>(`/vaults/overview?page=${page}`), [page]);
  const templates = useLoad(() => get<StoredTemplate[]>("/templates"), []);
  const all = useMemo(() => templates.data ?? [], [templates.data]);
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const action = useAction();

  const create = async (e: FormEvent) => {
    e.preventDefault();
    const v = await action.run(() => post<Vault>("/vaults", { name }));
    if (v) {
      setName("");
      setOpen(false);
      window.location.hash = `#/vaults/${v.id}/credentials`;
    }
  };

  const createButton = (
    <Button
      type="button"
      onClick={() => setOpen(true)}
      disabled={!canCreate}
      title={canCreate ? undefined : "Only admins can create vaults"}
    >
      <Plus />
      Create vault
    </Button>
  );

  // A page emptied under the list (its vaults deleted elsewhere): go back a page.
  const back = vaults.data ? fallbackPage(vaults.data) : null;
  useEffect(() => {
    if (back !== null) setPage(back);
  }, [back]);

  return (
    <PageContainer>
      <PageHeader title="Vaults" actions={createButton} />
      <ErrorBanner error={vaults.error ?? templates.error} />
      {vaults.loading && !vaults.data ? (
        <div className={GRID}>
          {[0, 1, 2].map((i) => (
            <Skeleton key={i} className="h-56 rounded-lg" />
          ))}
        </div>
      ) : vaults.data && vaults.data.items.length === 0 && back === null ? (
        <Panel>
          <Empty
            icon={VaultIcon}
            title="No vaults yet"
            description={
              canCreate
                ? "Create a vault, then add a service such as a GitHub token and a rule that allows it."
                : "An admin has to create the first vault."
            }
            action={canCreate ? createButton : undefined}
          />
        </Panel>
      ) : (
        <div className={GRID}>
          {vaults.data?.items.map((v) => (
            <VaultPanel key={v.id} vault={v} templates={all} />
          ))}
        </div>
      )}
      {vaults.data && hasPager(vaults.data) && (
        <Panel>
          <Pager page={vaults.data} onPage={setPage} />
        </Panel>
      )}
      <FormDialog
        open={open}
        onOpenChange={(o) => {
          setOpen(o);
          if (!o) action.clearError();
        }}
        title="Create vault"
        description="Credentials, rules and sessions all live inside one vault. API keys are bound to a single vault."
      >
        <form onSubmit={create} className="space-y-4">
          <ErrorBanner error={action.error} />
          <Field label="Name" htmlFor="vault-name">
            <Input id="vault-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="ci-agents" autoFocus required />
          </Field>
          <DialogActions>
            <Button type="button" variant="outline" onClick={() => setOpen(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={action.busy}>
              Create vault
            </Button>
          </DialogActions>
        </form>
      </FormDialog>
    </PageContainer>
  );
}

/** One vault: whether it is in use, its first services and its last request. */
function VaultPanel({ vault, templates }: { vault: VaultOverview; templates: StoredTemplate[] }) {
  const href = `#/vaults/${vault.id}/credentials`;
  const more = vault.service_count - vault.services.length;
  return (
    <Panel className="relative flex flex-col transition-colors hover:border-foreground/25 focus-within:border-foreground/40">
      <div className="flex items-center justify-between gap-2 px-4 pt-4">
        <h2 className="min-w-0 truncate text-base font-semibold">
          {/* The name's link covers the whole panel. */}
          <a href={href} className="after:absolute after:inset-0 after:rounded-lg focus-visible:outline-none">
            {vault.name}
          </a>
        </h2>
        {vault.live_sessions > 0 ? (
          <Status tone="success">{vault.live_sessions} live</Status>
        ) : (
          <Status tone="neutral">Idle</Status>
        )}
      </div>
      <div className="flex-1 px-4 py-3">
        {vault.services.length === 0 ? (
          <p className="py-2 text-sm text-warning-strong">
            No services yet.{" "}
            <a href={addServiceHref({ vault: vault.id })} className="relative z-10 underline underline-offset-2">
              Add one
            </a>
          </p>
        ) : (
          <ul className="space-y-1">
            {vault.services.map((c) => {
              const tpl = templateOf(templates, c);
              return (
                <li key={c.id} className="flex min-w-0 items-center gap-3 py-1">
                  <ServiceLogo template={tpl ?? { id: c.template_id, kind: "http" }} size="sm" />
                  <span className="min-w-0 truncate text-sm font-medium">{c.name}</span>
                  <span className="ml-auto min-w-0 truncate font-mono text-xs text-muted-foreground">
                    {targetHosts(tpl, c.host_override)[0] ?? ""}
                  </span>
                </li>
              );
            })}
            {more > 0 && <li className="pl-11 text-xs text-muted-foreground">+{more} more</li>}
          </ul>
        )}
      </div>
      <div className="border-t px-4 py-3 text-xs text-muted-foreground">
        {vault.last_request_at ? (
          <>
            Last request <Relative at={vault.last_request_at} />
          </>
        ) : (
          "No requests yet"
        )}
      </div>
    </Panel>
  );
}
