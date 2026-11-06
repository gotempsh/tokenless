// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { useState, type FormEvent } from "react";
import { FolderLock as VaultIcon, Plus } from "lucide-react";
import { get, post, type Page, type Vault } from "../api";
import { useAction, useLoad } from "../hooks";
import { DialogActions, Empty, ErrorBanner, Field, FormDialog, Loading, Pager, Panel, rowLink, When } from "../components/common";
import { Button } from "../components/ui/button-components";
import { Input } from "../components/ui/input";
import { PageContainer, PageHeader } from "../components/ui/page-header";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../components/ui/table";

export function Vaults({ canCreate }: { canCreate: boolean }) {
  const [page, setPage] = useState(1);
  const vaults = useLoad(() => get<Page<Vault>>(`/vaults?page=${page}`), [page]);
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

  return (
    <PageContainer>
      <PageHeader
        title="Vaults"
        description="A vault groups credentials, the rules that let them be injected, and the proxy sessions that may use those rules."
        actions={createButton}
      />
      <ErrorBanner error={vaults.error} />
      <Panel>
        {vaults.loading && !vaults.data ? (
          <Loading />
        ) : vaults.data && vaults.data.items.length === 0 ? (
          <Empty
            icon={VaultIcon}
            title="No vaults yet"
            description={
              canCreate
                ? "Create a vault, then add a credential such as a GitHub token, and a rule that allows it."
                : "An admin has to create the first vault."
            }
            action={canCreate ? createButton : undefined}
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Created</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {vaults.data?.items.map((v) => (
                <TableRow key={v.id} {...rowLink(`#/vaults/${v.id}/credentials`)}>
                  <TableCell className="font-medium">{v.name}</TableCell>
                  <TableCell className="text-muted-foreground">
                    <When at={v.created_at} />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
        <Pager page={vaults.data} onPage={setPage} />
      </Panel>
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
