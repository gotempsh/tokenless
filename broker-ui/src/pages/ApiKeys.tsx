// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { useState, type FormEvent } from "react";
import { KeySquare, Plus } from "lucide-react";
import { del, get, post, type ApiKey, type Page, type Role, type Vault } from "../api";
import { useAction, useLoad } from "../hooks";
import {
  ChoiceCards,
  ConfirmDialog,
  DialogActions,
  Empty,
  ErrorBanner,
  Field,
  FormDialog,
  Loading,
  Mono,
  OneTimeSecret,
  Pager,
  Panel,
  RowActions,
  SelectField,
  Status,
  useConfirm,
  When,
  type Choice,
} from "../components/common";
import { Button } from "../components/ui/button-components";
import { Input } from "../components/ui/input";
import { PageContainer, PageHeader } from "../components/ui/page-header";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../components/ui/table";

type KeyRole = Extract<Role, "session_issuer" | "viewer" | "editor">;

const KEY_ROLES: Choice<KeyRole>[] = [
  { value: "session_issuer", title: "Session issuer", description: "Mint proxy sessions only" },
  { value: "viewer", title: "Viewer", description: "Read the vault" },
  { value: "editor", title: "Editor", description: "Manage rules and sessions" },
];

const EMPTY_FORM = { name: "", vault_id: "", role: "session_issuer" as KeyRole, expires_in_days: 30 };

function keyStatus(k: ApiKey) {
  if (k.revoked_at) return <Status tone="destructive">revoked</Status>;
  if (new Date(k.expires_at) <= new Date()) return <Status tone="neutral">expired</Status>;
  return <Status tone="success">active</Status>;
}

export function ApiKeys() {
  const [page, setPage] = useState(1);
  const keys = useLoad(() => get<Page<ApiKey>>(`/api-keys?page=${page}`), [page]);
  const vaults = useLoad(() => get<Page<Vault>>("/vaults?page_size=100"), []);
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState(EMPTY_FORM);
  const [created, setCreated] = useState<string | null>(null);
  const confirm = useConfirm<ApiKey>();
  const createAction = useAction();
  const action = useAction();
  const vaultName = (id: string) => vaults.data?.items.find((v) => v.id === id)?.name ?? id;

  const create = async (e: FormEvent) => {
    e.preventDefault();
    const result = await createAction.run(() => post<{ api_key: string; key: ApiKey }>("/api-keys", form));
    if (result) {
      setCreated(result.api_key);
      setForm(EMPTY_FORM);
      keys.reload();
    }
  };

  const close = (o: boolean) => {
    setOpen(o);
    if (!o) {
      setCreated(null);
      createAction.clearError();
    }
  };

  const revoke = async (k: ApiKey) => {
    await action.run(() => del(`/api-keys/${k.id}`));
    confirm.close();
    keys.reload();
  };

  const createButton = (
    <Button type="button" onClick={() => setOpen(true)}>
      <Plus />
      Create API key
    </Button>
  );

  return (
    <PageContainer>
      <PageHeader
        title="API keys"
        description="Keys let automation mint proxy sessions or manage one vault. Each key belongs to exactly one vault and role, and expires. Only a hash is stored."
        actions={createButton}
      />
      <ErrorBanner error={keys.error ?? action.error} />
      <Panel>
        {keys.loading && !keys.data ? (
          <Loading />
        ) : keys.data?.items.length === 0 ? (
          <Empty
            icon={KeySquare}
            title="No API keys"
            description="Create a session-issuer key so a CI job or orchestrator can mint short-lived proxy sessions for its agents."
            action={createButton}
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Prefix</TableHead>
                <TableHead>Vault</TableHead>
                <TableHead>Role</TableHead>
                <TableHead>Expires</TableHead>
                <TableHead>Last used</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {keys.data?.items.map((k) => (
                <TableRow key={k.id}>
                  <TableCell className="font-medium">{k.name}</TableCell>
                  <TableCell>
                    <Mono>{k.prefix}</Mono>
                  </TableCell>
                  <TableCell>{vaultName(k.vault_id)}</TableCell>
                  <TableCell>{k.role.replace("_", " ")}</TableCell>
                  <TableCell className="text-muted-foreground">
                    <When at={k.expires_at} />
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    <When at={k.last_used_at} />
                  </TableCell>
                  <TableCell>{keyStatus(k)}</TableCell>
                  <TableCell>
                    <RowActions>
                      {!k.revoked_at && (
                        <Button type="button" variant="outline" size="sm" onClick={() => confirm.ask(k)}>
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
        <Pager page={keys.data} onPage={setPage} />
      </Panel>
      <FormDialog
        open={open}
        onOpenChange={close}
        wide
        title={created ? "API key created" : "Create an API key"}
        description={created ? undefined : "The key is shown once after it is created."}
      >
        {created ? (
          <div className="space-y-4">
            <OneTimeSecret
              label="API key"
              value={created}
              hint={
                <code className="block break-all rounded-md border bg-background px-3 py-2 font-mono text-xs">
                  Authorization: Bearer {created.slice(0, 16)}…
                </code>
              }
            />
            <DialogActions>
              <Button type="button" onClick={() => close(false)}>
                Done
              </Button>
            </DialogActions>
          </div>
        ) : (
          <form className="space-y-4" onSubmit={create}>
            <ErrorBanner error={createAction.error} />
            <div className="space-y-4">
              <Field label="Name" htmlFor="key-name">
                <Input
                  id="key-name"
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                  placeholder="ci-orchestrator"
                  required
                />
              </Field>
              <Field
                label="Vault"
                htmlFor="key-vault"
                hint={
                  vaults.data?.items.length === 0 ? (
                    <>
                      No vaults yet. <a href="#/vaults" className="underline">Create one</a> first.
                    </>
                  ) : undefined
                }
              >
                <SelectField
                  id="key-vault"
                  value={form.vault_id}
                  onChange={(v) => setForm({ ...form, vault_id: v })}
                  placeholder="Choose…"
                  options={(vaults.data?.items ?? []).map((v) => ({ value: v.id, label: v.name }))}
                />
              </Field>
            </div>
            <div className="space-y-2">
              <p className="text-sm font-medium">Role</p>
              <ChoiceCards
                name="key-role"
                value={form.role}
                onChange={(role) => setForm({ ...form, role })}
                choices={KEY_ROLES}
              />
            </div>
            <Field label="Expires in (days)" htmlFor="key-expiry" hint="Between 1 and 365.">
              <Input
                id="key-expiry"
                type="number"
                min={1}
                max={365}
                className="md:w-40"
                value={form.expires_in_days}
                onChange={(e) => setForm({ ...form, expires_in_days: Number(e.target.value) })}
              />
            </Field>
            <DialogActions>
              <Button type="button" variant="outline" onClick={() => close(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={createAction.busy || !form.vault_id}>
                Create API key
              </Button>
            </DialogActions>
          </form>
        )}
      </FormDialog>
      <ConfirmDialog
        open={confirm.open}
        onOpenChange={confirm.onOpenChange}
        title={`Revoke API key "${confirm.target?.name ?? ""}"?`}
        description="Anything using this key is refused immediately. Sessions it already minted keep running until they expire."
        confirmLabel="Revoke key"
        busy={action.busy}
        onConfirm={() => {
          if (confirm.target) void revoke(confirm.target);
        }}
      />
    </PageContainer>
  );
}
