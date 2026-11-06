// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { useMemo, useState, type FormEvent } from "react";
import { Braces, Lock, Plus, RefreshCw, Search, ShieldCheck, Trash2 } from "lucide-react";
import { del, get, post, put, type Page, type Variable } from "../api";
import { useAction, useLoad } from "../hooks";
import {
  ConfirmDialog,
  DialogActions,
  Empty,
  ErrorBanner,
  Field,
  FormDialog,
  Loading,
  Mono,
  Pager,
  Panel,
  RowActions,
  useConfirm,
  When,
} from "../components/common";
import { Alert, AlertDescription, AlertTitle } from "../components/ui/alert";
import { Button } from "../components/ui/button-components";
import { Input } from "../components/ui/input";
import { PageContainer, PageHeader } from "../components/ui/page-header";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../components/ui/table";

const KEY = /^[A-Z][A-Z0-9_]{0,63}$/;

export function Variables({ isAdmin }: { isAdmin: boolean }) {
  const [page, setPage] = useState(1);
  const vars = useLoad(
    () => (isAdmin ? get<Page<Variable>>(`/variables?page=${page}`) : Promise.resolve(undefined)),
    [page, isAdmin],
  );
  const [query, setQuery] = useState("");
  const [adding, setAdding] = useState(false);
  const [replacing, setReplacing] = useState<Variable | null>(null);
  const confirm = useConfirm<Variable>();
  const action = useAction();
  const items = useMemo(
    () => (vars.data?.items ?? []).filter((v) => v.key.includes(query.trim().toUpperCase())),
    [vars.data, query],
  );

  const remove = async (v: Variable) => {
    await action.run(() => del(`/variables/${v.id}`));
    confirm.close();
    vars.reload();
  };

  const addButton = (
    <Button type="button" onClick={() => setAdding(true)} disabled={!isAdmin}>
      <Plus />
      Add variable
    </Button>
  );

  return (
    <PageContainer>
      <PageHeader
        title="Variables"
        description={
          <>
            Secrets stored once and referenced as <Mono>{"{{NAME}}"}</Mono> from a service's credential fields or custom
            headers. Replacing a value updates every service that uses it at the proxies' next policy refresh.
          </>
        }
        actions={addButton}
      />
      {!isAdmin ? (
        <Alert>
          <ShieldCheck className="size-4" />
          <AlertTitle>Variables are managed by admins</AlertTitle>
          <AlertDescription>
            Ask an admin to create a variable; you can then see which services use it in each vault.
          </AlertDescription>
        </Alert>
      ) : (
        <>
          <ErrorBanner error={vars.error ?? action.error} />
          <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
            <div className="relative w-full sm:w-72">
              <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search keys…"
                className="pl-9"
                aria-label="Search variables"
              />
            </div>
            <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
              <Lock className="size-3.5" />
              Values are write-only: nobody, admins included, can read one back.
            </p>
          </div>
          <Panel>
            {vars.loading && !vars.data ? (
              <Loading />
            ) : vars.data?.items.length === 0 ? (
              <Empty
                icon={Braces}
                title="No variables yet"
                description={
                  <>
                    Store a secret once, for example <Mono>GITHUB_TOKEN</Mono>, then pick it when adding a service or
                    type <Mono>{"{{GITHUB_TOKEN}}"}</Mono> in a custom header.
                  </>
                }
                action={addButton}
              />
            ) : items.length === 0 ? (
              <Empty icon={Search} title="No variable matches" description={`Nothing matches “${query}”.`} />
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Key</TableHead>
                    <TableHead>Value</TableHead>
                    <TableHead>Used by</TableHead>
                    <TableHead>Updated</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {items.map((v) => (
                    <TableRow key={v.id}>
                      <TableCell>
                        <Mono className="font-medium">{v.key}</Mono>
                      </TableCell>
                      <TableCell>
                        <span
                          className="inline-flex items-center gap-1.5 font-mono text-xs text-muted-foreground"
                          title="Write-only: the value cannot be shown"
                        >
                          <Lock className="size-3" />
                          ••••••••
                        </span>
                      </TableCell>
                      <TableCell>
                        {v.used_by.length === 0 ? (
                          <span className="text-xs text-muted-foreground">not used</span>
                        ) : (
                          <div className="flex flex-wrap gap-1">
                            {v.used_by.map((u) => (
                              <a
                                key={u.credential_id}
                                href={`#/vaults/${u.vault_id}`}
                                className="inline-flex items-center rounded border bg-muted/40 px-1.5 py-0.5 text-xs hover:bg-accent"
                              >
                                {u.credential_name}
                                <span className="ml-1 text-muted-foreground">· {u.vault_name}</span>
                              </a>
                            ))}
                          </div>
                        )}
                      </TableCell>
                      <TableCell className="text-muted-foreground">
                        <When at={v.updated_at} />
                      </TableCell>
                      <TableCell>
                        <RowActions>
                          <Button type="button" variant="outline" size="sm" onClick={() => setReplacing(v)}>
                            <RefreshCw />
                            <span className="hidden sm:inline">Replace value</span>
                          </Button>
                          <Button
                            type="button"
                            variant="ghost"
                            size="sm"
                            className="text-destructive hover:text-destructive"
                            aria-label={`Delete ${v.key}`}
                            disabled={v.used_by.length > 0}
                            title={v.used_by.length > 0 ? "Remove it from the services that use it first" : undefined}
                            onClick={() => confirm.ask(v)}
                          >
                            <Trash2 />
                          </Button>
                        </RowActions>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
            <Pager page={vars.data} onPage={setPage} />
          </Panel>
        </>
      )}
      <FormDialog
        open={adding}
        onOpenChange={setAdding}
        title="Add a variable"
        description="The value is encrypted and can never be read back, only replaced."
      >
        <VariableForm
          onCancel={() => setAdding(false)}
          onSubmit={(key, value) => post<Variable>("/variables", { key, value })}
          onDone={() => {
            setAdding(false);
            vars.reload();
          }}
        />
      </FormDialog>
      <FormDialog
        open={replacing !== null}
        onOpenChange={(o) => {
          if (!o) setReplacing(null);
        }}
        title={replacing ? `Replace ${replacing.key}` : "Replace value"}
        description={
          replacing?.used_by.length
            ? `${replacing.used_by.length} service(s) pick up the new value at the proxies' next policy refresh. The old value cannot be recovered.`
            : "The old value cannot be recovered."
        }
      >
        {replacing && (
          <VariableForm
            fixedKey={replacing.key}
            onCancel={() => setReplacing(null)}
            onSubmit={(_, value) => put<Variable>(`/variables/${replacing.id}`, { value })}
            onDone={() => {
              setReplacing(null);
              vars.reload();
            }}
          />
        )}
      </FormDialog>
      <ConfirmDialog
        open={confirm.open}
        onOpenChange={confirm.onOpenChange}
        title={`Delete variable ${confirm.target?.key ?? ""}?`}
        description="The value is destroyed. Services cannot reference it any more."
        confirmLabel="Delete variable"
        destructive
        busy={action.busy}
        onConfirm={() => {
          if (confirm.target) void remove(confirm.target);
        }}
      />
    </PageContainer>
  );
}

function VariableForm({
  fixedKey,
  onCancel,
  onSubmit,
  onDone,
}: {
  fixedKey?: string;
  onCancel: () => void;
  onSubmit: (key: string, value: string) => Promise<Variable>;
  onDone: () => void;
}) {
  const [key, setKey] = useState(fixedKey ?? "");
  const [value, setValue] = useState("");
  const action = useAction();
  const keyProblem = key && !KEY.test(key) ? "Use uppercase letters, digits and _, starting with a letter." : null;
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const saved = await action.run(() => onSubmit(key, value));
    // Never keep a secret in memory longer than needed.
    setValue("");
    if (saved) onDone();
  };
  return (
    <form className="space-y-4" onSubmit={submit} autoComplete="off">
      <ErrorBanner error={action.error} />
      <Field label="Key" htmlFor="var-key" hint={keyProblem ?? "Referenced as {{KEY}}."}>
        <Input
          id="var-key"
          value={key}
          onChange={(e) => setKey(e.target.value.toUpperCase().replace(/[\s-]/g, "_"))}
          placeholder="GITHUB_TOKEN"
          className="font-mono"
          disabled={fixedKey !== undefined}
          aria-invalid={keyProblem !== null}
          required
        />
      </Field>
      <Field label={fixedKey ? "New value" : "Value"} htmlFor="var-value">
        <Input
          id="var-value"
          type="password"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          className="font-mono"
          spellCheck={false}
          autoComplete="new-password"
          required
        />
      </Field>
      <DialogActions>
        <Button type="button" variant="outline" onClick={onCancel}>
          Cancel
        </Button>
        <Button type="submit" disabled={action.busy || keyProblem !== null || !value}>
          {fixedKey ? "Replace value" : "Save variable"}
        </Button>
      </DialogActions>
    </form>
  );
}
