// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { useMemo, useState, type FormEvent } from "react";
import { Braces, Lock, Plus, RefreshCw, Search, ShieldCheck, Trash2 } from "lucide-react";
import { del, get, post, put, type Page, type Variable } from "../api";
import { useAction, useLoad } from "../hooks";
import {
  fromWidth,
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
  RowMenu,
  useConfirm,
  When,
} from "../components/common";
import { cn } from "../lib/utils";
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

  // With nothing stored the empty state holds the one call to action.
  const empty = vars.data?.items.length === 0 && page === 1;

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
    <PageContainer width="settings">
      <PageHeader
        title="Variables"
        description={<>Use in a service as <Mono>{"{{NAME}}"}</Mono>.</>}
        actions={empty ? undefined : addButton}
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
          {!empty && (
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
          )}
          <Panel>
            {vars.loading && !vars.data ? (
              <Loading />
            ) : vars.data?.items.length === 0 ? (
              <Empty
                icon={Braces}
                title="No variables yet"
                description={
                  <>
                    Store a token once, then use it in any service as <Mono>{"{{GITHUB_TOKEN}}"}</Mono>.
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
                    <TableHead className={fromWidth["3xl"]}>Value</TableHead>
                    <TableHead className={fromWidth.xl}>Used by</TableHead>
                    <TableHead className={fromWidth.lg}>Updated</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {items.map((v) => (
                    <TableRow key={v.id}>
                      <TableCell>
                        <Mono className="font-medium [overflow-wrap:anywhere]">{v.key}</Mono>
                        <div className="text-xs text-muted-foreground @xl:hidden">
                          {v.used_by.length === 0
                            ? "not used"
                            : `used by ${v.used_by.length} service${v.used_by.length === 1 ? "" : "s"}`}
                        </div>
                      </TableCell>
                      <TableCell className={fromWidth["3xl"]}>
                        <span
                          className="inline-flex items-center gap-1.5 font-mono text-xs text-muted-foreground"
                          title="Write-only: the value cannot be shown"
                        >
                          <Lock className="size-3" />
                          ••••••••
                        </span>
                      </TableCell>
                      <TableCell className={fromWidth.xl}>
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
                      <TableCell className={cn(fromWidth.lg, "text-muted-foreground")}>
                        <When at={v.updated_at} />
                      </TableCell>
                      <TableCell>
                        <RowActions>
                          <RowMenu
                            label={v.key}
                            items={[
                              { label: "Replace value", icon: RefreshCw, onSelect: () => setReplacing(v) },
                              {
                                label: "Delete variable",
                                icon: Trash2,
                                onSelect: () => confirm.ask(v),
                                disabled: v.used_by.length > 0,
                                reason: "Remove it from the services that use it first",
                                destructive: true,
                              },
                            ]}
                          />
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
