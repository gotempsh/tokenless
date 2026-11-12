// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Tripwires: decoy credentials planted on agents' machines. A session that
// sends one is cut off and an alert raised, because only someone who took
// it from the machine would.

import { useState, type FormEvent } from "react";
import { Plus, Siren, Trash2 } from "lucide-react";
import { del, get, post, type CreatedTripwire, type Page, type Tripwire, type TripwireKind } from "../api";
import { can, type Me } from "../access";
import { kindLabel, TRIPWIRE_KINDS, whereSeen } from "../tripwires";
import { useAction, useLoad } from "../hooks";
import {
  fromWidth,
  ChoiceCards,
  ConfirmDialog,
  CopyButton,
  DialogActions,
  Empty,
  ErrorBanner,
  Field,
  FormDialog,
  Loading,
  Mono,
  Pager,
  Panel,
  Relative,
  RowActions,
  RowMenu,
  Section,
  Status,
  useConfirm,
} from "../components/common";
import { cn } from "../lib/utils";
import { Alert, AlertDescription, AlertTitle } from "../components/ui/alert";
import { Button } from "../components/ui/button-components";
import { Input } from "../components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../components/ui/table";
import { ALERTS_HREF } from "./Alerts";

export function VaultTripwires({ vaultId, user }: { vaultId: string; user: Me }) {
  const [page, setPage] = useState(1);
  const tripwires = useLoad(() => get<Page<Tripwire>>(`/vaults/${vaultId}/tripwires?page=${page}`), [vaultId, page]);
  const [adding, setAdding] = useState(false);
  const confirm = useConfirm<Tripwire>();
  const action = useAction();
  const canChange = can(user, vaultId, "edit");

  const remove = async (t: Tripwire) => {
    await action.run(() => del(`/tripwires/${t.id}`));
    confirm.close();
    tripwires.reload();
  };

  const addButton = (
    <Button type="button" onClick={() => setAdding(true)} disabled={!canChange}>
      <Plus />
      Plant a tripwire
    </Button>
  );

  return (
    <Section title="Tripwires" actions={addButton}>
      <ErrorBanner error={tripwires.error ?? action.error} />
      <Panel>
        {tripwires.loading && !tripwires.data ? (
          <Loading />
        ) : tripwires.data?.items.length === 0 ? (
          <Empty
            icon={Siren}
            title="No tripwires yet"
            description="Plant a fake key where the agent's real ones would be. A session that sends it is cut off and you are alerted: only someone who took it from the machine would."
            action={addButton}
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Tripwire</TableHead>
                <TableHead className={fromWidth.md}>Kind</TableHead>
                <TableHead className={fromWidth.lg}>Planted</TableHead>
                <TableHead>Tripped</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {tripwires.data?.items.map((t) => (
                <TableRow key={t.id}>
                  <TableCell>
                    <div className="font-medium">{t.name}</div>
                    <div className="text-xs text-muted-foreground">
                      <Mono>{t.prefix}…</Mono>
                      <span className="@md:hidden"> · {kindLabel(t.kind)}</span>
                    </div>
                  </TableCell>
                  <TableCell className={cn(fromWidth.md, "text-muted-foreground")}>{kindLabel(t.kind)}</TableCell>
                  <TableCell className={cn(fromWidth.lg, "text-muted-foreground")}>
                    <Relative at={t.created_at} />
                  </TableCell>
                  <TableCell>
                    {t.last_tripped_at ? (
                      <a href={ALERTS_HREF}>
                        <Status tone="destructive">
                          tripped <Relative at={t.last_tripped_at} />
                        </Status>
                      </a>
                    ) : (
                      <span className="text-muted-foreground">never</span>
                    )}
                  </TableCell>
                  <TableCell>
                    <RowActions>
                      <RowMenu
                        label={t.name}
                        items={[
                          {
                            label: "Delete tripwire",
                            icon: Trash2,
                            onSelect: () => confirm.ask(t),
                            destructive: true,
                            disabled: !canChange,
                            reason: "Only the vault's editors and admins can delete tripwires",
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
        <Pager page={tripwires.data} onPage={setPage} />
      </Panel>
      <FormDialog open={adding} onOpenChange={setAdding} title="Plant a tripwire" wide>
        {adding && (
          <PlantForm
            vaultId={vaultId}
            onCancel={() => setAdding(false)}
            onCreated={() => tripwires.reload()}
          />
        )}
      </FormDialog>
      <ConfirmDialog
        open={confirm.open}
        onOpenChange={confirm.onOpenChange}
        title={confirm.target ? `Delete tripwire "${confirm.target.name}"?` : "Delete tripwire"}
        description="Proxies stop looking for its key, so a session that sends it is no longer cut off. Remove the key from the machine too."
        confirmLabel="Delete tripwire"
        busy={action.busy}
        onConfirm={() => confirm.target && void remove(confirm.target)}
      />
    </Section>
  );
}

function PlantForm({ vaultId, onCancel, onCreated }: { vaultId: string; onCancel: () => void; onCreated: () => void }) {
  const [name, setName] = useState("");
  const [kind, setKind] = useState<TripwireKind>("aws");
  const [created, setCreated] = useState<CreatedTripwire | null>(null);
  const action = useAction();

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const done = await action.run(() => post<CreatedTripwire>(`/vaults/${vaultId}/tripwires`, { name, kind }));
    if (done) {
      setCreated(done);
      onCreated();
    }
  };

  if (created) {
    return (
      <div className="space-y-4">
        <Alert variant="warning">
          <Siren className="size-4" />
          <AlertTitle>Plant it now: this is the only time the key is shown</AlertTitle>
          <AlertDescription>
            Put it where the agent's user keeps real keys, somewhere the agent itself never reads, or its own requests trip it.
          </AlertDescription>
        </Alert>
        {created.plant.map((p) => (
          <Field key={p.place} label={`In ${p.place}`}>
            <div className="flex items-start gap-2">
              <pre className="min-w-0 flex-1 overflow-x-auto whitespace-pre-wrap break-all rounded-md border bg-background px-3 py-2 font-mono text-xs text-foreground">
                {p.text}
              </pre>
              <CopyButton value={`${p.text}\n`} label="Copy" />
            </div>
          </Field>
        ))}
        <p className="text-xs text-muted-foreground">{whereSeen(created.tripwire.kind)}</p>
        <DialogActions>
          <Button type="button" onClick={onCancel}>
            Done
          </Button>
        </DialogActions>
      </div>
    );
  }

  return (
    <form className="space-y-4" onSubmit={submit}>
      <ErrorBanner error={action.error} />
      <Field label="Where it is planted" htmlFor="tripwire-name" hint="The machine or sandbox, so an alert says which one was entered.">
        <Input
          id="tripwire-name"
          value={name}
          maxLength={100}
          required
          onChange={(e) => setName(e.target.value)}
          placeholder="build-runner-2"
        />
      </Field>
      <Field label="Looks like">
        <ChoiceCards<TripwireKind>
          name="tripwire-kind"
          value={kind}
          onChange={setKind}
          columns={2}
          choices={TRIPWIRE_KINDS.map((k) => ({ value: k.value, title: k.label, description: k.description }))}
        />
      </Field>
      <DialogActions>
        <Button type="button" variant="outline" onClick={onCancel}>
          Cancel
        </Button>
        <Button type="submit" disabled={action.busy || name.trim() === ""}>
          Create the key
        </Button>
      </DialogActions>
    </form>
  );
}
