// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// A bundle's launcher keys: what an agent machine (CI, a server, a shared
// box) starts its sessions with, instead of someone's sign-in.

import { useState, type FormEvent } from "react";
import { KeyRound, Plus, Trash2 } from "lucide-react";
import {
  get,
  post,
  type AccessBundle,
  type CreatedLauncherKey,
  type LauncherKey,
  type Page,
  type RevokedLauncherKey,
} from "../api";
import { useAction, useLoad } from "../hooks";
import { keyRunCommand, keyState, KEY_SAVE_COMMAND, lengthChoices, sessionLength, type KeyState } from "../launcherKeys";
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
  OneTimeSecret,
  Panel,
  RowActions,
  RowMenu,
  Section,
  SelectField,
  Status,
  useConfirm,
  When,
} from "../components/common";
import { cn } from "../lib/utils";
import { Button } from "../components/ui/button-components";
import { Input } from "../components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../components/ui/table";
import { CommandSnippet } from "./Bundles";

interface SessionLimits {
  max_ttl_secs: number;
  default_ttl_secs: number;
}

function stateBadge(state: KeyState) {
  if (state === "revoked") return <Status tone="destructive">revoked</Status>;
  if (state === "expired") return <Status tone="neutral">expired</Status>;
  return <Status tone="success">active</Status>;
}

export function BundleLauncherKeys({
  bundle,
  vaultName,
  canEdit,
}: {
  bundle: AccessBundle;
  vaultName?: string;
  canEdit: boolean;
}) {
  const keys = useLoad(
    () => get<Page<LauncherKey>>(`/vaults/${bundle.vault_id}/launcher-keys?bundle_id=${bundle.id}&page_size=100`),
    [bundle.id],
  );
  const [open, setOpen] = useState(false);
  const confirm = useConfirm<LauncherKey>();
  const action = useAction();
  const [revoked, setRevoked] = useState<RevokedLauncherKey | null>(null);
  const now = new Date();

  const revoke = async (k: LauncherKey) => {
    const done = await action.run(() =>
      post<RevokedLauncherKey>(`/vaults/${bundle.vault_id}/launcher-keys/${k.id}/revoke`),
    );
    confirm.close();
    if (done) setRevoked(done);
    keys.reload();
  };

  const newButton = (
    <Button
      type="button"
      onClick={() => setOpen(true)}
      disabled={!canEdit}
      title={canEdit ? undefined : "Only the vault's editors and admins can create launcher keys"}
    >
      <Plus />
      New launcher key
    </Button>
  );

  return (
    <Section
      title="Launcher keys"
      description="For a machine that runs agents on its own, such as CI or a server: it starts this bundle's sessions and nothing else."
      actions={newButton}
    >
      <ErrorBanner error={keys.error ?? action.error} />
      {revoked && (
        <p className="text-sm text-muted-foreground" role="status">
          Revoked <span className="font-medium text-foreground">{revoked.launcher_key.name}</span> and ended{" "}
          {revoked.sessions_revoked} live session{revoked.sessions_revoked === 1 ? "" : "s"} it had started.
        </p>
      )}
      <Panel>
        {keys.loading && !keys.data ? (
          <Loading />
        ) : keys.data?.items.length === 0 ? (
          <Empty
            icon={KeyRound}
            title="No launcher keys"
            description={`A launcher key lets a machine start ${bundle.name} sessions without anyone's sign-in on it, so whoever gets onto that machine reaches this bundle and nothing more.`}
            action={newButton}
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead className={fromWidth["3xl"]}>Prefix</TableHead>
                <TableHead className={fromWidth.xl}>Sessions up to</TableHead>
                <TableHead className={fromWidth["2xl"]}>Last used</TableHead>
                <TableHead className={fromWidth["4xl"]}>Expires</TableHead>
                <TableHead className={fromWidth.md}>Status</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {keys.data?.items.map((k) => {
                const state = keyState(k, now);
                return (
                  <TableRow key={k.id}>
                    <TableCell>
                      <div className="font-medium">{k.name}</div>
                      <div className="text-xs text-muted-foreground @2xl:hidden">
                        last used <When at={k.last_used_at} />
                      </div>
                      <div className="mt-1 @md:hidden">{stateBadge(state)}</div>
                    </TableCell>
                    <TableCell className={fromWidth["3xl"]}>
                      <Mono>{k.prefix}</Mono>
                    </TableCell>
                    <TableCell className={fromWidth.xl}>
                      {sessionLength(k.max_ttl_secs)}
                      {k.request_limit !== undefined && (
                        <span className="text-muted-foreground"> · {k.request_limit} requests</span>
                      )}
                    </TableCell>
                    <TableCell className={cn(fromWidth["2xl"], "text-muted-foreground")}>
                      <When at={k.last_used_at} />
                    </TableCell>
                    <TableCell className={cn(fromWidth["4xl"], "text-muted-foreground")}>
                      <When at={k.expires_at} />
                    </TableCell>
                    <TableCell className={fromWidth.md}>{stateBadge(state)}</TableCell>
                    <TableCell>
                      <RowActions>
                        {state !== "revoked" && canEdit && (
                          <RowMenu
                            label={`Actions for ${k.name}`}
                            items={[
                              {
                                label: "Revoke",
                                icon: Trash2,
                                destructive: true,
                                onSelect: () => confirm.ask(k),
                              },
                            ]}
                          />
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
      <NewLauncherKeyDialog
        bundle={bundle}
        vaultName={vaultName}
        open={open}
        onOpenChange={setOpen}
        onCreated={keys.reload}
      />
      <ConfirmDialog
        open={confirm.open}
        onOpenChange={confirm.onOpenChange}
        title={`Revoke "${confirm.target?.name ?? ""}"?`}
        description="The key stops working at once, and the live sessions it started are ended, so the machine holding it is cut off."
        confirmLabel="Revoke key"
        destructive
        busy={action.busy}
        onConfirm={() => {
          if (confirm.target) void revoke(confirm.target);
        }}
      />
    </Section>
  );
}

function NewLauncherKeyDialog({
  bundle,
  vaultName,
  open,
  onOpenChange,
  onCreated,
}: {
  bundle: AccessBundle;
  vaultName?: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onCreated: () => void;
}) {
  const limits = useLoad(
    () => (open ? get<SessionLimits>(`/vaults/${bundle.vault_id}/sessions/limits`) : Promise.resolve(undefined)),
    [open, bundle.vault_id],
  );
  const [name, setName] = useState("");
  const [length, setLength] = useState("900");
  const [requestLimit, setRequestLimit] = useState("");
  const [created, setCreated] = useState<CreatedLauncherKey | null>(null);
  const action = useAction();
  const choices = lengthChoices(limits.data?.max_ttl_secs ?? 15 * 60);

  const close = (o: boolean) => {
    onOpenChange(o);
    if (!o) {
      setCreated(null);
      setName("");
      setRequestLimit("");
      action.clearError();
    }
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const limit = requestLimit.trim() === "" ? undefined : Number(requestLimit);
    const result = await action.run(() =>
      post<CreatedLauncherKey>(`/vaults/${bundle.vault_id}/launcher-keys`, {
        name: name.trim(),
        bundle: bundle.id,
        max_ttl_secs: Number(length),
        request_limit: limit,
      }),
    );
    if (result) {
      setCreated(result);
      onCreated();
    }
  };

  return (
    <FormDialog
      open={open}
      onOpenChange={close}
      wide={created !== null}
      title={created ? "Launcher key created" : `New launcher key for ${bundle.name}`}
      description={created ? undefined : "The key is shown once after it is created."}
    >
      {created ? (
        <div className="space-y-4">
          <OneTimeSecret label="Launcher key" value={created.key} />
          <div className="space-y-2 text-sm">
            <p>On the agent machine, save it where only you can read it (paste it, then Ctrl-D):</p>
            <CommandSnippet command={KEY_SAVE_COMMAND} />
            <p>Then start the agent with it:</p>
            <CommandSnippet command={keyRunCommand(bundle.name, "claude", vaultName)} />
          </div>
          <DialogActions>
            <Button type="button" onClick={() => close(false)}>
              Done
            </Button>
          </DialogActions>
        </div>
      ) : (
        <form className="space-y-4" onSubmit={submit}>
          <ErrorBanner error={limits.error ?? action.error} />
          <Field label="Name" htmlFor="launcher-key-name" hint="The machine it goes on, so you know which one to cut off.">
            <Input
              id="launcher-key-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="build-runner"
              maxLength={100}
              required
            />
          </Field>
          <Field
            label="Sessions last up to"
            htmlFor="launcher-key-length"
            hint="The machine renews them while the agent runs, so short is fine."
          >
            <SelectField
              id="launcher-key-length"
              value={length}
              onChange={setLength}
              options={choices.map((s) => ({ value: String(s), label: sessionLength(s) }))}
            />
          </Field>
          <Field
            label="Requests per session"
            htmlFor="launcher-key-limit"
            hint="Leave empty for no limit."
          >
            <Input
              id="launcher-key-limit"
              type="number"
              min={1}
              inputMode="numeric"
              value={requestLimit}
              onChange={(e) => setRequestLimit(e.target.value)}
              placeholder="No limit"
            />
          </Field>
          <DialogActions>
            <Button type="button" variant="outline" onClick={() => close(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={action.busy || name.trim() === ""}>
              Create key
            </Button>
          </DialogActions>
        </form>
      )}
    </FormDialog>
  );
}
