// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Creates a session from an access bundle and shows its token once: the
// credential an agent is given instead of an API key or a secret.

import { useState, type FormEvent } from "react";
import { post, get, type AccessBundle, type MintedSession } from "../api";
import { useAction, useLoad } from "../hooks";
import {
  DialogActions,
  ErrorBanner,
  Exact,
  Field,
  FormDialog,
  Mono,
  OneTimeSecret,
  SelectField,
} from "../components/common";
import { Button } from "../components/ui/button-components";
import { Input } from "../components/ui/input";
import { defaultLifetime, lifetimeLabel, lifetimesUpTo, tokenCommands } from "../sessionForm";
import { CommandSnippet } from "./Bundles";

interface SessionLimits {
  max_ttl_secs: number;
  default_ttl_secs: number;
}

const EMPTY = { bundle: "", name: "", ttl: "", limit: "" };

export function NewSessionDialog({
  bundle: fixed,
  choices,
  vaultNames = {},
  open,
  onOpenChange,
  onCreated,
  isAdmin,
  agentCommand = "claude",
}: {
  /** The bundle the session is for; without it the form asks, from `choices`. */
  bundle?: AccessBundle;
  choices?: AccessBundle[];
  vaultNames?: Record<string, string>;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onCreated?: (minted: MintedSession) => void;
  isAdmin: boolean;
  /** The command the result's `tokenless run` line starts. */
  agentCommand?: string;
}) {
  const [form, setForm] = useState(EMPTY);
  // With a single bundle to choose from, it is chosen.
  const bundle = fixed ?? choices?.find((b) => b.id === form.bundle) ?? (choices?.length === 1 ? choices[0] : undefined);
  const vaultId = bundle?.vault_id;
  const limits = useLoad(
    () => (open && vaultId ? get<SessionLimits>(`/vaults/${vaultId}/sessions/limits`) : Promise.resolve(undefined)),
    [open, vaultId],
  );
  const [minted, setMinted] = useState<MintedSession | null>(null);
  const action = useAction();
  const max = limits.data?.max_ttl_secs;
  const lifetimes = max ? lifetimesUpTo(max) : [];
  const ttl = form.ttl || (max ? String(defaultLifetime(max)) : "");
  const limit = form.limit.trim();
  const limitProblem = limit && !/^[1-9][0-9]*$/.test(limit) ? "A whole number of requests, at least 1" : null;

  const close = (o: boolean) => {
    onOpenChange(o);
    if (!o) {
      setForm(EMPTY);
      setMinted(null);
      action.clearError();
    }
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!bundle) return;
    const name = form.name.trim();
    const result = await action.run(() =>
      post<MintedSession>(`/vaults/${bundle.vault_id}/sessions`, {
        bundle: bundle.id,
        ttl_secs: Number(ttl),
        request_limit: limit ? Number(limit) : undefined,
        labels: name ? { name } : {},
      }),
    );
    if (result) {
      setMinted(result);
      onCreated?.(result);
    }
  };

  const commands = minted ? tokenCommands(minted.token, agentCommand) : null;
  const bundleOptions = (choices ?? []).map((b) => ({
    value: b.id,
    label: vaultNames[b.vault_id] ? `${b.name} · ${vaultNames[b.vault_id]}` : b.name,
  }));
  return (
    <FormDialog
      open={open}
      onOpenChange={close}
      wide={minted !== null}
      title={minted ? "Session created" : fixed ? `New session for ${fixed.name}` : "New session"}
    >
      {minted && commands && bundle ? (
        <div className="space-y-4">
          <OneTimeSecret
            label="Session token"
            value={minted.token}
            hint={
              <>
                It reaches {bundle.name}'s services until <Exact at={minted.session.expires_at} />
                {minted.session.request_limit ? `, for ${minted.session.request_limit} requests,` : ""} or until you
                revoke it.
              </>
            }
          />
          <div className="space-y-2 text-sm">
            <p>In the agent's shell:</p>
            <CommandSnippet command={commands.exportLine} display={`${commands.exportLine.slice(0, 50)}…`} />
            <CommandSnippet command={commands.run} />
            <p className="text-xs text-muted-foreground">
              On another machine, also set <Mono>TOKENLESS_URL</Mono> to this console's address and{" "}
              <Mono>TOKENLESS_PROXY_ADDRESS</Mono> to a{" "}
              <a href="#/proxies" className="underline">
                proxy
              </a>
              's <Mono>host:port</Mono>.
            </p>
          </div>
          <DialogActions>
            <Button type="button" variant="outline" asChild>
              <a href={`#/sessions/${minted.session.id}`}>Open session</a>
            </Button>
            <Button type="button" onClick={() => close(false)}>
              Done
            </Button>
          </DialogActions>
        </div>
      ) : (
        <form className="space-y-4" onSubmit={submit}>
          <ErrorBanner error={limits.error ?? action.error} />
          {!fixed && (
            <Field
              label="Access bundle"
              htmlFor="session-bundle"
              hint={
                choices && choices.length === 0 ? (
                  <>
                    No access bundles yet.{" "}
                    <a href="#/bundles" className="underline">
                      Create one
                    </a>{" "}
                    first.
                  </>
                ) : (
                  "The services the session reaches."
                )
              }
            >
              <SelectField
                id="session-bundle"
                value={bundle?.id ?? ""}
                onChange={(v) => setForm({ ...form, bundle: v, ttl: "" })}
                options={bundleOptions}
                placeholder={choices ? "Choose a bundle" : "Loading…"}
              />
            </Field>
          )}
          <Field label="Name" htmlFor="session-name" hint="Shown on the Sessions page and in its logs.">
            <Input
              id="session-name"
              value={form.name}
              maxLength={256}
              placeholder="laptop-claude"
              onChange={(e) => setForm({ ...form, name: e.target.value })}
            />
          </Field>
          <Field
            label="Expires after"
            htmlFor="session-ttl"
            hint={
              max !== undefined && max < 90 * 86400 ? (
                <>
                  Settings allow up to {lifetimeLabel(max)}.
                  {isAdmin && (
                    <>
                      {" "}
                      <a href="#/settings" className="underline">
                        Allow longer
                      </a>
                    </>
                  )}
                </>
              ) : undefined
            }
          >
            <SelectField
              id="session-ttl"
              value={ttl}
              onChange={(v) => setForm({ ...form, ttl: v })}
              options={lifetimes.map((l) => ({ value: String(l.secs), label: l.label }))}
              placeholder={!bundle ? "Choose a bundle first" : limits.loading ? "Loading…" : undefined}
            />
          </Field>
          <Field
            label="Request limit"
            htmlFor="session-limit"
            hint="Optional. The proxy refuses the session's requests after this many."
            error={limitProblem}
          >
            <Input
              id="session-limit"
              inputMode="numeric"
              value={form.limit}
              placeholder="No limit"
              onChange={(e) => setForm({ ...form, limit: e.target.value })}
            />
          </Field>
          <DialogActions>
            <Button type="button" variant="outline" onClick={() => close(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={action.busy || !bundle || !ttl || limitProblem !== null}>
              Create session
            </Button>
          </DialogActions>
        </form>
      )}
    </FormDialog>
  );
}
