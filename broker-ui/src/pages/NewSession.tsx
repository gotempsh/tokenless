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
  Field,
  FormDialog,
  SelectField,
} from "../components/common";
import { Button } from "../components/ui/button-components";
import { Input } from "../components/ui/input";
import {
  customLifetime,
  defaultLifetime,
  LIFETIME_UNITS,
  lifetimeLabel,
  lifetimesUpTo,
  type LifetimeUnit,
} from "../sessionForm";
import { SessionHandoff, useHandoffGuard } from "./SessionHandoff";

interface SessionLimits {
  max_ttl_secs: number;
  default_ttl_secs: number;
}

/** The Expires after choice that reveals the typed-in lifetime. */
const CUSTOM = "custom";

const EMPTY = { bundle: "", name: "", ttl: "", amount: "", unit: "hours" as LifetimeUnit, limit: "" };

export function NewSessionDialog({
  bundle: fixed,
  choices,
  vaultNames = {},
  open,
  onOpenChange,
  onCreated,
  isAdmin,
}: {
  /** The bundle the session is for; without it the form asks, from `choices`. */
  bundle?: AccessBundle;
  choices?: AccessBundle[];
  vaultNames?: Record<string, string>;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onCreated?: (minted: MintedSession) => void;
  isAdmin: boolean;
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
  const choice = form.ttl || (max ? String(defaultLifetime(max)) : "");
  const custom = choice === CUSTOM && max ? customLifetime(form.amount, form.unit, max) : null;
  const ttl = choice === CUSTOM ? (custom && "secs" in custom ? String(custom.secs) : "") : choice;
  const limit = form.limit.trim();
  const limitProblem = limit && !/^[1-9][0-9]*$/.test(limit) ? "A whole number of requests, at least 1" : null;

  const guard = useHandoffGuard();
  const close = (o: boolean) => {
    // Escape, the close button and an outside click land here too: the
    // token is shown only once, so the first try before copying warns.
    if (!o && minted && !guard.mayClose()) return;
    onOpenChange(o);
    if (!o) {
      setForm(EMPTY);
      setMinted(null);
      guard.reset();
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
      {minted && bundle ? (
        <SessionHandoff
          minted={minted}
          reaches={`${bundle.name}'s services`}
          guard={guard}
          onDone={() => close(false)}
        />
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
              // The custom lifetime's own error says the same when it is too long.
              max !== undefined && max < 90 * 86400 && !(custom && "problem" in custom) ? (
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
              value={choice}
              onChange={(v) => setForm({ ...form, ttl: v })}
              options={[
                ...lifetimes.map((l) => ({ value: String(l.secs), label: l.label })),
                ...(max ? [{ value: CUSTOM, label: "Custom…" }] : []),
              ]}
              placeholder={!bundle ? "Choose a bundle first" : limits.loading ? "Loading…" : undefined}
            />
          </Field>
          {choice === CUSTOM && (
            <Field
              label="Custom lifetime"
              htmlFor="session-ttl-amount"
              error={custom && "problem" in custom ? custom.problem : null}
            >
              <div className="flex gap-2">
                <Input
                  id="session-ttl-amount"
                  inputMode="numeric"
                  autoFocus
                  className="w-28"
                  value={form.amount}
                  placeholder="36"
                  onChange={(e) => setForm({ ...form, amount: e.target.value })}
                />
                <SelectField
                  value={form.unit}
                  onChange={(v) => setForm({ ...form, unit: v as LifetimeUnit })}
                  options={LIFETIME_UNITS.map((u) => ({ value: u.value, label: u.label }))}
                  className="w-36"
                />
              </div>
            </Field>
          )}
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
