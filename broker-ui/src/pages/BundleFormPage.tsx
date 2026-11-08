// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Creating or editing an access bundle: its vault, name and description,
// and which of the vault's services (rules) it holds. A page of its own,
// since a vault's services can be a long list.

import { useState, type FormEvent } from "react";
import {
  get,
  patch,
  post,
  type AccessBundle,
  type CredentialMeta,
  type Page,
  type Rule,
  type StoredTemplate,
  type Vault,
} from "../api";
import { backCrumbs, useBreadcrumbs } from "../breadcrumbs";
import type { BundleFormContext } from "../bundleForm";
import { useAction, useLoad } from "../hooks";
import { CheckField, ErrorBanner, Field, Loading, Panel, SelectField, Tags } from "../components/common";
import { ServiceLogo } from "../components/ServiceLogo";
import { Button } from "../components/ui/button-components";
import { Input } from "../components/ui/input";
import { PageContainer, PageHeader } from "../components/ui/page-header";
import { Skeleton } from "../components/ui/skeleton";
import { Textarea } from "../components/ui/textarea";
import { templateOf } from "./Services";

const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

export function BundleFormPage({ ctx }: { ctx: BundleFormContext }) {
  const editing = ctx.bundle !== undefined;
  const bundle = useLoad(
    () => (ctx.bundle ? get<AccessBundle>(`/bundles/${ctx.bundle}`) : Promise.resolve(undefined)),
    [ctx.bundle],
  );
  const vaults = useLoad(() => get<Page<Vault>>("/vaults?page_size=100"), []);
  const b = bundle.data;
  // With one vault there is nothing to choose.
  const onlyVault = vaults.data?.items.length === 1 ? vaults.data.items[0]?.id : undefined;
  const back = ctx.back ?? (ctx.bundle ? `bundles/${ctx.bundle}` : "bundles");
  const leave = () => {
    window.location.hash = `#/${back}`;
  };

  useBreadcrumbs(
    editing
      ? [
          { label: "Access bundles", href: "#/bundles" },
          { label: b?.name ?? null, href: `#/bundles/${ctx.bundle}` },
          { label: "Edit" },
        ]
      : [
          ...backCrumbs(back, { vault: vaults.data?.items.find((v) => v.id === ctx.vault)?.name ?? null }),
          { label: "New access bundle" },
        ],
  );

  return (
    <PageContainer width="form">
      <PageHeader title={editing ? (b ? `Edit ${b.name}` : "Edit bundle") : "Create an access bundle"} />
      <ErrorBanner error={bundle.error ?? vaults.error} />
      {editing && !b ? (
        bundle.loading && (
          <Panel>
            <Loading />
          </Panel>
        )
      ) : (
        <BundleForm
          vaultId={b?.vault_id ?? ctx.vault ?? onlyVault}
          vaults={vaults.data?.items}
          bundle={b ?? null}
          onCancel={leave}
          onSaved={(saved) => {
            // A new bundle's next step is on its page: run an agent with it.
            window.location.hash = editing ? `#/${back}` : `#/bundles/${saved.id}`;
          }}
        />
      )}
    </PageContainer>
  );
}

interface FormState {
  name: string;
  description: string;
  rule_ids: string[];
}

function BundleForm({
  vaultId: fixedVault,
  vaults,
  bundle,
  onCancel,
  onSaved,
}: {
  /** The bundle's vault; when absent (a new bundle from the sidebar page) the form asks. */
  vaultId: string | undefined;
  vaults: Vault[] | undefined;
  bundle: AccessBundle | null;
  onCancel: () => void;
  onSaved: (saved: AccessBundle) => void;
}) {
  const [chosenVault, setChosenVault] = useState(fixedVault ?? "");
  const vaultId = fixedVault ?? chosenVault;
  const services = useLoad(
    () =>
      vaultId
        ? Promise.all([
            get<Page<Rule>>(`/vaults/${vaultId}/rules?page_size=100`),
            get<Page<CredentialMeta>>(`/vaults/${vaultId}/credentials?page_size=100`),
          ])
        : Promise.resolve(undefined),
    [vaultId],
  );
  const templates = useLoad(() => get<StoredTemplate[]>("/templates"), []);
  const rules = services.data?.[0].items;
  const credential = (id: string) => services.data?.[1].items.find((c) => c.id === id);
  const [form, setForm] = useState<FormState>(
    bundle
      ? { name: bundle.name, description: bundle.description, rule_ids: bundle.rule_ids }
      : { name: "", description: "", rule_ids: [] },
  );
  const action = useAction();
  const nameProblem =
    form.name && !NAME.test(form.name.trim())
      ? "Letters, digits, '-', '_' and '.', starting with a letter or digit (up to 64)."
      : null;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const body = { name: form.name.trim(), description: form.description, rule_ids: form.rule_ids };
    const saved = await action.run(() =>
      bundle ? patch<AccessBundle>(`/bundles/${bundle.id}`, body) : post<AccessBundle>(`/vaults/${vaultId}/bundles`, body),
    );
    if (saved) onSaved(saved);
  };

  return (
    <form className="space-y-6" onSubmit={submit}>
      <ErrorBanner error={action.error ?? services.error} />
      {!fixedVault && (
        <Field label="Vault" htmlFor="bundle-vault" hint="A bundle can only hold services from its own vault.">
          <SelectField
            id="bundle-vault"
            value={chosenVault}
            onChange={(v) => {
              setChosenVault(v);
              setForm({ ...form, rule_ids: [] });
            }}
            placeholder="Choose a vault…"
            options={(vaults ?? []).map((v) => ({ value: v.id, label: v.name }))}
          />
        </Field>
      )}
      <Field label="Name" htmlFor="bundle-name" hint={nameProblem ?? "Used on the command line: --bundle <name>."}>
        <Input
          id="bundle-name"
          value={form.name}
          onChange={(e) => setForm({ ...form, name: e.target.value })}
          placeholder="code-review"
          className="font-mono"
          aria-invalid={nameProblem !== null}
          required
        />
      </Field>
      <Field label="Description" htmlFor="bundle-description" hint="Optional: what the bundle is for.">
        <Textarea
          id="bundle-description"
          rows={2}
          value={form.description}
          onChange={(e) => setForm({ ...form, description: e.target.value })}
          placeholder="Read pull requests and post review comments"
        />
      </Field>
      <fieldset className="space-y-2">
        <legend className="text-sm font-medium">Services</legend>
        {bundle && (
          <p className="text-xs text-muted-foreground">
            Sessions created afterwards get these; running sessions keep what they started with.
          </p>
        )}
        {!vaultId ? (
          <p className="text-sm text-muted-foreground">Choose a vault to see its services.</p>
        ) : rules === undefined ? (
          <Skeleton className="h-24 w-full rounded-lg" />
        ) : rules.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            This vault has no services with a rule yet. Create the bundle empty, then use{" "}
            <span className="font-medium text-foreground">Add a service</span> on it to pick one from the catalogue.
          </p>
        ) : (
          <div className="divide-y rounded-lg border">
            {rules.map((r) => {
              const c = credential(r.credential_id);
              const tpl = c ? templateOf(templates.data ?? [], c) : undefined;
              return (
                <div key={r.id} className="px-3 py-3">
                  <CheckField
                    id={`bundle-rule-${r.id}`}
                    checked={form.rule_ids.includes(r.id)}
                    onChange={(checked) =>
                      setForm({
                        ...form,
                        rule_ids: checked ? [...form.rule_ids, r.id] : form.rule_ids.filter((id) => id !== r.id),
                      })
                    }
                    hint={<Tags values={r.allow.hosts} />}
                  >
                    <span className="inline-flex flex-wrap items-center gap-2">
                      <ServiceLogo template={tpl ?? { id: c?.template_id ?? "", kind: "http" }} size="sm" />
                      <span className="font-medium">{c?.name ?? r.credential_id.slice(0, 8)}</span>
                      {r.name !== c?.name && <span className="text-muted-foreground">· {r.name}</span>}
                      {!r.enabled && <span className="text-muted-foreground">(turned off, skipped by new sessions)</span>}
                    </span>
                  </CheckField>
                </div>
              );
            })}
          </div>
        )}
      </fieldset>
      <div className="flex justify-end gap-2 border-t pt-4">
        <Button type="button" variant="outline" onClick={onCancel}>
          Cancel
        </Button>
        <Button type="submit" disabled={action.busy || nameProblem !== null || !form.name.trim() || !vaultId}>
          {bundle ? "Save bundle" : "Create bundle"}
        </Button>
      </div>
    </form>
  );
}
