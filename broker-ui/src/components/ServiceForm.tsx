// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// The form that stores a service's credential: its name, secret fields
// (a value or a variable reference), custom headers and host override.

import { useState, type FormEvent } from "react";
import { Plus } from "lucide-react";
import { ApiError, get, type CredentialField, type CustomHeader, type Page, type ServiceTemplate, type Variable } from "../api";
import type { CredentialBody } from "../addService";
import { useAction, useLoad } from "../hooks";
import { cn } from "../lib/utils";
import { DialogActions, ErrorBanner, Field, lines, Mono, SelectField, Tags } from "./common";
import { ServiceLogo } from "./ServiceLogo";
import { CustomHeadersEditor } from "./VariableInput";
import { Button } from "./ui/button-components";
import { Input } from "./ui/input";

/** Variable keys the caller may reference; empty (not an error) for non-admins. */
export function useVariableKeys(enabled: boolean) {
  return useLoad(async () => {
    if (!enabled) return [] as string[];
    try {
      const page = await get<Page<Variable>>("/variables?page_size=100");
      return page.items.map((v) => v.key);
    } catch (e) {
      if (e instanceof ApiError && e.problem.status === 403) return [] as string[];
      throw e;
    }
  }, [enabled]);
}

/** The headers the credential itself injects, lower-cased. */
export function injectedHeaders(t: ServiceTemplate | undefined): string[] {
  if (!t) return [];
  return t.injection.method === "header" ? [t.injection.name.toLowerCase()] : ["authorization"];
}

export type SecretMode = "value" | "variable";

export const EMPTY_SECRET: SecretInput = { mode: "value", value: "", variable: "" };

export interface SecretInput {
  mode: SecretMode;
  value: string;
  variable: string;
}

export function initialSecrets(
  fields: CredentialField[],
  variables: string[],
  suggested: string | null | undefined,
): Record<string, SecretInput> {
  const out: Record<string, SecretInput> = {};
  fields.forEach((f, i) => {
    const preferred = i === 0 && suggested && variables.includes(suggested) ? suggested : "";
    out[f.name] = { mode: preferred ? "variable" : "value", value: "", variable: preferred };
  });
  return out;
}

/** Values sent to the API: the typed secret, or a `{{KEY}}` reference. */
export function secretValues(secrets: Record<string, SecretInput>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, s] of Object.entries(secrets)) {
    const v = s.mode === "variable" ? (s.variable ? `{{${s.variable}}}` : "") : s.value;
    if (v) out[name] = v;
  }
  return out;
}

export function SecretFieldInput({
  field,
  input,
  onChange,
  variables,
  suggested,
  labelPrefix = "",
}: {
  field: CredentialField;
  input: SecretInput;
  onChange: (input: SecretInput) => void;
  variables: string[];
  suggested?: string | null;
  labelPrefix?: string;
}) {
  const id = `secret-${field.name}`;
  return (
    <Field
      htmlFor={id}
      label={
        <>
          {labelPrefix}
          {field.label}
          {!field.required && <span className="font-normal text-muted-foreground"> (optional)</span>}
        </>
      }
      hint={
        input.mode === "variable" && variables.length === 0 ? (
          <>
            No variables yet.{" "}
            <a href="#/variables" className="underline underline-offset-4">
              Create {suggested ? <Mono>{suggested}</Mono> : "one"} under Variables
            </a>{" "}
            to share a secret between services.
          </>
        ) : (
          field.description || undefined
        )
      }
    >
      <div className="flex flex-col gap-2 sm:flex-row">
        <div className="flex shrink-0 rounded-md border p-0.5" role="radiogroup" aria-label={`${field.label} source`}>
          {(["value", "variable"] as const).map((m) => (
            <button
              key={m}
              type="button"
              role="radio"
              aria-checked={input.mode === m}
              onClick={() => onChange({ ...input, mode: m })}
              className={`h-8 rounded-sm px-2.5 text-xs transition-colors ${
                input.mode === m ? "bg-accent font-medium text-foreground" : "text-muted-foreground hover:text-foreground"
              }`}
            >
              {m === "value" ? "Secret value" : "Variable"}
            </button>
          ))}
        </div>
        <div className="min-w-0 flex-1">
          {input.mode === "value" ? (
            <Input
              id={id}
              type="password"
              autoComplete="new-password"
              spellCheck={false}
              className="font-mono"
              value={input.value}
              onChange={(e) => onChange({ ...input, value: e.target.value })}
              required={field.required}
            />
          ) : (
            <SelectField
              id={id}
              value={input.variable}
              onChange={(variable) => onChange({ ...input, variable })}
              placeholder={variables.length ? "Choose a variable…" : "No variables"}
              options={variables.map((k) => ({ value: k, label: `{{${k}}}` }))}
            />
          )}
        </div>
      </div>
    </Field>
  );
}

export function ServiceForm({
  template,
  variables,
  isAdmin,
  onBack,
  onSubmit,
  onSaved,
  submitLabel = "Save service",
  backLabel = "Back",
  showTemplate = true,
  blocked = null,
}: {
  template: ServiceTemplate;
  variables: string[];
  isAdmin: boolean;
  onBack: () => void;
  /** Stores the service; resolves with anything truthy on success. */
  onSubmit: (body: CredentialBody) => Promise<unknown>;
  onSaved: () => void;
  submitLabel?: string;
  backLabel?: string;
  /** Why the form cannot be submitted yet, shown next to the button. */
  blocked?: string | null;
  /** The template summary at the top; off when the step before showed it. */
  showTemplate?: boolean;
}) {
  const [name, setName] = useState(template.name);
  const [hostOverride, setHostOverride] = useState("");
  const [secrets, setSecrets] = useState(() =>
    initialSecrets(template.credential_fields, variables, template.suggested_variable),
  );
  const [headers, setHeaders] = useState<CustomHeader[]>(() => template.default_headers ?? []);
  // Most services need none; templates that ship some show them.
  const [showHeaders, setShowHeaders] = useState(headers.length > 0);
  const action = useAction();
  const missingVariable = Object.values(secrets).some((s) => s.mode === "variable" && !s.variable);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const saved = await action.run(() =>
      onSubmit({
        name,
        template_id: template.id,
        template_version: template.version,
        host_override: lines(hostOverride),
        fields: secretValues(secrets),
        custom_headers: headers,
      }),
    );
    if (saved) {
      // Clear typed secrets from memory as soon as they are stored.
      setSecrets(initialSecrets(template.credential_fields, [], null));
      onSaved();
    }
  };

  return (
    <form className="space-y-5" onSubmit={submit} autoComplete="off">
      <ErrorBanner error={action.error} />
      {showTemplate && (
      <div className="flex items-start gap-3 rounded-md border bg-muted/40 p-3">
        <ServiceLogo template={template} />
        <div className="min-w-0 flex-1 space-y-1.5 text-sm">
          <p className="text-muted-foreground">{template.description}</p>
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs font-medium text-muted-foreground">Hosts</span>
            {template.hosts.length ? <Tags values={template.hosts} /> : <span className="text-xs">chosen below</span>}
          </div>
        </div>
        <Button type="button" variant="ghost" size="sm" onClick={onBack}>
          Change
        </Button>
      </div>
      )}
      <div className={cn("grid grid-cols-1 gap-4", template.host_override.allowed && "md:grid-cols-2")}>
        <Field label="Name" htmlFor="svc-name">
          <Input id="svc-name" value={name} onChange={(e) => setName(e.target.value)} required />
        </Field>
        {template.host_override.allowed && (
          <Field
            label={
              <>
                {template.host_override.label ?? "Base URL"}
                {!template.host_override.required && (
                  <span className="font-normal text-muted-foreground"> (optional)</span>
                )}
              </>
            }
            htmlFor="svc-host"
            hint={
              isAdmin
                ? "Replaces the template's hosts. Admin only, and audited."
                : "Only admins can set the host."
            }
          >
            <Input
              id="svc-host"
              placeholder="https://api.internal.example:8443"
              value={hostOverride}
              onChange={(e) => setHostOverride(e.target.value)}
              disabled={!isAdmin}
              required={template.host_override.required && isAdmin}
            />
          </Field>
        )}
      </div>
      {template.credential_fields.map((f) => (
        <SecretFieldInput
          key={f.name}
          field={f}
          input={secrets[f.name] ?? EMPTY_SECRET}
          onChange={(input) => setSecrets({ ...secrets, [f.name]: input })}
          variables={variables}
          suggested={template.suggested_variable}
        />
      ))}
      {showHeaders ? (
        <div className="space-y-2">
          <div>
            <div className="text-sm font-medium">Custom headers</div>
            <p className="text-xs text-muted-foreground">
              Sent with every request. Type <Mono>{"{{"}</Mono> to use a variable.
            </p>
          </div>
          <CustomHeadersEditor
            headers={headers}
            onChange={setHeaders}
            variables={variables}
            reserved={injectedHeaders(template)}
          />
        </div>
      ) : (
        <Button type="button" variant="ghost" size="sm" className="-ml-2 text-muted-foreground" onClick={() => setShowHeaders(true)}>
          <Plus />
          Custom headers
        </Button>
      )}
      <DialogActions>
        {blocked && <p className="mr-auto self-center text-sm text-muted-foreground">{blocked}</p>}
        <Button type="button" variant="outline" onClick={onBack}>
          {backLabel}
        </Button>
        <Button type="submit" disabled={action.busy || missingVariable || !isAdmin || blocked !== null}>
          {submitLabel}
        </Button>
      </DialogActions>
    </form>
  );
}
