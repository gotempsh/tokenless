// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// The form that stores a service's credential: its name, secret fields
// (a value or a variable reference), custom headers and host override.

import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { ChevronRight } from "lucide-react";
import { ApiError, get, type CredentialField, type CustomHeader, type Page, type ServiceTemplate, type Variable } from "../api";
import { freeName, nameTaken, type CredentialBody } from "../addService";
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
  const other = input.mode === "value" ? "variable" : "value";
  return (
    <Field
      htmlFor={id}
      label={
        <span className="flex w-full items-baseline justify-between gap-3">
          <span>
            {labelPrefix}
            {field.label}
            {!field.required && <span className="font-normal text-muted-foreground"> (optional)</span>}
          </span>
          <button
            type="button"
            onClick={(e) => {
              e.preventDefault();
              onChange({ ...input, mode: other });
            }}
            className="text-xs font-normal text-muted-foreground hover:text-foreground"
          >
            {other === "variable" ? "Use a variable instead" : "Enter a value instead"}
          </button>
        </span>
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
      <div>
        <div className="min-w-0">
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
              placeholder="Paste it here. It can't be read back once saved."
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
  takenNames,
  vaultName,
  children,
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
  /** Service names the target vault already has; they cannot be reused. */
  takenNames?: readonly string[];
  /** The target vault's name, for saying where a name is taken. */
  vaultName?: string;
  /** More of the form, shown after the credential and before the buttons. */
  children?: ReactNode;
}) {
  const [name, setName] = useState(template.name);
  const [nameEdited, setNameEdited] = useState(false);
  // Until the user types a name, keep the suggestion free in the vault:
  // a second GitHub becomes "GitHub 2" rather than a failed save.
  useEffect(() => {
    if (!nameEdited && takenNames) setName(freeName(template.name, takenNames));
  }, [nameEdited, takenNames, template.name]);
  const duplicate = takenNames !== undefined && nameTaken(name, takenNames);
  const [hostOverride, setHostOverride] = useState("");
  const [secrets, setSecrets] = useState(() =>
    initialSecrets(template.credential_fields, variables, template.suggested_variable),
  );
  const [headers, setHeaders] = useState<CustomHeader[]>(() => template.default_headers ?? []);
  // Most services need neither; templates that ship headers open it.
  const [advanced, setAdvanced] = useState(headers.length > 0);
  const hostRequired = template.host_override.allowed && template.host_override.required;
  const hostOptional = template.host_override.allowed && !template.host_override.required;
  const action = useAction();
  const missingVariable = Object.values(secrets).some((s) => s.mode === "variable" && !s.variable);

  const hostField = (required: boolean) => (
    <Field
      label={
        <>
          {template.host_override.label ?? "Base URL"}
          {!required && <span className="font-normal text-muted-foreground"> (optional)</span>}
        </>
      }
      htmlFor="svc-host"
      hint={
        isAdmin
          ? required
            ? "Where the service runs. Admin only, and audited."
            : "Replaces the template's hosts, for a self-hosted or regional endpoint. Admin only, and audited."
          : "Only the vault's admins can set the host."
      }
    >
      <Input
        id="svc-host"
        placeholder="https://api.internal.example:8443"
        value={hostOverride}
        onChange={(e) => setHostOverride(e.target.value)}
        disabled={!isAdmin}
        required={required && isAdmin}
      />
    </Field>
  );

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
      <Field
        label="Name"
        htmlFor="svc-name"
        hint="How it shows in the vault and in session info."
        error={
          duplicate &&
          `${vaultName ? `${vaultName} already has` : "This vault already has"} a service named "${name.trim()}". Try "${freeName(name, takenNames ?? [])}".`
        }
      >
        <Input
          id="svc-name"
          value={name}
          aria-invalid={duplicate}
          onChange={(e) => {
            setNameEdited(true);
            setName(e.target.value);
          }}
          required
        />
      </Field>
      {hostRequired && hostField(true)}
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
      <div>
        <button
          type="button"
          aria-expanded={advanced}
          onClick={() => setAdvanced(!advanced)}
          className="flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
        >
          <ChevronRight className={cn("size-4 transition-transform", advanced && "rotate-90")} />
          {hostOptional ? "Custom endpoint and headers" : "Custom headers"}
        </button>
        {advanced && (
          <div className="mt-4 space-y-4 border-l pl-4">
            {hostOptional && hostField(false)}
            <div className="space-y-2">
              <div>
                {hostOptional && <div className="text-sm font-medium">Custom headers</div>}
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
          </div>
        )}
      </div>
      {children}
      <ErrorBanner error={action.error} title="The service was not saved" />
      <DialogActions>
        {blocked && <p className="mr-auto self-center text-sm text-muted-foreground">{blocked}</p>}
        <Button type="button" variant="outline" onClick={onBack}>
          {backLabel}
        </Button>
        <Button type="submit" disabled={action.busy || missingVariable || duplicate || !isAdmin || blocked !== null}>
          {submitLabel}
        </Button>
      </DialogActions>
    </form>
  );
}
