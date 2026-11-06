// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Edits a credential's substitutions: the placeholder an agent sends, the
// secret field the proxy puts in its place, and where it looks.

import { Plus, Trash2 } from "lucide-react";
import type { Substitution, SubstitutionLocation } from "../api";
import { Field, SelectField } from "./common";
import { Button } from "./ui/button-components";
import { Checkbox } from "./ui/checkbox";
import { Input } from "./ui/input";

const LOCATIONS: { value: SubstitutionLocation; label: string; hint: string }[] = [
  { value: "header", label: "Headers", hint: "headers the agent sends" },
  { value: "query", label: "Query", hint: "?key=… in the URL" },
  { value: "path", label: "Path", hint: "/v1/…/ segments" },
  { value: "body", label: "Body", hint: "JSON, form or text up to 4 MiB" },
];

const PLACEHOLDER = /^[A-Za-z0-9_.-]{8,128}$/;
const ENV = /^[A-Z_][A-Z0-9_]{0,63}$/;

function upperSnake(value: string): string {
  return value.toUpperCase().replace(/[^A-Z0-9]+/g, "_").replace(/^_+|_+$/g, "");
}

/** `__GITHUB_TOKEN__` for field `token` of template `github`. */
export function suggestedPlaceholder(templateId: string, field: string): string {
  return `__${upperSnake(`${templateId}_${field}`)}__`;
}

export function substitutionProblem(s: Substitution, all: Substitution[]): string | null {
  if (!PLACEHOLDER.test(s.placeholder)) {
    return "Placeholders are 8-128 letters, digits, '_', '-' or '.', so ordinary text never matches one";
  }
  if (all.some((o) => o !== s && (o.placeholder.includes(s.placeholder) || s.placeholder.includes(o.placeholder)))) {
    return "Placeholders must be distinct and none may contain another";
  }
  if (s.locations.length === 0) return "Choose at least one place to look";
  if (s.env && !ENV.test(s.env)) return "The environment variable must be UPPER_SNAKE_CASE";
  return null;
}

export function SubstitutionsEditor({
  substitutions,
  onChange,
  fields,
  templateId,
}: {
  substitutions: Substitution[];
  onChange: (substitutions: Substitution[]) => void;
  /** The credential's secret field names. */
  fields: string[];
  templateId: string;
}) {
  const set = (i: number, patch: Partial<Substitution>) =>
    onChange(substitutions.map((s, j) => (j === i ? { ...s, ...patch } : s)));
  const toggle = (i: number, location: SubstitutionLocation, on: boolean) => {
    const current = substitutions[i]?.locations ?? [];
    set(i, { locations: on ? [...current, location] : current.filter((l) => l !== location) });
  };
  const add = () => {
    const field = fields[0] ?? "";
    onChange([
      ...substitutions,
      {
        placeholder: suggestedPlaceholder(templateId, field),
        field,
        env: upperSnake(`${templateId}_${field}`),
        locations: ["header", "query"],
      },
    ]);
  };
  return (
    <div className="space-y-3">
      {substitutions.map((s, i) => {
        const problem = substitutionProblem(s, substitutions);
        return (
          <div key={i} className="space-y-4 rounded-md border p-4">
            <div className="flex items-center justify-between gap-2">
              <p className="text-sm font-medium">Placeholder {i + 1}</p>
              <Button
                type="button"
                variant="ghost"
                size="icon"
                className="size-8 text-muted-foreground hover:text-destructive"
                aria-label={`Remove placeholder ${s.placeholder || i + 1}`}
                onClick={() => onChange(substitutions.filter((_, j) => j !== i))}
              >
                <Trash2 />
              </Button>
            </div>
            <Field label="Placeholder" htmlFor={`sub-${i}-placeholder`} hint="What the agent sends instead of the secret.">
              <Input
                id={`sub-${i}-placeholder`}
                value={s.placeholder}
                onChange={(e) => set(i, { placeholder: e.target.value })}
                placeholder="__GITHUB_TOKEN__"
                aria-invalid={problem !== null}
                className="font-mono"
                required
              />
            </Field>
            <Field label="Replaced by" htmlFor={`sub-${i}-field`}>
              <SelectField
                id={`sub-${i}-field`}
                value={s.field}
                onChange={(field) => set(i, { field })}
                options={fields.map((f) => ({ value: f, label: f }))}
                placeholder="Secret field"
              />
            </Field>
            <Field
              label={
                <>
                  Environment variable <span className="font-normal text-muted-foreground">(optional)</span>
                </>
              }
              htmlFor={`sub-${i}-env`}
              hint="Set to the placeholder for agents started with credential-broker run."
            >
              <Input
                id={`sub-${i}-env`}
                value={s.env ?? ""}
                onChange={(e) => set(i, { env: e.target.value || undefined })}
                placeholder="GITHUB_TOKEN"
                className="font-mono"
              />
            </Field>
            <fieldset className="space-y-2">
              <legend className="mb-2 text-sm font-medium">Where the proxy looks</legend>
              {LOCATIONS.map((l) => {
                const id = `sub-${i}-${l.value}`;
                return (
                  <label key={l.value} htmlFor={id} className="flex items-center gap-2 text-sm">
                    <Checkbox
                      id={id}
                      checked={s.locations.includes(l.value)}
                      onCheckedChange={(on) => toggle(i, l.value, on === true)}
                    />
                    <span>{l.label}</span>
                    <span className="text-xs text-muted-foreground">{l.hint}</span>
                  </label>
                );
              })}
            </fieldset>
            {problem && <p className="text-xs text-destructive">{problem}</p>}
          </div>
        );
      })}
      <Button type="button" variant="outline" size="sm" disabled={substitutions.length >= 16 || fields.length === 0} onClick={add}>
        <Plus />
        Add placeholder
      </Button>
    </div>
  );
}
