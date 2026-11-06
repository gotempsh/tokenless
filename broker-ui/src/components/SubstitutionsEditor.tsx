// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Edits a credential's substitutions: the placeholder an agent sends, the
// secret field the proxy puts in its place, and where it looks.

import { Plus, Trash2 } from "lucide-react";
import type { Substitution, SubstitutionLocation } from "../api";
import { SelectField } from "./common";
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
          <div key={i} className="space-y-3 rounded-md border p-3">
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-[minmax(0,3fr)_minmax(0,2fr)_minmax(0,2fr)_2rem]">
              <Input
                value={s.placeholder}
                onChange={(e) => set(i, { placeholder: e.target.value })}
                placeholder="__GITHUB_TOKEN__"
                aria-label={`Placeholder ${i + 1}`}
                aria-invalid={problem !== null}
                className="font-mono"
                required
              />
              <SelectField
                value={s.field}
                onChange={(field) => set(i, { field })}
                options={fields.map((f) => ({ value: f, label: `replaced by ${f}` }))}
                placeholder="Secret field"
              />
              <Input
                value={s.env ?? ""}
                onChange={(e) => set(i, { env: e.target.value || undefined })}
                placeholder="ENV_VAR (optional)"
                aria-label={`Environment variable for placeholder ${i + 1}`}
                className="font-mono"
              />
              <Button
                type="button"
                variant="ghost"
                size="icon"
                className="size-10 text-muted-foreground hover:text-destructive"
                aria-label={`Remove placeholder ${s.placeholder || i + 1}`}
                onClick={() => onChange(substitutions.filter((_, j) => j !== i))}
              >
                <Trash2 />
              </Button>
            </div>
            <div className="flex flex-col gap-2 sm:flex-row sm:flex-wrap sm:gap-4">
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
            </div>
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
