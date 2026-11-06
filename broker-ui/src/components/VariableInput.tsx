// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Inputs that understand `{{VARIABLE}}` references: typing `{{` offers the
// stored variable keys, and the custom headers editor uses it for values.

import { useRef, useState, type KeyboardEvent } from "react";
import { Braces, Plus, Trash2 } from "lucide-react";
import type { CustomHeader } from "../api";
import { cn } from "../lib/utils";
import { Button } from "./ui/button-components";
import { Input } from "./ui/input";

/** The partial key after an unclosed `{{` just before the cursor. */
function openReference(text: string, cursor: number): { start: number; partial: string } | null {
  const before = text.slice(0, cursor);
  const open = before.lastIndexOf("{{");
  if (open < 0 || before.indexOf("}}", open) >= 0) return null;
  const partial = before.slice(open + 2).trimStart();
  if (!/^[A-Z0-9_]*$/i.test(partial)) return null;
  return { start: open, partial };
}

export function referencedKeys(text: string): string[] {
  return [...text.matchAll(/\{\{\s*([A-Z][A-Z0-9_]*)\s*\}\}/g)].flatMap((m) => (m[1] ? [m[1]] : []));
}

export function VariableInput({
  id,
  value,
  onChange,
  variables,
  placeholder,
  type = "text",
  required,
  className,
  "aria-label": ariaLabel,
}: {
  id?: string;
  value: string;
  onChange: (value: string) => void;
  variables: string[];
  placeholder?: string;
  type?: "text" | "password";
  required?: boolean;
  className?: string;
  "aria-label"?: string;
}) {
  const ref = useRef<HTMLInputElement>(null);
  const [cursor, setCursor] = useState<number | null>(null);
  const [active, setActive] = useState(0);
  const open = cursor === null ? null : openReference(value, cursor);
  const matches = open
    ? variables.filter((k) => k.startsWith(open.partial.toUpperCase())).slice(0, 8)
    : [];
  const showing = matches.length > 0;

  const pick = (key: string) => {
    if (!open || cursor === null) return;
    const after = value.slice(cursor).replace(/^[A-Z0-9_]*\s*(\}\})?/i, "");
    const next = `${value.slice(0, open.start)}{{${key}}}${after}`;
    onChange(next);
    const pos = open.start + key.length + 4;
    setCursor(null);
    requestAnimationFrame(() => {
      ref.current?.focus();
      ref.current?.setSelectionRange(pos, pos);
    });
  };

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (!showing) return;
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      setActive((a) => (a + (e.key === "ArrowDown" ? 1 : matches.length - 1)) % matches.length);
    } else if (e.key === "Enter" || e.key === "Tab") {
      e.preventDefault();
      const key = matches[Math.min(active, matches.length - 1)];
      if (key) pick(key);
    } else if (e.key === "Escape") {
      e.preventDefault();
      setCursor(null);
    }
  };

  return (
    <div className="relative">
      <Input
        ref={ref}
        id={id}
        type={type}
        value={value}
        required={required}
        placeholder={placeholder}
        aria-label={ariaLabel}
        aria-autocomplete="list"
        aria-expanded={showing}
        spellCheck={false}
        autoComplete={type === "password" ? "new-password" : "off"}
        className={cn("font-mono", className)}
        onChange={(e) => {
          onChange(e.target.value);
          setCursor(e.target.selectionStart);
          setActive(0);
        }}
        onKeyUp={(e) => setCursor(e.currentTarget.selectionStart)}
        onClick={(e) => setCursor(e.currentTarget.selectionStart)}
        onBlur={() => setTimeout(() => setCursor(null), 120)}
        onKeyDown={onKeyDown}
      />
      {showing && (
        <ul
          role="listbox"
          className="absolute z-50 mt-1 max-h-56 w-full overflow-y-auto rounded-md border bg-popover p-1 text-popover-foreground shadow-md"
        >
          {matches.map((key, i) => (
            <li key={key} role="option" aria-selected={i === active}>
              <button
                type="button"
                onMouseDown={(e) => {
                  e.preventDefault();
                  pick(key);
                }}
                className={cn(
                  "flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-left font-mono text-xs",
                  i === active ? "bg-accent text-accent-foreground" : "hover:bg-accent/60",
                )}
              >
                <Braces className="size-3.5 text-muted-foreground" />
                {key}
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;

/** Rows of name/value pairs; values may reference variables. */
export function CustomHeadersEditor({
  headers,
  onChange,
  variables,
  reserved,
}: {
  headers: CustomHeader[];
  onChange: (headers: CustomHeader[]) => void;
  variables: string[];
  /** Header the credential itself sets; a custom header cannot reuse it. */
  reserved: string[];
}) {
  const set = (i: number, patch: Partial<CustomHeader>) =>
    onChange(headers.map((h, j) => (j === i ? { ...h, ...patch } : h)));
  return (
    <div className="space-y-2">
      {headers.length > 0 && (
        <div className="hidden grid-cols-[minmax(0,2fr)_minmax(0,3fr)_2rem] gap-2 px-0.5 text-xs font-medium text-muted-foreground sm:grid">
          <span>Header</span>
          <span>Value</span>
        </div>
      )}
      {headers.map((h, i) => {
        const nameProblem =
          h.name && !HEADER_NAME.test(h.name)
            ? "Not a valid header name"
            : reserved.includes(h.name.toLowerCase())
              ? "The credential already sets this header"
              : null;
        return (
          <div key={i} className="space-y-1">
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-[minmax(0,2fr)_minmax(0,3fr)_2rem]">
              <Input
                value={h.name}
                onChange={(e) => set(i, { name: e.target.value })}
                placeholder="X-Api-Version"
                aria-label={`Header ${i + 1} name`}
                aria-invalid={nameProblem !== null}
                className="font-mono"
                required
              />
              <VariableInput
                value={h.value}
                onChange={(value) => set(i, { value })}
                variables={variables}
                placeholder="value or {{VARIABLE}}"
                aria-label={`Header ${i + 1} value`}
                required
              />
              <Button
                type="button"
                variant="ghost"
                size="icon"
                className="size-10 text-muted-foreground hover:text-destructive"
                aria-label={`Remove header ${h.name || i + 1}`}
                onClick={() => onChange(headers.filter((_, j) => j !== i))}
              >
                <Trash2 />
              </Button>
            </div>
            {nameProblem && <p className="text-xs text-destructive">{nameProblem}</p>}
          </div>
        );
      })}
      <Button
        type="button"
        variant="outline"
        size="sm"
        disabled={headers.length >= 16}
        onClick={() => onChange([...headers, { name: "", value: "" }])}
      >
        <Plus />
        Add header
      </Button>
    </div>
  );
}
