// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Broker-specific building blocks composed from the ported Temps primitives
// in ./ui. Pages use these so every list, form and status reads the same.

import { useState, type KeyboardEvent, type MouseEvent, type ReactNode } from "react";
import { AlertCircle, Check, ChevronLeft, ChevronRight, Copy, KeyRound, MoreHorizontal, type LucideIcon } from "lucide-react";
import type { Page } from "../api";
import { compactTime, exactTime, relativeTime } from "../time";
import { cn } from "../lib/utils";
import { Alert, AlertDescription, AlertTitle } from "./ui/alert";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button-components";
import { Checkbox } from "./ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "./ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "./ui/dropdown-menu";
import { EmptyState } from "./ui/empty-state";
import { Label } from "./ui/label";
import { RadioGroup, RadioGroupItem } from "./ui/radio-group";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "./ui/select";
import { Skeleton } from "./ui/skeleton";

export function ErrorBanner({ error, title = "Something went wrong" }: { error: string | null; title?: string }) {
  if (!error) return null;
  return (
    <Alert variant="destructive">
      <AlertCircle className="size-4" />
      <AlertTitle>{title}</AlertTitle>
      <AlertDescription className="break-words">{error}</AlertDescription>
    </Alert>
  );
}

/** Placeholder rows shaped like a table while its data loads. */
export function Loading({ rows = 3 }: { rows?: number }) {
  return (
    <div className="space-y-3 p-4" aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }, (_, i) => (
        <Skeleton key={i} className="h-8 w-full" />
      ))}
    </div>
  );
}

export function Empty({
  icon,
  title,
  description,
  action,
}: {
  icon: LucideIcon;
  title: string;
  description: ReactNode;
  action?: ReactNode;
}) {
  return <EmptyState size="compact" icon={icon} title={title} description={description} action={action} />;
}

/** A titled block within a page; sections are separated by the page's `space-y-6`. */
export function Section({
  title,
  description,
  actions,
  children,
}: {
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="space-y-4">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <h2 className="text-lg font-semibold">{title}</h2>
          {description && <p className="mt-1 text-sm text-muted-foreground">{description}</p>}
        </div>
        {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
      </div>
      {children}
    </section>
  );
}

/** The bordered surface a table or form sits on. No shadow, per the Temps design rules. */
export function Panel({ className, children }: { className?: string; children: ReactNode }) {
  return <div className={cn("rounded-lg border bg-card text-card-foreground", className)}>{children}</div>;
}

export function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <Button
      type="button"
      variant="outline"
      size="sm"
      onClick={() => {
        void navigator.clipboard.writeText(value).then(() => {
          setCopied(true);
          window.setTimeout(() => setCopied(false), 2000);
        });
      }}
    >
      {copied ? <Check /> : <Copy />}
      <span className="hidden sm:inline">{copied ? "Copied" : label}</span>
    </Button>
  );
}

/** A credential minted by the request: shown once, never retrievable again. */
export function OneTimeSecret({ label, value, hint }: { label: string; value: string; hint?: ReactNode }) {
  return (
    <Alert variant="warning">
      <KeyRound className="size-4" />
      <AlertTitle>{label}</AlertTitle>
      <AlertDescription className="space-y-3">
        <p>This is the only time it is shown. Store it now.</p>
        <div className="flex items-center gap-2">
          <code className="min-w-0 flex-1 break-all rounded-md border bg-background px-3 py-2 font-mono text-xs text-foreground">
            {value}
          </code>
          <CopyButton value={value} />
        </div>
        {hint && <div className="text-foreground/80">{hint}</div>}
      </AlertDescription>
    </Alert>
  );
}

export function Pager<T>({ page, onPage }: { page: Page<T> | undefined; onPage: (p: number) => void }) {
  if (!page || page.total === 0) return null;
  const pages = Math.max(1, Math.ceil(page.total / page.page_size));
  const first = (page.page - 1) * page.page_size + 1;
  const last = Math.min(page.total, page.page * page.page_size);
  return (
    <div className="flex items-center justify-between gap-2 border-t px-4 py-3 text-sm text-muted-foreground">
      <span className="hidden sm:inline">
        Showing {first}–{last} of {page.total}
      </span>
      <span className="sm:hidden">
        {page.page} / {pages}
      </span>
      <div className="flex items-center gap-2">
        <Button type="button" variant="outline" size="sm" disabled={page.page <= 1} onClick={() => onPage(page.page - 1)}>
          <ChevronLeft />
          Previous
        </Button>
        <Button
          type="button"
          variant="outline"
          size="sm"
          disabled={page.page >= pages}
          onClick={() => onPage(page.page + 1)}
        >
          Next
          <ChevronRight />
        </Button>
      </div>
    </div>
  );
}

/** A table-friendly time: relative within a day, the date after that. Exact on hover. */
export function When({ at }: { at: string | null | undefined }) {
  if (!at) return <span className="text-muted-foreground">never</span>;
  const d = new Date(at);
  return (
    <time dateTime={at} title={exactTime(d)} className="whitespace-nowrap">
      {compactTime(d, new Date())}
    </time>
  );
}

/** "in 5 days" / "3 hours ago", with the exact time on hover. */
export function Relative({ at }: { at: string | null | undefined }) {
  if (!at) return <span className="text-muted-foreground">never</span>;
  const d = new Date(at);
  return (
    <time dateTime={at} title={exactTime(d)} className="whitespace-nowrap">
      {relativeTime(d, new Date())}
    </time>
  );
}

/** The full date and time, for detail views. */
export function Exact({ at }: { at: string | null | undefined }) {
  if (!at) return <span className="text-muted-foreground">never</span>;
  const d = new Date(at);
  return (
    <time dateTime={at} title={relativeTime(d, new Date())}>
      {exactTime(d)}
    </time>
  );
}

export function Mono({ children, className }: { children: ReactNode; className?: string }) {
  return <code className={cn("rounded bg-muted px-1.5 py-0.5 font-mono text-xs", className)}>{children}</code>;
}

export function Tags({ values }: { values: string[] }) {
  return (
    <span className="flex flex-wrap gap-1">
      {values.map((v) => (
        <Mono key={v}>{v}</Mono>
      ))}
    </span>
  );
}

export type Tone = "success" | "warning" | "destructive" | "neutral";

/** Status as a text-labelled badge; colour is never the only signal. */
export function Status({ tone, children }: { tone: Tone; children: ReactNode }) {
  return (
    <Badge variant={`${tone}-subtle`} className="whitespace-nowrap font-medium">
      {children}
    </Badge>
  );
}

/** A label above its control, with an optional hint underneath. */
export function Field({
  label,
  htmlFor,
  hint,
  error,
  className,
  children,
}: {
  label: ReactNode;
  htmlFor?: string;
  hint?: ReactNode;
  /** What is wrong with the value, shown instead of the hint. */
  error?: ReactNode;
  className?: string;
  children: ReactNode;
}) {
  return (
    <div className={cn("space-y-2", className)}>
      <Label htmlFor={htmlFor}>{label}</Label>
      {children}
      {error ? (
        <p role="alert" className="text-xs text-destructive">
          {error}
        </p>
      ) : (
        hint && <p className="text-xs text-muted-foreground">{hint}</p>
      )}
    </div>
  );
}

export interface Option {
  value: string;
  label: ReactNode;
}

/** Radix select. An empty `value` shows the placeholder. */
export function SelectField({
  id,
  value,
  onChange,
  options,
  placeholder,
  className,
}: {
  id?: string;
  value: string;
  onChange: (value: string) => void;
  options: Option[];
  placeholder?: string;
  className?: string;
}) {
  return (
    <Select value={value === "" ? undefined : value} onValueChange={onChange}>
      <SelectTrigger id={id} className={cn("w-full", className)}>
        <SelectValue placeholder={placeholder} />
      </SelectTrigger>
      <SelectContent>
        {options.map((o) => (
          <SelectItem key={o.value} value={o.value}>
            {o.label}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

export function CheckField({
  id,
  checked,
  onChange,
  children,
  hint,
}: {
  id: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
  children: ReactNode;
  hint?: ReactNode;
}) {
  return (
    <div className="flex items-start gap-3">
      <Checkbox id={id} checked={checked} onCheckedChange={(v) => onChange(v === true)} className="mt-0.5" />
      <div className="space-y-1">
        <Label htmlFor={id} className="cursor-pointer font-normal leading-snug">
          {children}
        </Label>
        {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
      </div>
    </div>
  );
}

export interface Choice<T extends string> {
  value: T;
  title: string;
  description: ReactNode;
}

/**
 * Selectable cards for a small set of exclusive options. One per row by
 * default, as forms in modals are; full-width pages may ask for columns.
 */
export function ChoiceCards<T extends string>({
  name,
  value,
  onChange,
  choices,
  columns = 1,
}: {
  name: string;
  value: T;
  onChange: (value: T) => void;
  choices: Choice<T>[];
  columns?: 1 | 2 | 3;
}) {
  return (
    <RadioGroup
      value={value}
      onValueChange={(v) => {
        const found = choices.find((c) => c.value === v);
        if (found) onChange(found.value);
      }}
      className={cn("grid grid-cols-1 gap-3", columns === 2 && "md:grid-cols-2", columns === 3 && "md:grid-cols-3")}
    >
      {choices.map((c) => {
        const id = `${name}-${c.value}`;
        return (
          <Label
            key={c.value}
            htmlFor={id}
            className={cn(
              "flex cursor-pointer items-start gap-3 rounded-lg border p-4 font-normal transition-colors hover:bg-accent/50",
              value === c.value && "border-foreground/40 bg-accent/40",
            )}
          >
            <RadioGroupItem id={id} value={c.value} className="mt-0.5" />
            <span className="space-y-1">
              <span className="block text-sm font-medium">{c.title}</span>
              <span className="block text-xs leading-relaxed text-muted-foreground">{c.description}</span>
            </span>
          </Label>
        );
      })}
    </RadioGroup>
  );
}

/** Asks before a destructive or access-changing action runs. */
export function ConfirmDialog({
  open,
  title,
  description,
  confirmLabel,
  busy,
  destructive = true,
  onConfirm,
  onOpenChange,
}: {
  open: boolean;
  title: string;
  description: ReactNode;
  confirmLabel: string;
  busy?: boolean;
  /** Set false for confirmations that grant rather than take away. */
  destructive?: boolean;
  onConfirm: () => void;
  onOpenChange: (open: boolean) => void;
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>
        <DialogFooter className="gap-2">
          <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button type="button" variant={destructive ? "destructive" : "default"} disabled={busy} onClick={onConfirm}>
            {confirmLabel}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/**
 * Remembers which item a destructive action is pending for, so a page
 * needs one `ConfirmDialog` however many rows it has.
 */
export function useConfirm<T>() {
  const [target, setTarget] = useState<T | null>(null);
  return {
    target,
    ask: (t: T) => setTarget(t),
    open: target !== null,
    onOpenChange: (open: boolean) => {
      if (!open) setTarget(null);
    },
    close: () => setTarget(null),
  };
}

export function lines(text: string): string[] {
  return text
    .split(/[\n,]/)
    .map((s) => s.trim())
    .filter(Boolean);
}

/** A dialog that hosts a create/edit form; the form supplies its own footer. */
export function FormDialog({
  open,
  onOpenChange,
  title,
  description,
  wide,
  children,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description?: ReactNode;
  wide?: boolean;
  children: ReactNode;
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className={cn("max-h-[90vh] overflow-y-auto", wide && "sm:max-w-2xl")}>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          {description && <DialogDescription>{description}</DialogDescription>}
        </DialogHeader>
        {children}
      </DialogContent>
    </Dialog>
  );
}

export function DialogActions({ children }: { children: ReactNode }) {
  return <DialogFooter className="gap-2 pt-2">{children}</DialogFooter>;
}

/** Elements inside a row that keep their own click: links, buttons, menus. */
const ROW_INTERACTIVE = "a,button,input,select,textarea,label,[role=menuitem],[role=checkbox],[data-row-ignore]";

/**
 * Whether a click on `target` inside `row` should open the row's record:
 * not when it lands on a control of its own, and not from a portal (a menu
 * or dialog the row opened), whose events bubble through React to the row.
 */
export function opensRow(row: Element, target: Element): boolean {
  if (!row.contains(target)) return false;
  const hit = target.closest(ROW_INTERACTIVE);
  return !hit || hit === row || !row.contains(hit);
}

/**
 * Props that make a whole table row open its record, by click, Enter or
 * Space, so the name needs no link. `open` gets whether the user asked for
 * a new tab (Cmd/Ctrl-click or middle click). Selecting text never opens it.
 */
export function rowOpener(open: (newTab: boolean) => void, className?: string | false | null) {
  const click = (e: MouseEvent<HTMLTableRowElement>, newTab: boolean) => {
    if (!opensRow(e.currentTarget, e.target as Element)) return;
    if (window.getSelection()?.toString()) return;
    open(newTab);
  };
  return {
    tabIndex: 0,
    className: cn("cursor-pointer focus-visible:bg-muted/50 focus-visible:outline-none", className),
    onClick: (e: MouseEvent<HTMLTableRowElement>) => click(e, e.metaKey || e.ctrlKey),
    onAuxClick: (e: MouseEvent<HTMLTableRowElement>) => {
      if (e.button === 1) click(e, true);
    },
    onKeyDown: (e: KeyboardEvent<HTMLTableRowElement>) => {
      if (e.target !== e.currentTarget || (e.key !== "Enter" && e.key !== " ")) return;
      e.preventDefault();
      open(e.metaKey || e.ctrlKey);
    },
  };
}

/** {@link rowOpener} for a row whose record has its own page. */
export function rowLink(href: string) {
  return rowOpener((newTab) => {
    if (newTab) window.open(href, "_blank", "noopener");
    else window.location.hash = href;
  });
}

export function RowActions({ children }: { children: ReactNode }) {
  return <div className="flex items-center justify-end gap-2">{children}</div>;
}

export interface RowMenuItem {
  label: string;
  icon: LucideIcon;
  onSelect: () => void;
  disabled?: boolean;
  /** Why the item is disabled, shown as its tooltip. */
  reason?: string;
  /** Destructive items go last, after a separator, in the destructive colour. */
  destructive?: boolean;
}

/**
 * The "…" menu at the end of a table row. A row shows at most one action
 * of its own; everything else lives here, so rows stay quiet and scannable.
 */
export function RowMenu({ label, items }: { label: string; items: RowMenuItem[] }) {
  const regular = items.filter((i) => !i.destructive);
  const destructive = items.filter((i) => i.destructive);
  const render = (item: RowMenuItem) => (
    <DropdownMenuItem
      key={item.label}
      disabled={item.disabled}
      title={item.disabled ? item.reason : undefined}
      onSelect={item.onSelect}
      className={cn(
        "gap-2 [&>svg]:size-4 [&>svg]:shrink-0",
        item.destructive && "text-destructive focus:bg-destructive/10 focus:text-destructive",
      )}
    >
      <item.icon />
      {item.label}
    </DropdownMenuItem>
  );
  return (
    <DropdownMenu modal={false}>
      <DropdownMenuTrigger asChild>
        <Button type="button" variant="ghost" size="icon" className="size-8" aria-label={`Actions for ${label}`}>
          <MoreHorizontal />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="min-w-44">
        {regular.map(render)}
        {regular.length > 0 && destructive.length > 0 && <DropdownMenuSeparator />}
        {destructive.map(render)}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
