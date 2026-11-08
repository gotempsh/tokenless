// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Page layouts shared by the console: a record's page with its facts beside
// the work, and settings sections with their label beside the controls.

import type { ReactNode } from "react";
import { cn } from "../lib/utils";
import { Panel } from "./common";

/**
 * A record's page: its working content (lists, logs, tabs) in the main
 * column and its facts in a 320px column on the right. On narrow screens
 * the facts come first, above the work.
 */
export function DetailLayout({ facts, children }: { facts: ReactNode; children: ReactNode }) {
  return (
    <div className="grid items-start gap-6 lg:grid-cols-[minmax(0,1fr)_320px] lg:gap-8">
      <aside className="min-w-0 space-y-4 lg:order-last">{facts}</aside>
      <div className="min-w-0 space-y-8">{children}</div>
    </div>
  );
}

/** A panel of labelled facts, one under another. */
export function FactList({ title, action, children }: { title?: string; action?: ReactNode; children: ReactNode }) {
  return (
    <Panel className="p-4">
      {(title || action) && (
        <div className="mb-3 flex items-center justify-between gap-2">
          {title && <h2 className="text-sm font-semibold">{title}</h2>}
          {action}
        </div>
      )}
      <dl className="space-y-3">{children}</dl>
    </Panel>
  );
}

export function Fact({ label, children, className }: { label: string; children: ReactNode; className?: string }) {
  return (
    <div className={cn("min-w-0 space-y-0.5", className)}>
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="text-sm [overflow-wrap:anywhere]">{children}</dd>
    </div>
  );
}

/**
 * One settings section: its name and a short line on the left, its
 * controls on the right; stacked on narrow screens.
 */
export function SettingsSection({ title, hint, children }: { title: string; hint?: ReactNode; children: ReactNode }) {
  return (
    <section className="grid gap-4 border-t py-6 first:border-t-0 first:pt-0 md:grid-cols-[240px_minmax(0,1fr)] md:gap-8">
      <div className="min-w-0">
        <h2 className="text-sm font-semibold">{title}</h2>
        {hint && <p className="mt-1 text-sm text-muted-foreground">{hint}</p>}
      </div>
      <div className="min-w-0 space-y-3">{children}</div>
    </section>
  );
}
