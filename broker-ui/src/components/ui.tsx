// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { useState, type ReactNode } from "react";
import type { Page } from "../api";

export function ErrorBanner({ error }: { error: string | null }) {
  if (!error) return null;
  return (
    <div className="banner error" role="alert">
      {error}
    </div>
  );
}

export function Loading({ rows = 3 }: { rows?: number }) {
  return (
    <div className="skeleton-list" aria-busy="true">
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className="skeleton" />
      ))}
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}

export function Section({ title, actions, children }: { title: string; actions?: ReactNode; children: ReactNode }) {
  return (
    <section className="section">
      <header className="section-header">
        <h2>{title}</h2>
        <div className="actions">{actions}</div>
      </header>
      {children}
    </section>
  );
}

/** A credential minted by the request: shown once, never retrievable again. */
export function OneTimeSecret({ label, value, hint }: { label: string; value: string; hint?: ReactNode }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="banner once">
      <strong>{label}</strong>
      <p>This is the only time it is shown. Store it now.</p>
      <div className="secret-row">
        <code className="secret">{value}</code>
        <button
          type="button"
          onClick={() => {
            void navigator.clipboard.writeText(value).then(() => setCopied(true));
          }}
        >
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      {hint && <div className="hint">{hint}</div>}
    </div>
  );
}

export function Pager<T>({ page, onPage }: { page: Page<T> | undefined; onPage: (p: number) => void }) {
  if (!page) return null;
  const pages = Math.max(1, Math.ceil(page.total / page.page_size));
  return (
    <div className="pager">
      <button type="button" disabled={page.page <= 1} onClick={() => onPage(page.page - 1)}>
        Previous
      </button>
      <span>
        {page.page} / {pages} ({page.total} total)
      </span>
      <button type="button" disabled={page.page >= pages} onClick={() => onPage(page.page + 1)}>
        Next
      </button>
    </div>
  );
}

export function When({ at }: { at: string | null | undefined }) {
  if (!at) return <span className="muted">never</span>;
  const d = new Date(at);
  return <time dateTime={at} title={at}>{d.toLocaleString()}</time>;
}

export function Tags({ values }: { values: string[] }) {
  return (
    <span className="tags">
      {values.map((v) => (
        <code key={v} className="tag">
          {v}
        </code>
      ))}
    </span>
  );
}

export function lines(text: string): string[] {
  return text
    .split(/[\n,]/)
    .map((s) => s.trim())
    .filter(Boolean);
}
