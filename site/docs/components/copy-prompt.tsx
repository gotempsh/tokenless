// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

'use client';
import { Check, Copy } from 'lucide-react';
import { useState } from 'react';
import { agentPrompt } from './prompt';

/**
 * Copies the set-up prompt for a coding agent, and shows it underneath so
 * nobody pastes a prompt they haven't read. Where the clipboard is refused,
 * the prompt opens instead, to be selected by hand.
 */
export function CopyPrompt() {
  const [state, setState] = useState<'idle' | 'copied' | 'failed'>('idle');
  const [open, setOpen] = useState(false);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(agentPrompt);
      setState('copied');
    } catch {
      setOpen(true);
      setState('failed');
    }
    setTimeout(() => setState('idle'), 2000);
  };

  return (
    <div className="not-prose my-6 rounded-xl border bg-fd-card p-4">
      <div className="flex flex-col items-start gap-3 sm:flex-row sm:items-center">
        <button
          type="button"
          onClick={copy}
          className="inline-flex items-center gap-2 rounded-md bg-fd-primary px-3 py-2 text-sm font-medium text-fd-primary-foreground transition-opacity hover:opacity-90"
        >
          {state === 'copied' ? <Check className="size-4" /> : <Copy className="size-4" />}
          {state === 'copied' ? 'Copied' : state === 'failed' ? 'Select the prompt below' : 'Copy prompt'}
        </button>
        <p className="min-w-0 text-sm text-fd-muted-foreground sm:flex-1">
          Paste it into Claude Code, Codex or another coding agent. It installs tokenless and walks you through
          adding services; you type every token into your own terminal, never into the chat.
        </p>
      </div>
      <details open={open} onToggle={(e) => setOpen(e.currentTarget.open)} className="mt-3 text-sm">
        <summary className="cursor-pointer text-fd-muted-foreground hover:text-fd-foreground">Read the prompt</summary>
        <pre className="mt-2 whitespace-pre-wrap rounded-md border bg-fd-secondary p-3 font-mono text-xs leading-relaxed">
          {agentPrompt}
        </pre>
      </details>
    </div>
  );
}
