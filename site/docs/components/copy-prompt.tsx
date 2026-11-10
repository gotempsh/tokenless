// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

'use client';
import { Check, Sparkles } from 'lucide-react';
import { useState, type MouseEvent } from 'react';
import { buttonVariants } from 'fumadocs-ui/components/ui/button';
import { Popover, PopoverContent, PopoverTrigger } from 'fumadocs-ui/components/ui/popover';
import { harnesses } from './harness-logos';
import { agentPrompt } from './prompt';

type CopyState = 'idle' | 'copied' | 'failed';

/** Copies the set-up prompt; says so for two seconds, or that the browser refused. */
function useCopyPrompt() {
  const [state, setState] = useState<CopyState>('idle');
  const copy = async (): Promise<boolean> => {
    let ok = true;
    try {
      await navigator.clipboard.writeText(agentPrompt);
      setState('copied');
    } catch {
      ok = false;
      setState('failed');
    }
    setTimeout(() => setState('idle'), 2000);
    return ok;
  };
  return { state, copy };
}

function PromptText() {
  return (
    <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-words rounded-md border bg-fd-secondary p-3 font-mono text-xs leading-relaxed">
      {agentPrompt}
    </pre>
  );
}

/**
 * The prompt in the top bar of every page. A click copies it; where the
 * browser refuses the clipboard, the prompt opens beside the button to be
 * selected by hand.
 */
export function CopyPromptButton() {
  const { state, copy } = useCopyPrompt();
  const [open, setOpen] = useState(false);
  const onClick = async (e: MouseEvent) => {
    // The button copies; the popover only opens when copying fails.
    e.preventDefault();
    if (!(await copy())) setOpen(true);
  };
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger
        onClick={onClick}
        title="Copy a prompt that installs and sets up tokenless, for your coding agent"
        className={buttonVariants({ variant: 'secondary', size: 'sm', className: 'gap-1.5 rounded-full' })}
      >
        {state === 'copied' ? <Check className="size-3.5" /> : <Sparkles className="size-3.5" />}
        {state === 'copied' ? 'Copied' : 'Copy prompt'}
      </PopoverTrigger>
      <PopoverContent align="end" className="w-[min(32rem,calc(100vw-2rem))] space-y-2">
        <p className="text-sm">Your browser refused the clipboard. Select the prompt and copy it:</p>
        <PromptText />
      </PopoverContent>
    </Popover>
  );
}

/** The coding agents the prompt is written for, as their logos. */
function HarnessLogos() {
  return (
    <ul
      className="flex items-center gap-2"
      aria-label="Works with Claude Code, Codex, Cursor, Gemini CLI, opencode and other coding agents"
    >
      {harnesses.map((h) => (
        <li
          key={h.key}
          title={h.name}
          className="flex size-8 items-center justify-center rounded-lg border bg-fd-background p-1.5 [&_svg]:size-full"
          dangerouslySetInnerHTML={{ __html: h.svg }}
        />
      ))}
    </ul>
  );
}

/**
 * The prompt on the home page: which agents it is for, one line on what it
 * does, and the prompt itself underneath so nobody pastes one they haven't
 * read. Where the clipboard is refused, the prompt opens to be selected.
 */
export function CopyPrompt() {
  const { state, copy } = useCopyPrompt();
  const [open, setOpen] = useState(false);
  return (
    <div className="not-prose my-6 rounded-xl border bg-fd-card p-4">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-3">
        <HarnessLogos />
        <p className="min-w-48 flex-1 text-sm text-fd-muted-foreground">
          Paste it into your coding agent to install tokenless.
        </p>
        <button
          type="button"
          onClick={async () => {
            if (!(await copy())) setOpen(true);
          }}
          className={buttonVariants({ variant: 'primary', className: 'gap-2' })}
        >
          {state === 'copied' ? <Check className="size-4" /> : <Sparkles className="size-4" />}
          {state === 'copied' ? 'Copied' : state === 'failed' ? 'Select it below' : 'Copy prompt'}
        </button>
      </div>
      <details open={open} onToggle={(e) => setOpen(e.currentTarget.open)} className="mt-3 text-sm">
        <summary className="cursor-pointer text-fd-muted-foreground hover:text-fd-foreground">Read the prompt</summary>
        <div className="mt-2">
          <PromptText />
        </div>
      </details>
    </div>
  );
}
