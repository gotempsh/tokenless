// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// The commands a bundle's Connect tab shows: how to start an agent with
// it and how to fill a script's environment by reference.

import type { CredentialMeta } from "./api";

/** Quotes `value` for a POSIX shell when it needs it. */
export function shellQuote(value: string): string {
  if (/^[A-Za-z0-9._/:=@%+,-]+$/.test(value)) return value;
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

function upperSnake(value: string): string {
  return value
    .toUpperCase()
    .replace(/[^A-Z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
}

/** One `NAME=cb://<service>/<field>` a script can ask for. */
export interface EnvReference {
  name: string;
  reference: string;
  service: string;
}

/**
 * The references for every placeholder of `credentials`, named after the
 * placeholder's environment variable when it has one. When two claim the
 * same name the first is kept, as `tokenless run` does.
 */
export function envReferences(credentials: CredentialMeta[]): EnvReference[] {
  const out: EnvReference[] = [];
  for (const c of credentials) {
    for (const s of c.substitutions) {
      const name = s.env ?? upperSnake(`${c.template_id}_${s.field}`);
      if (!name || out.some((r) => r.name === name)) continue;
      out.push({ name, reference: `cb://${c.name}/${s.field}`, service: c.name });
    }
  }
  return out;
}

export interface AgentChoice {
  id: string;
  label: string;
  command: string;
  /** Its maker's logo among the bundled service logos; none for "another command". */
  logo?: string;
}

export const AGENTS: AgentChoice[] = [
  { id: "claude", label: "Claude Code", command: "claude", logo: "anthropic" },
  { id: "codex", label: "Codex", command: "codex", logo: "openai" },
  { id: "other", label: "Another command", command: "<agent-command>" },
];

function vaultFlag(vault?: string): string {
  return vault ? ` --vault ${shellQuote(vault)}` : "";
}

/** `tokenless run -- <command>`, with the session in TOKENLESS_SESSION_TOKEN. */
export function runAgentCommand(command: string): string {
  return `tokenless run -- ${command}`;
}

/**
 * `tokenless run --bundle <name> -- <command>`: for someone signed in with
 * `tokenless login`, who can mint a session that ends with the command.
 */
export function signedInRunCommand(bundle: string, command: string, vault?: string): string {
  return `tokenless run${vaultFlag(vault)} --bundle ${shellQuote(bundle)} -- ${command}`;
}

/** `tokenless exec` with each reference as an argument. */
export function execCommand(refs: EnvReference[]): string {
  const args = refs.map((r) => `${r.name}=${shellQuote(r.reference)}`);
  return ["tokenless exec", ...args, "-- ./script.sh"].join(" \\\n  ");
}

/** A committable `.env.broker`: references only. */
export function envFile(refs: EnvReference[]): string {
  const body = refs.map((r) => `${r.name}=${/\s/.test(r.reference) ? `"${r.reference}"` : r.reference}`);
  return ["# References, not secrets: safe to commit.", ...body].join("\n") + "\n";
}
