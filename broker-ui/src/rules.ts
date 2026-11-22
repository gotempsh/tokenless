// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Rules in words, for lists.

import type { Rule } from "./api";

/** {@link allowsLabel} for a rule that narrows neither paths nor methods. */
export const EVERYTHING = "Every path and method";

/** What a rule lets through on its hosts, naming only what it narrows. */
export function allowsLabel(r: Pick<Rule, "allow">): string {
  const paths = r.allow.paths.filter((p) => p !== "/*" && p !== "*");
  const methods = r.allow.methods.filter((m) => m !== "*");
  if (!paths.length && !methods.length) return EVERYTHING;
  return `${methods.length ? methods.join(", ") : "Any method"} on ${paths.length ? paths.join(", ") : "any path"}`;
}

/** Distinguish drafts even when another editor or list page already has copies. */
export function suggestedCopyName(name: string): string {
  const nonce = Array.from(crypto.getRandomValues(new Uint8Array(6)), byte => byte.toString(16).padStart(2, "0")).join("");
  const suffix = ` (copy ${nonce})`;
  // The server limits names to 100 UTF-8 bytes. encodeInto stops before splitting a code point.
  const { read } = new TextEncoder().encodeInto(name, new Uint8Array(100 - suffix.length));
  return name.slice(0, read).trimEnd() + suffix;
}
