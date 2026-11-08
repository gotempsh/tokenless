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
