// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import type { TripwireKind } from "./api";

export const TRIPWIRE_KINDS: { value: TripwireKind; label: string; description: string }[] = [
  { value: "aws", label: "AWS access key", description: "A key pair for ~/.aws/credentials, the first thing someone tries." },
  { value: "github", label: "GitHub token", description: "A personal access token, as in GITHUB_TOKEN." },
  { value: "openai", label: "OpenAI API key", description: "An API key, as in OPENAI_API_KEY." },
  { value: "generic", label: "Generic API key", description: "An API key of no provider in particular." },
];

export function kindLabel(kind: TripwireKind): string {
  return TRIPWIRE_KINDS.find((k) => k.value === kind)?.label ?? kind;
}

/** The hosts the proxy opens under the deny policy to look for a decoy of `kind`. */
export const DECOY_HOSTS: Record<TripwireKind, string[]> = {
  aws: ["sts.amazonaws.com", "iam.amazonaws.com", "s3.amazonaws.com"],
  github: ["api.github.com", "github.com"],
  openai: ["api.openai.com"],
  generic: [],
};

/** Where the proxy looks for a decoy of `kind`, in one line. */
export function whereSeen(kind: TripwireKind): string {
  const hosts = DECOY_HOSTS[kind];
  const always = "in every request a proxy opens for a session's rules";
  if (hosts.length === 0) return `Seen ${always}.`;
  return `Seen ${always}, and on ${hosts.join(", ")} when other hosts are blocked.`;
}
