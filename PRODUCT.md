<!--
SPDX-FileCopyrightText: 2026 tokenless contributors
SPDX-License-Identifier: MIT OR Apache-2.0
-->

# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Engineers who give AI agents (Claude Code, Codex, other coding agents) and
CI jobs access to third-party APIs without handing them the keys. They set
up vaults, services (credentials) and rules occasionally, then create and
watch sessions daily, and check the audit log when something looks wrong.
Admins also manage people, API keys, proxies and instance settings.

## Product Purpose

tokenless is a self-hosted credential broker. Agents send HTTPS traffic
through a local forward proxy with a short-lived session token; for hosts a
rule covers, the proxy terminates TLS and injects the real credential, so the
agent never sees it. Success: a person goes from "my agent needs GitHub" to
an agent running with scoped, revocable, audited access in minutes, and can
always answer "what did this agent reach, and with what".

## Positioning

The agent never holds the secret. Secrets are write-only (nobody, admins
included, can read one back), sessions are scoped to a vault's rules with a
lifetime and optional request limit, revocation reaches proxies within
seconds, and the proxy fails closed: no valid policy lease or no audit record
means no injection.

## Operating Context

- A web console (this UI), served by `tokenless serve` and often reached
  over a private network.
- A CLI on the agent's machine: `tokenless run -- <agent>` starts an agent
  behind the proxy; `tokenless skill --install` teaches Claude Code the broker.
- Proxies (`tokenless node run`) on the agent's machine or nearby, with an MCP
  gateway for MCP servers.
- Access bundles group a vault's rules by job (`code-review`); sessions are
  minted from them.
- People hand a session to an agent by pasting commands, so ready-to-paste
  commands are part of the product.

## Capabilities and Constraints

- Roles: admin, editor, viewer. Viewers read; editors change vaults and
  sessions; admins manage people, keys, proxies and settings.
- Secrets are write-only: no screen may show a stored credential, and a
  minted token is shown once.
- The console runs under a content security policy that allows only its own
  origin: fonts and assets are bundled, nothing is loaded from other hosts.
- Self-hosted, small footprint; the audit log and session logs can be large
  and are paginated.

## Brand Commitments

- The product name is written `tokenless`, lowercase.
- The console keeps the Temps design system: Temps' tokens (Geist, neutral
  greys, status colours) and its component family. Redesign work changes page
  structure, hierarchy and flows within it, not the visual identity.

## Evidence on Hand

No customers, testimonials, benchmarks or usage numbers exist; none may be
invented. Service logos for supported integrations live in `site/logos` and
the template catalogue.

## Product Principles

- Show the next action: an empty or unconfigured feature says what is missing
  and links to the fix; a page flags problems and what to do about them.
- Commands ready to paste beat explanations.
- Few columns, compact times, details on the record's own page; a sparse
  list never stretches across a wide screen.
- Pages don't explain themselves: no paragraph under a title.
- Complex forms are full pages; dialogs hold short, single-column forms.
