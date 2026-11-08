<!--
SPDX-FileCopyrightText: 2026 tokenless contributors
SPDX-License-Identifier: MIT OR Apache-2.0
-->

# ADR 0004: Sessions are the agent's credential

- **Status:** Accepted and implemented.
- **Date:** 2026-11-08

## Context

An agent reached the proxy with a session minted from an access bundle,
but to get one its machine needed an API key with the `session_issuer`
role, which could mint any number of sessions from any bundle in its
vault until it expired (up to a year). The thing handed to the agent's
machine was therefore broader and longer-lived than the session it was
used for, and the console showed it as a key, not as the agent's access:
there was no page that said what one agent did.

## Decision

- **A session is what an agent is given.** People create one on an
  access bundle's page with a name, a lifetime and an optional request
  limit; the token is shown once. `tokenless run`, `exec` and
  `session start` use the session in `TOKENLESS_SESSION_TOKEN` (or
  `--session-token-file`) as is: they don't renew or end it, and `run`
  says so on standard error when it expires. Minting from `--bundle`
  stays for people signed in with `tokenless login` and for editor API
  keys, renewed and ended per run as before.
- **The `session_issuer` role is removed**, and migration 0009 deletes
  the keys that had it. API keys are for scripts that manage a vault
  (`editor`, `viewer`).
- **Session lifetimes are long enough to hand over.** The default cap
  is 7 days and the highest an admin may set is 90 days. Revoked sessions
  stay in every snapshot until they expire, so the ceiling bounds that
  list. An instance created before this change keeps the 1-hour cap it
  had (the migration pins it) until an admin changes it.
- **Each session has a page** with its requests (`proxy.*` audit events
  carrying its id) and its history: the audit query for a session now
  also returns events whose target is `session:<id>` (created,
  relabelled, revoked). Editors see the lifetimes they may choose through
  `GET /vaults/{id}/sessions/limits`, since Settings stay admin-only.

## Consequences

- A leaked session token reaches one bundle's services until it expires,
  is revoked, or uses up its request limit; a leaked issuer key could
  mint sessions for every bundle in a vault.
- CI jobs store a session token instead of a key, and need a new one
  when it expires. A job that wants a fresh short session per run uses an
  editor key, which can do more than mint; there is no narrower role.
- Existing `session_issuer` keys stop working on upgrade, with
  "API key is unknown". The release notes have to say so.
