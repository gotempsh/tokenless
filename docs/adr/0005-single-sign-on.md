<!--
SPDX-FileCopyrightText: 2026 tokenless contributors
SPDX-License-Identifier: MIT OR Apache-2.0
-->

# ADR 0005: Single sign-on with OpenID Connect

- **Status:** Accepted and implemented.
- **Date:** 2026-11-08

## Context

Every person had a local account: a password, an optional authenticator,
and a role an admin set by hand. Teams that already manage people and
groups in an identity provider had to invite each person again, remember
to disable them when they left, and keep roles in step with groups by
hand.

## Decision

- **OpenID Connect, authorization code flow with PKCE.** Admins add
  providers (issuer, client ID, optional client secret, redirect URI,
  scopes, claims, group mappings) in the console or through
  `/api/v1/identity-providers`. Managing them is the instance-level
  `identity_provider_manage` action, admin-only and behind step-up.
- **The browser carries the flow, and the server stores nothing until
  the provider answers.** `start` seals the state (hashed), nonce, PKCE
  verifier, purpose and return path into a `__Host-` cookie with
  AES-256-GCM, under a key derived with HKDF from an instance secret.
  The browser can neither read nor change it. The callback accepts an
  answer only with that cookie, within 10 minutes, and when the `state`
  matches, then clears the cookie. `start` needs no account, so
  server-side requests would be a table anyone could fill. A global cap
  on them would let an anonymous client crowd out every real sign-in.
- **ID tokens are verified here**, with `ring`, which the TLS stack
  already depends on: RS/PS 256–512, ES256/384 and EdDSA; `none`, HMAC
  and tokens with `crit` headers are refused. Keys come from the
  provider's JWKS, cached with its discovery document for 15 minutes and
  refetched (at most every 30 seconds) for an unknown `kid`. Issuer,
  audience and `azp`, expiry, `iat`, `nbf` (60 seconds of skew), nonce
  and subject are checked. User info is read only when the token lacks
  the groups or username claim, and its subject must match.
- **Groups decide the role at every sign-in.** The highest mapped role
  wins. No mapped group means no access: the sign-in is refused, audited,
  and the message lists (up to 20 of) the groups the provider sent. The
  first sign-in creates the account; a username already held by a local
  account is refused rather than linked. Admins can't change these roles
  by hand, and the last admin is never demoted by its groups.
- **Step-up re-authenticates at the provider** with `prompt=login` and
  `max_age=0`; the step-up time is the token's `auth_time`, which must
  not predate the request. The console does it in a popup so the page
  that asked keeps its state.
- **Local accounts stay.** Admins may limit password sign-in to local
  admins (break-glass for a provider outage). Then local non-admin
  sessions stop authenticating and invites create only admins.
- **Turning a provider off ends its sessions**: every session check
  confirms the person's provider is still on. A provider with linked
  accounts can't be deleted.
- **The client secret is write-only**, encrypted with the instance key
  like other secrets and included in key rotation.
- **Provider traffic** trusts what credential validation trusts, follows
  no redirects, times out after 10 seconds and reads at most 1 MiB. The
  agents' egress policy doesn't apply: an admin names the provider, and
  it is often on the internal network. Only `https` URLs are accepted,
  or `http` to loopback.

## Consequences

- People who sign in with a provider have no password here, so
  `tokenless login` doesn't work for them; in a terminal they use a
  session token or an API key. A device-code flow could close that gap.
- Leaving the provider, or leaving its mapped groups, removes access at
  the next sign-in, not at once: an existing console session lasts until
  it expires. Disabling the account here, or turning the provider off,
  is immediate.
- Providers that don't put groups in the ID token or user info (Google's
  OpenID Connect, for one) can't be mapped and so can't be used.
- An answer is not recorded as used on the server. Replaying one needs
  the sign-in's cookie, which is `HttpOnly` and cleared by the callback,
  and the provider refuses an authorization code used twice, as OAuth
  requires.
- An admin disabling an account while it signs in is never undone: the
  role from groups is written only while the account is still enabled.
- SAML is not supported.
