<!--
SPDX-FileCopyrightText: 2026 tokenless contributors
SPDX-License-Identifier: MIT OR Apache-2.0
-->

# Security model

The full design, threat model and trade-offs are in
[ADR 0001](https://github.com/gotempsh/tokenless/blob/main/docs/adr/0001-architecture.md).
This page is the summary an operator needs.

## What it protects against

- **An agent leaking a credential.** The agent never holds one. A
  compromised agent leaks at most a session token: bound to specific
  rules, valid for an hour or less, and revocable within seconds.
- **A credential being used outside its scope.** The proxy adds a
  credential only to requests a session's rules allow, and only over
  HTTPS to the service's own hosts.
- **Reaching your private network through the proxy.** Loopback, private,
  link-local and metadata addresses are refused unless you allow them.
- **Reading secrets back.** Secrets are write-only for everyone, admins
  included. They are encrypted at rest with AES-256-GCM under
  `master.key` and only ever leave the control plane sealed to an enrolled
  proxy.

## What it doesn't

- **A compromised proxy host** exposes the credentials of the rules in its
  policy and the interception CA's key. Run separate proxies per trust
  domain, and trust the interception CA only inside agent sandboxes.
- **A compromised control plane host** with access to `master.key` and the
  database exposes every secret. Protect it like any secret store.
- **What a service does with a request it accepts.** A rule that allows
  `DELETE` lets an agent delete. Use read-only access and narrow paths
  where you can.

## Failing closed

Proxies run from an Ed25519-signed policy snapshot with a lease. When the
lease lapses (60 seconds by default) because the control plane is
unreachable, the proxy refuses traffic. It refuses to inject a credential
when it can't record the audit event. A control plane outage therefore
stops all injection within one lease; that is deliberate.

## Accounts

- Passwords are hashed with argon2id. An authenticator app (TOTP) is
  optional per account and recommended for admins.
- With an authenticator, sensitive actions (adding or widening
  credentials and rules, managing people, API keys, templates and proxies)
  need a code entered within the last five minutes.
- The console session cookie is `HttpOnly`, `Secure` and `SameSite=Strict`,
  and every change carries a CSRF token.
- API keys are stored only as hashes and expire.

## Verifying a release

Every release archive and image is signed with Sigstore by the release
workflow and has a build provenance attestation. See
[Install → Download a release yourself](install.md#download-a-release-yourself).

## Reporting a vulnerability

Please report it privately through
[GitHub security advisories](https://github.com/gotempsh/tokenless/security/advisories/new),
not in a public issue.
