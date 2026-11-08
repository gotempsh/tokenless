<!--
SPDX-FileCopyrightText: 2026 tokenless contributors
SPDX-License-Identifier: MIT OR Apache-2.0
-->

# Automation and API keys

Create API keys under **API keys**. Each key belongs to exactly one vault
and one role, and expires (1 to 365 days). Only a hash is stored; the key
is shown once.

| Role | Use it for |
|---|---|
| Editor | Tools that manage rules, bundles and sessions in one vault. |
| Viewer | Read-only integrations. |

Agents don't get API keys: give them a session (below).

## Mint a session over the API

By bundle:

```sh
curl -s -X POST "$TOKENLESS_URL/api/v1/vaults/<vault-id>/sessions" \
  -H "Authorization: Bearer $TOKENLESS_API_KEY" \
  -H 'content-type: application/json' \
  -d '{"bundle":"code-review","ttl_secs":900,"labels":{"agent":"build-bot"}}'
```

Or by rules, with `"rule_ids": ["..."]` instead of `"bundle"`. Add
`"request_limit": 100` to cap how many requests the session may make.
Labels show on the **Sessions** page and in the audit log.

The response holds the session token. Send it as the proxy's credentials:
`HTTPS_PROXY=http://<token>@127.0.0.1:3128`.

## End a session

Holding a session's token is enough to end it:

```sh
curl -s -X POST "$TOKENLESS_URL/api/v1/sessions/revoke-self" \
  -H "Authorization: Bearer <session token>"
```

A key allowed to manage sessions can also revoke any session in its
vault by id.

## In CI

Create a session for the job on the bundle's page (as long as the job
should keep working, with a request limit if you like), store its token
as a CI secret named `TOKENLESS_SESSION_TOKEN`, and start the job's
agent with `tokenless run`. The job never holds a service credential,
and revoking the session cuts it off:

```sh
tokenless run --server https://tokenless.internal -- ./scripts/release.sh
```

For a fresh short session per run, store an editor key as
`TOKENLESS_API_KEY` instead and add `--bundle release`: `run` mints the
session and ends it when the job finishes. An editor key can do more than
mint, so prefer the session token where it fits.

The proxy has to be reachable from the runner: run `tokenless node run` on
it, or point `--proxy` at a proxy on a private address.
