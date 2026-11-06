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
| Session issuer | Launchers and CI jobs that start agents. Mints sessions in its vault and nothing else. |
| Editor | Tools that manage rules, bundles and sessions in one vault. |
| Viewer | Read-only integrations. |

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

That is how `tokenless run` cleans up with only a session issuer key. A
key allowed to manage sessions can also revoke any session in its vault
by id.

## In CI

Store a session issuer key as a CI secret and start the job's agent with
`tokenless run`. The job never holds a service credential, and when it
finishes, its session ends:

```sh
tokenless run --server https://tokenless.internal --bundle release -- ./scripts/release.sh
```

The proxy has to be reachable from the runner: run `tokenless node run` on
it, or point `--proxy` at a proxy on a private address.
