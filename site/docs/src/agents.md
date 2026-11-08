<!--
SPDX-FileCopyrightText: 2026 tokenless contributors
SPDX-License-Identifier: MIT OR Apache-2.0
-->

# Run an agent

An agent's credential is a **session**: a token that reaches one access
bundle's services until it expires or is revoked, optionally for a set
number of requests. Create one on the bundle's page (**Run an agent →
New session**: a name, how long it lasts, a request limit) and copy the
token; it is shown once. Then, where the agent runs:

```sh
export TOKENLESS_SESSION_TOKEN=v4.public...
tokenless run -- claude
```

Each session has a page under **Sessions** with every request it made and
its history: who created it, relabelled it or revoked it.

Signed in with `tokenless login` (or with an editor API key), `run` can
also mint a session itself from `--bundle`, renew it while the agent runs
and end it when the agent exits.

| Setting | Flag | Environment |
|---|---|---|
| Management API | `--server` | `TOKENLESS_URL` (default `http://127.0.0.1:8080`) |
| Session token | `--session-token-file` | `TOKENLESS_SESSION_TOKEN` |
| API key, to mint | `--api-key-file` | `TOKENLESS_API_KEY` (or the `tokenless login` session) |
| Vault | `--vault <name or id>` | `TOKENLESS_VAULT` (not needed with a vault-bound key) |
| Bundle | `--bundle <name or id>` | `TOKENLESS_BUNDLE` |
| Proxy | `--proxy host:port` | `TOKENLESS_PROXY_ADDRESS` (default `127.0.0.1:3128`) |

## `tokenless run`

```sh
tokenless run -- claude                          # the session in TOKENLESS_SESSION_TOKEN
tokenless run --bundle code-review -- claude     # mint one for this run
```

`run` opens a **session port**: a
loopback proxy address that adds the session to every request and relays
it to the proxy. It starts the command with:

- `HTTPS_PROXY` (and `HTTP_PROXY`) pointing at the session port;
- trust files that include the broker's interception CA:
  `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE` and others;
- `NODE_USE_ENV_PROXY=1`, so Node's built-in `fetch` uses the proxy;
- no session token and no API key anywhere in its environment.

A session it minted is renewed while the command runs and ended when the
command exits; a session it was given is used as is, and `run` says so if
it expires mid-run. `run` exits with the command's code.

Pass `--ca-fingerprint` with the SHA-256 shown on the **Proxies** page to
refuse to start if the proxy presents a different CA.

## A session port for agents you start yourself

```sh
tokenless session start --bundle code-review \
  --listen 127.0.0.1:17323 --env-file ./agent.env
# in the agent's shell:
. ./agent.env && curl https://api.github.com/user
```

It prints the same exports and runs until Ctrl-C or SIGTERM. With
`--bundle` it mints the session, keeps it renewed and ends it on exit;
with `TOKENLESS_SESSION_TOKEN` it uses that session. The session port only listens on loopback, because
anything that reaches it uses the session; on a shared machine, other
local users can too.

## Managing the token yourself

```sh
TOKEN=$(tokenless session create --bundle code-review --ttl 15m)
HTTPS_PROXY="http://$TOKEN@127.0.0.1:3128" curl --cacert broker-ca.pem https://api.github.com/user
TOKENLESS_SESSION_TOKEN=$TOKEN tokenless session revoke
```

Download `broker-ca.pem` from the **Proxies** page (**Download CA**).

## What an agent can reach

```sh
tokenless session info          # behind run or session start
tokenless session info --json
```

It lists each service's hosts, the allowed methods and paths, and its
placeholders, never a secret.

## The agent skill

The skill tells an agent how to see what it can reach, hand a tool a
placeholder instead of a key, and read the proxy's answers below without
trying to work around them. Install it into the agents you use with the
[skills CLI](https://skills.sh):

```sh
npx skills add gotempsh/tokenless                    # this project, for the agents it finds
npx skills add gotempsh/tokenless -g -a claude-code  # every project, Claude Code only
```

The CLI clones the repository with git, so any git URL works too, using
your own git credentials: a fork, a mirror, or a copy you can only reach
over SSH.

```sh
npx skills add git@github.com:gotempsh/tokenless.git
npx skills add https://git.example.com/you/tokenless.git
```

Or from the binary, which installs the copy built into it, so it always
matches the CLI you have:

```sh
tokenless skill --install                        # ~/.claude/skills/tokenless/SKILL.md
tokenless skill --install --dir .claude/skills   # for one project
tokenless skill                                  # print it
```

## When the proxy says no

Answers from the proxy itself carry the header `x-broker-error: 1` and a
plain-text reason.

| Status | Meaning |
|---|---|
| 403 `no rule in this session allows ...` | The host is in the session, but not this method or path. Widen the rule or the bundle. |
| 403 `no rule in this session covers <host>` | Other hosts are blocked and this one isn't in the session. |
| 403 `<host> resolves to <ip>, which is ...` | Connections to that address range are blocked (see [Settings](settings.md#private-addresses)). |
| 407 `proxy session rejected: ...` | The session expired or was revoked. |
| 429 `session request limit of <n> reached` | The session used all its requests. |
| 503 with `retry-after` | The proxy hasn't received a brand-new session yet. Retry after the delay. |
| 502 | The service failed or couldn't be reached. |

A 401 or 403 **without** `x-broker-error` comes from the service: the
credential reached it and was refused, for example an expired token or
missing scopes. Replace the secret on the service's page.

## Cutting an agent off

Revoke its session on the **Sessions** page, disable the rule, or delete
the bundle, which also ends every live session minted from it. Proxies
refuse the session at their next policy refresh, within seconds.
