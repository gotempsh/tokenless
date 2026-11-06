---
# SPDX-FileCopyrightText: 2026 tokenless contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
name: tokenless
description: Use when you need to call an API or run a tool that wants an API key or token and TOKENLESS_PROXY is set in your environment, or when asked to run a command with secrets from a credential broker vault. Explains how to see which services you can reach, how to hand a tool a key through placeholders, how to fill environment variables with `tokenless exec NAME=cb://<service>/<field>`, and what the proxy's 403, 407 and 429 answers mean.
---

# Working behind the credential broker

You reach third-party APIs through a credential broker: an HTTPS proxy
that adds the real credential to requests your session is allowed to make.
**You never see, and never need, the secret itself.** Nobody can read a
stored secret back, not even an admin, so don't go looking for one.

You are behind the broker when `TOKENLESS_PROXY` is set. Then
`HTTPS_PROXY` points at a local session port and the broker's CA is
already trusted (`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`,
`REQUESTS_CA_BUNDLE`, ...). Leave these variables alone. Unsetting or
overriding them only makes your requests fail.

## 1. See what you can reach

```sh
tokenless session info          # readable summary
tokenless session info --json   # for scripts
```

For each service it lists the hosts, the allowed methods and paths, and the
placeholders it accepts:

```text
GitHub — Work GitHub
  hosts:   api.github.com, uploads.github.com
  allowed: GET,HEAD /*
  cb://Work GitHub/token
    send __GITHUB_TOKEN__ in the header and the proxy puts the real value there (exported as GITHUB_TOKEN)
```

Check this before you call a service and before you tell the user that
something is impossible.

## 2. Make authenticated requests

Usually you do nothing. Send the request to the real HTTPS URL without
credentials, and the proxy adds them:

```sh
curl https://api.github.com/user
```

When a tool will not start without a key, give it the **placeholder**.
Variables listed as "exported as" are already set to it, so `gh`, SDKs and
similar tools just work. For any other variable, set it to the placeholder
yourself:

```sh
OPENAI_API_KEY=__OPENAI_API_KEY__ python summarize.py
```

The proxy replaces the placeholder only where the service says it looks
(headers, query, path or body) and only on hosts in your session. Outside
the proxy the placeholder is worthless, so it is fine to print or log it.

Rules of thumb:

- Use `https://`. Credentials are never added to plain `http://` requests.
- Don't paste a real-looking key you found elsewhere. Use the placeholder
  from `session info`.
- Node's built-in `fetch` ignores `HTTPS_PROXY` unless `NODE_USE_ENV_PROXY=1`
  (Node 24+); `tokenless run` sets it. Other runtimes with their own
  network stack may also need their proxy settings pointed at
  `$HTTPS_PROXY`.

## 3. Fill environment variables by reference

People start scripts and agents with `tokenless exec`. It mints a
session from an access bundle, starts the command behind it, and fills
variables by reference:

```sh
tokenless exec --bundle deploy \
  GITHUB_TOKEN=cb://github/token \
  REGION=eu-west-1 \
  -- ./release.sh
```

- `cb://<service>/<field>` becomes that field's placeholder, never the
  secret. `<service>` is the service (credential), rule or template name;
  the field can be left out when the service has a single placeholder.
- Other values pass through unchanged, as with `env NAME=value`.
- `--env-file .env.broker` reads the same `NAME=value` lines from a file.
  It holds references, not secrets, so it can be committed:

  ```sh
  # .env.broker
  GITHUB_TOKEN=cb://github/token
  OPENAI_API_KEY=cb://openai/token
  ```

- A reference that names nothing stops the run before the command starts,
  and the error lists the references the session does resolve.
- The command never inherits `TOKENLESS_API_KEY` or
  `TOKENLESS_SESSION_TOKEN` from the shell that started it.

`exec` and `run` are the same command. `exec` needs an API key allowed to
mint sessions, so you normally can't run it from inside a session yourself.
In that case, set the variables to the placeholders as in section 2.

## 4. When the proxy says no

Answers from the proxy itself carry the header `x-broker-error: 1` and a
plain-text reason:

| Status | Meaning | What to do |
|---|---|---|
| 403 `no rule in this session allows <METHOD> <path> on <host>` | The host is brokered, but not for this method or path | Don't retry another way. Tell the user which access is missing (method, path, host) so they can widen the rule or the bundle |
| 403 `no rule in this session covers <host>` | The host isn't in your session and unmatched hosts are blocked | Ask the user to add the service to the bundle |
| 403 `<host> resolves to <ip>, which is ...` | Egress to that address range is blocked | Ask an admin; don't work around it |
| 407 `proxy session rejected: ...` | The session expired or was revoked | Tell the user; a new session comes from restarting the command with `tokenless run`/`exec` |
| 429 `session request limit of <n> reached` | The session has used all the requests it was minted with | Stop and tell the user; retrying won't help |
| 503 with `retry-after` | The node hasn't caught up with a new session yet | Retry after the given delay |
| 502 | The upstream service failed or couldn't be reached | Retrying later may help |

A 401 or 403 **without** `x-broker-error` comes from the service itself:
the credential reached it and was refused (for example an expired token or
missing scopes). Report that the stored credential needs attention; you
can't fix it yourself.

Never try to bypass the broker: no direct connections, no unsetting the
proxy, no hunting for keys in files. If you need access you don't have, say
exactly what you need and stop.
