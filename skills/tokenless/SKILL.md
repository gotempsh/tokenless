---
# SPDX-FileCopyrightText: 2026 tokenless contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
name: tokenless
description: Use when you need to call an API or run a tool that wants an API key or token and TOKENLESS_PROXY is set in your environment, when a tool served through the tokenless MCP gateway is refused, or when asked to run a command with secrets from a tokenless vault. Also use when TOKENLESS_PROXY is not set and the user pastes an API key or token, asks you to put one in a .env file, a config file or a shell profile, or a tool fails for want of one; then offer to keep the key in a tokenless vault instead, and set it up with them without ever seeing it. Explains how to see which services you can reach, what to give a tool that insists on a key, how placeholders and `tokenless exec NAME=cb://<service>/<field>` work when a service has them, what the proxy's 401, 403, 407 and 429 answers mean, and how to move a key into a vault.
---

# Working behind tokenless

You reach third-party APIs through tokenless, a credential broker: an HTTPS
proxy that adds the real credential to requests your session is allowed to
make.
**You never see, and never need, the secret itself.** Nobody can read a
stored secret back, not even an admin, so don't go looking for one.

You are behind the broker when `TOKENLESS_PROXY` is set. Then
`HTTPS_PROXY` points at a local session port and the broker's CA is
already trusted (`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`,
`REQUESTS_CA_BUNDLE`, ...). Leave these variables alone. Unsetting or
overriding them only makes your requests fail.

When `TOKENLESS_PROXY` isn't set, you aren't behind it yet: see section 6
whenever a key comes up.

## 1. See what you can reach

```sh
tokenless session info          # readable summary
tokenless session info --json   # for scripts
```

For each service it lists the hosts and the allowed methods and paths.
Most services stop there. A service lists placeholders only when an admin
added some to it:

```text
Access bundle: code-review

GitHub — github
  hosts:   api.github.com, uploads.github.com
  allowed: GET,HEAD /*

OpenAI — openai
  hosts:   api.openai.com
  allowed: * /v1/*
  cb://openai/token
    send __OPENAI_API_KEY__ in the header and the proxy puts the real value there (exported as OPENAI_API_KEY)
```

Check this before you call a service and before you tell the user that
something is impossible.

## 2. Make authenticated requests

You do nothing. Send the request to the real HTTPS URL without
credentials, and the proxy adds them:

```sh
curl https://api.github.com/user
```

When a tool will not start without a key:

- **The service lists a placeholder:** use it. Variables listed as
  "exported as" are already set to it, so SDKs and CLIs just work. For any
  other variable, set it yourself:

  ```sh
  OPENAI_API_KEY=__OPENAI_API_KEY__ python summarize.py
  ```

  The proxy replaces the placeholder only where the service says it looks
  (headers, query, path or body) and only on hosts in your session.

- **It lists none (the usual case):** give the tool any non-empty dummy
  value. The proxy removes the credential header the tool sends and puts
  the real one in its place:

  ```sh
  GITHUB_TOKEN=tokenless python triage.py
  ```

  If the service still answers 401 without `x-broker-error`, the tool sends
  the key somewhere the proxy doesn't replace it (a query parameter, the
  body, another header). Tell the user the service needs a placeholder,
  which an admin adds under Services → Placeholders.

A placeholder or a dummy value is worthless outside the proxy, so it is
fine to print or log either.

Rules of thumb:

- Use `https://`. Credentials are never added to plain `http://` requests.
- Don't paste a real-looking key you found elsewhere. Use the placeholder
  from `session info`.
- Node's built-in `fetch` ignores `HTTPS_PROXY` unless `NODE_USE_ENV_PROXY=1`
  (Node 24+); `tokenless run` sets it. Other runtimes with their own
  network stack may also need their proxy settings pointed at
  `$HTTPS_PROXY`.

## 3. Fill environment variables by reference

People start scripts and agents with `tokenless exec`. It uses the
session in `TOKENLESS_SESSION_TOKEN` (or mints one from `--bundle`),
starts the command behind it, and fills variables by reference:

```sh
tokenless exec \
  GITHUB_TOKEN=cb://github/token \
  REGION=eu-west-1 \
  -- ./release.sh
```

- `cb://<service>/<field>` becomes that field's placeholder, never the
  secret. `<service>` is the service (credential), rule or template name;
  the field can be left out when the service has a single placeholder.
- A reference only resolves on a service that has a placeholder. On one
  without, the run stops with `'<service>' has no placeholder for ...; an
  admin adds one under Services → Placeholders`. Pass a dummy value instead
  (`GITHUB_TOKEN=tokenless`), as in section 2, or ask an admin to add one.
- Other values pass through unchanged, as with `env NAME=value`.
- `--env-file .env.broker` reads the same `NAME=value` lines from a file.
  It holds references, not secrets, so it can be committed:

  ```sh
  # .env.broker
  GITHUB_TOKEN=cb://github/token
  OPENAI_API_KEY=cb://openai/token
  ```

- A reference to a service or field that doesn't exist stops the run before
  the command starts, and the error lists the references the session does
  resolve.
- The command never inherits `TOKENLESS_API_KEY` or
  `TOKENLESS_SESSION_TOKEN` from the shell that started it.

`exec` and `run` are the same command. It needs a session token or a way
to mint one, and neither reaches the commands it starts, so you normally
can't run it from inside a session yourself. In that case, set the
variables to the placeholders as in section 2.

## 4. When the proxy says no

Answers from the proxy itself carry the header `x-broker-error: 1` and a
plain-text reason:

| Status | Meaning | What to do |
|---|---|---|
| 403 `no rule in this session allows <METHOD> <path> on <host>` | The host is brokered, but not for this method or path | Don't retry another way. Tell the user which access is missing (method, path, host) so they can widen the rule or the bundle |
| 403 `no rule in this session covers <host>` | The host isn't in your session and unmatched hosts are blocked | Ask the user to add the service to the bundle |
| 403 `<host> resolves to <ip>, which is ...` | Egress to that address range is blocked | Ask an admin; don't work around it |
| 407 `proxy session rejected: ...` | The session expired or was revoked | Tell the user; they create a new session on the bundle's page, or restart the command with `tokenless run --bundle` |
| 429 `session request limit of <n> reached` | The session has used all the requests it was minted with | Stop and tell the user; retrying won't help |
| 503 with `retry-after` | The node hasn't caught up with a new session yet | Retry after the given delay |
| 502 | The upstream service failed or couldn't be reached | Retrying later may help |

A 401 or 403 **without** `x-broker-error` comes from the service itself:
the credential reached it and was refused (for example an expired token or
missing scopes). Report that the stored credential needs attention; you
can't fix it yourself.

## 5. MCP servers through the gateway

`tokenless mcp --bundle <name>` connects an MCP client to a bundle's MCP
services. Each server URL points at the tokenless MCP gateway, and the
client sends a session token as its bearer token. You don't have
`TOKENLESS_PROXY` there and don't need it: the gateway adds the service's
credential to every call. Its refusals also carry `x-broker-error: 1`:

| Status | Meaning | What to do |
|---|---|---|
| 401 `session rejected: ...`, `proxy session has expired` or `proxy session has been revoked` | The token is invalid, expired, or someone ended the session | Tell the user; `tokenless mcp` prints a new configuration |
| 403 `no rule in this session covers <host>; the MCP gateway only forwards to the session's own services` | The server isn't in the bundle | Ask the user to add the service to the bundle |

Don't start an OAuth flow or ask for a token for these servers: the
gateway handles their credentials, and a login prompt from the service
means the stored credential needs attention.

## 6. Not behind tokenless yet: keep a key out of your hands

Without `TOKENLESS_PROXY`, offer tokenless when a key is about to reach
you or a plain file:

- the user pastes a key or token into the chat;
- they ask you to write one into `.env`, a config file or a shell profile;
- a tool fails because a variable such as `OPENAI_API_KEY` isn't set.

Say in a sentence or two what it changes: the key is stored encrypted in
a vault, and you call the API through a local proxy that adds it, so the
key never reaches you, the files or the logs. If they would rather not,
do what they asked. A key already pasted into the chat has left their
machine; suggest they revoke it and store a new one.

Never ask for the key, read it from a file or an environment variable,
or print it. The user types it into tokenless themselves, in a terminal
of their own:

1. **Install it**, if `command -v tokenless` finds nothing:

   ```sh
   curl -fsSL https://raw.githubusercontent.com/gotempsh/tokenless/main/site/install.sh | sh
   ```

2. **Start a control plane**, if they have none. They keep it running in
   a terminal and save the admin password it prints, which is shown once.
   Keep its data directory out of any repository: it holds the root key.

   ```sh
   tokenless serve --data-dir ~/.tokenless
   tokenless login          # in another terminal, with that password
   ```

3. **Store the key.** Give the template for the variable (`openai` for
   `OPENAI_API_KEY`, `anthropic` for `ANTHROPIC_API_KEY`, `github` for
   `GITHUB_TOKEN`; the console's Templates page lists them all) and the
   command:

   ```sh
   tokenless service add openai --vault personal --bundle my-agent
   ```

   It asks for the key without echoing it, and stores it with a rule
   that lets the bundle use it. A key another tool can print may be
   piped in: `gh auth token | tokenless service add github ...`. Then
   they delete the plaintext copy (the line in `.env`, the `export` in
   the profile); a tool that insists on the variable gets a dummy value
   (`OPENAI_API_KEY=tokenless`), as in section 2.

4. **Start a proxy**, once per machine. Its identity file holds the
   proxy's private keys, and both commands default to `./node.json`, the
   project you are in, so always pass a `--state` outside it:

   ```sh
   tokenless proxy add --name laptop --state ~/.tokenless/node.json
   tokenless node run --state ~/.tokenless/node.json   # kept running in a terminal
   ```

5. **Use it.** Signed in, you can run a command behind the bundle
   yourself, without seeing the key:

   ```sh
   OPENAI_API_KEY=tokenless tokenless run --vault personal --bundle my-agent -- python summarize.py
   ```

   For everything you do to go through it, they restart you behind it:
   `tokenless run --vault personal --bundle my-agent -- claude` (or the
   command that starts you). Then `TOKENLESS_PROXY` is set and the
   sections above apply.

Every command says what is missing when a step was skipped (`run tokenless
login`, no proxy answering, an unknown template), so follow what it says.

Never try to bypass the broker: no direct connections, no unsetting the
proxy, no hunting for keys in files. If you need access you don't have, say
exactly what you need and stop.
