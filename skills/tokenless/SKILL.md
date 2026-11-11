---
# SPDX-FileCopyrightText: 2026 tokenless contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
name: tokenless
description: Use when you need to call an API or run a tool that wants an API key or token and TOKENLESS_PROXY is set in your environment, when a tool served through the tokenless MCP gateway is refused, or when asked to run a command with secrets from a tokenless vault. Also use when TOKENLESS_PROXY is not set and the user pastes an API key or token, asks you to put one in a .env file, a config file or a shell profile, or a tool fails for want of one; then offer to keep the key in a tokenless vault instead and set it up with them, starting from `tokenless status`, with the key handed over in a file or the console so you never see it, or when asked to connect this machine to a team's tokenless server. Explains how to see which services you can reach, what to give a tool that insists on a key, how placeholders and `tokenless exec NAME=cb://<service>/<field>` work when a service has them, what the proxy's 401, 403, 407 and 429 answers mean, and how to move a key into a vault.
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
or print it. The person hands it to tokenless directly, and you only run
the commands around it.

**Start with `tokenless status --json`** (install it first if
`command -v tokenless` finds nothing). It checks the control plane, the
sign-in, the services, their access bundle, the proxy and this skill, and
`next` is the one command to run. Run it again after each step until
`ready` is true. When `next` is `null`, the check that is not `ok` says
what the person has to do.

```sh
curl -fsSL https://raw.githubusercontent.com/gotempsh/tokenless/main/site/install.sh | sh
tokenless status --json
```

The steps it leads through:

1. **A control plane.** One serves a whole team, so first find out
   whether there is one: `TOKENLESS_URL` is set, `status` finds one
   answering, or the person says their team runs tokenless on a server.
   Then don't start another; connect to it as in "On a team's server"
   below. Otherwise the person starts one in a terminal of their own and
   keeps it running: it prints the admin password once, which you must
   not see. Its data directory holds the root key, so keep it out of any
   repository. Then they sign in, also in their own terminal, since it
   asks for the password.

   ```sh
   tokenless serve --data-dir ~/.tokenless
   tokenless login
   ```

2. **The key.** Find the template for the service or the variable the
   tool reads:

   ```sh
   tokenless service templates OPENAI_API_KEY --json
   ```

   Then let the person hand the key over in one of two ways. In both,
   the key goes from them to tokenless and never through you.

   - **A file they fill in.** Run this in the background: it creates a
     file only they can read, waits until they save the key in it, then
     stores the key and deletes the file (if storing fails, the file stays
     and running the same command again reads it). `--open` opens the file in their
     text editor. Tell them the path it prints, and never read the file
     yourself.

     ```sh
     tokenless service add openai --vault personal --bundle my-agent --secret-file --open
     ```

   - **The console.** This prints the console page that adds the service,
     with the vault and bundle chosen, and waits until they save it there.
     `--open` opens it in their browser.

     ```sh
     tokenless service add openai --vault personal --bundle my-agent --web --open
     ```

   Either ends with the service's vault and the bundle it joined, as JSON
   with `--json`.
   Then they delete any plaintext copy (the line in `.env`, the `export`
   in the profile); a tool that insists on the variable gets a dummy value
   (`OPENAI_API_KEY=tokenless`), as in section 2.

3. **A proxy**, once per machine. Its identity file holds the proxy's
   private keys, and both commands default to `./node.json`, the project
   you are in, so always pass a `--state` outside it. `node run` keeps
   running: in a terminal of theirs, or in the background if you can keep
   it there.

   ```sh
   tokenless proxy add --name laptop --state ~/.tokenless/node.json
   tokenless node run --state ~/.tokenless/node.json
   ```

4. **Use it.** Signed in, you can run a command behind the bundle
   yourself, without seeing the key:

   ```sh
   OPENAI_API_KEY=tokenless tokenless run --vault personal --bundle my-agent -- python summarize.py
   ```

   For everything you do to go through it, they restart you behind it:
   `tokenless run --vault personal --bundle my-agent -- claude` (or the
   command that starts you). Then `TOKENLESS_PROXY` is set and the
   sections above apply.

### On a team's server

When the control plane runs on another machine, the vaults, services and
people are there. This machine only signs in to it and runs a proxy of
its own.

- **Point at it.** The person adds
  `export TOKENLESS_URL=https://tokenless.example.com` (their server's
  name) to their shell profile, so every command uses it without
  `--server`. Use the `https://` name the console is on, not an IP or port
  8080: signing in only works over HTTPS. When `status` finds nothing
  answering there, tell them the address it tried and stop; that server
  isn't yours to start.
- **Sign in as themselves**, in their own terminal:
  `tokenless login --username <their username>`. Without `--username` it
  signs in as `admin`. An account that only uses single sign-on has no
  password for `login`: they add services in the console, and start you
  with a session token from the bundle's page
  (`TOKENLESS_SESSION_TOKEN`, section 3).
- **Services** may already be there, added once for the team. When
  `status` reports services and an access bundle, skip step 2. When the
  one you need is missing, they add it (step 2) to a vault they can
  write, or ask an admin.
- **A proxy on every machine**, step 3, even with a shared server:
  requests leave through this machine's own proxy. `proxy add` is for
  admins. Anyone else gets "only an admin can see proxies" from `status`
  and asks an admin for a join token (**Proxies → Add a proxy** in the
  console). They run it in their own terminal: it works once, but on any
  machine, for an hour. Port 8443 on the server's name is where proxies
  connect.

  ```sh
  tokenless node join --control-url https://tokenless.example.com:8443 \
    --token '<the join token>' --name <this machine> --state ~/.tokenless/node.json
  tokenless node run --state ~/.tokenless/node.json
  ```

  On a shared server `status` reports the proxy connected when any
  machine's is. This machine has its own when `~/.tokenless/node.json`
  exists and `node run` is running; `tokenless run` says so when no proxy
  answers here.

A command that has no terminal to ask in says so and what to do instead,
and every other refusal names what is missing (`run tokenless login`, no
proxy answering, an unknown template), so follow what it says.

Never try to bypass the broker: no direct connections, no unsetting the
proxy, no hunting for keys in files. If you need access you don't have, say
exactly what you need and stop.
