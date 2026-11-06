<!--
SPDX-FileCopyrightText: 2026 tokenless contributors
SPDX-License-Identifier: MIT OR Apache-2.0
-->

# Set up from the terminal

Everything in the [Quickstart](quickstart.md) can be done without the
console: sign in, add a service and enrol a proxy.

## Sign in

```sh
tokenless login                 # the admin printed by `tokenless serve`
```

It asks for the password, and an authenticator code if the account has
one. The session is kept in the operating system's keychain (macOS
Keychain, Windows Credential Manager, the Linux kernel keyring), never in
a file, and lasts as long as a console session. `--server` signs in to
another control plane; `tokenless logout` ends the session.

On macOS the binary is not notarized, so after installing or upgrading it
the Keychain asks once whether `tokenless` may read its entry. Choose
**Always Allow**.

## Add a service

```sh
tokenless service add github --vault work --bundle code-review
```

It asks for the token without echoing it, or reads it from standard input
when piped (`gh auth token | tokenless service add github ...`). Then it:

1. creates the vault if it doesn't exist,
2. stores the credential, encrypted, write-only from then on,
3. adds a rule that lets agents use it with the template's scope
   (`--read-only` limits it to `GET` and `HEAD`),
4. adds that rule to the bundle, creating the bundle if needed.

Templates with several fields (a client ID and a secret, say) ask for
each one, so run those in a terminal. `--name` names the credential when
the vault already has one for the same service.

## Enrol a proxy

```sh
tokenless proxy add --name laptop     # writes ./node.json
tokenless node run
```

`proxy add` creates a join token and enrols this machine with it in one
step. It reaches the node API on the control plane's host at port 8443;
pass `--control-url` when it listens elsewhere.

## Run an agent

```sh
tokenless run --vault work --bundle code-review -- claude
```

Signed in, `run`, `exec`, `session` and `mcp` mint sessions with your
account, so you don't need an API key on your own machine. Use an API key
for CI and other unattended runs; see
[Automation and API keys](automation.md).

## Sensitive actions

With an authenticator, adding credentials and rules needs a code from the
last five minutes; signing in counts. When the server asks for a newer
one, the commands prompt for it and carry on.

## A lost admin password

On the machine that runs the control plane, against the same data:

```sh
tokenless admin reset-password --data-dir ./tokenless-data
```

It prints a new password once and ends every session of that account.
It works while the server is running. With PostgreSQL, pass
`--database-url` as well.
