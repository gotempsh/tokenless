<!--
SPDX-FileCopyrightText: 2026 tokenless contributors
SPDX-License-Identifier: MIT OR Apache-2.0
-->

# tokenless

tokenless gives AI agents access to APIs without giving them the keys.

You store a credential once, for example a GitHub token. An agent then
sends its HTTPS traffic through a tokenless proxy with a short-lived
session. For the hosts its session allows, the proxy adds the real
credential to the request on the way out. The agent can call the API,
but it never holds the key, so it can't leak it, paste it into a log or
keep using it after the job.

```text
agent ──HTTPS_PROXY──▶ proxy ──adds Authorization──▶ api.github.com
                         ▲
                         │ signed policy, sealed credentials
                    control plane (console, API, vaults)
```

## What you get

- **Secrets are write-only.** They are encrypted at rest with AES-256-GCM.
  Nobody can read one back, admins included. They only ever travel,
  sealed, to enrolled proxies.
- **Sessions are scoped and short-lived.** A session is bound to one vault,
  a set of rules, a lifetime (15 minutes by default) and optionally a
  request limit. Revoking one reaches the proxy within seconds.
- **Agents start with one command.** `tokenless run --bundle code-review -- claude`
  starts the agent behind a local proxy address with the right CA trusted
  and no token in its environment.
- **The proxy fails closed.** It runs from a signed, leased policy
  snapshot. When the lease lapses it refuses traffic, and it never injects
  a credential it can't audit.
- **No pivoting into your network.** By default the proxy won't connect to
  loopback, private, link-local or cloud metadata addresses.
- **Everything is audited**: every change, every injected request and
  every refusal.

## How it fits together

- **`tokenless serve`** runs the control plane: the web console, the
  management API, and the node API that proxies connect to. It stores
  everything in SQLite.
- **`tokenless node run`** runs a proxy, normally on the machine your
  agents run on.
- **`tokenless run`**, **`tokenless mcp`** and the other client commands
  start agents and MCP clients behind a proxy.

All three are the same binary.

Start with [Install](install.md) and the [Quickstart](quickstart.md).
