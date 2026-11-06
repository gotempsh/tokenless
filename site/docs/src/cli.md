<!--
SPDX-FileCopyrightText: 2026 tokenless contributors
SPDX-License-Identifier: MIT OR Apache-2.0
-->

# Command line

Every command takes `--help` for its full list of options.

| Command | What it does |
|---|---|
| `tokenless serve` | Run the control plane: console, management API and node API. See [Deploy](deploy.md). |
| `tokenless node join` | Enrol this machine as a proxy with a one-time join token. |
| `tokenless node run` | Run the proxy and the MCP gateway. |
| `tokenless run` | Run a command behind a session from an access bundle. See [Run an agent](agents.md). |
| `tokenless exec` | `run`, with environment variables filled by reference. See [Placeholders](placeholders.md). |
| `tokenless session start` | Open a session port for agents you start yourself. |
| `tokenless session create` | Mint a session and print its token. |
| `tokenless session info` | Show what a session can reach and the placeholders it accepts. |
| `tokenless session revoke` | End a session. |
| `tokenless mcp` | Print MCP client configuration for a bundle's MCP servers. See [MCP](mcp.md). |
| `tokenless skill` | Print or install the agent skill. |

## `serve`

| Option | Default | |
|---|---|---|
| `--data-dir` | `./data` | Master key and SQLite database |
| `--database-url` | `sqlite://<data-dir>/broker.db` | |
| `--api-listen` | `127.0.0.1:8080` | Console and management API |
| `--api-tls-cert`, `--api-tls-key` | | Serve the API over HTTPS; reloaded on change |
| `--node-listen` | `127.0.0.1:8443` | Node API (mutual TLS) |
| `--node-api-name` | `localhost`, `127.0.0.1` | Names in the node API certificate (repeatable) |
| `--validation-ca` | | Extra CAs for credential tests (repeatable) |
| `--lease-secs` | `60` | How long a proxy may run without reaching the control plane |
| `--ui-dir` | | Serve the console from a directory instead of the built-in one |

## `node run`

| Option | Default | |
|---|---|---|
| `--state` | `./node.json` | The identity written by `node join` |
| `--listen` | `127.0.0.1:3128` | Proxy listener |
| `--mcp-listen` | `127.0.0.1:3129` | MCP gateway |
| `--no-mcp-gateway` | | Don't start the MCP gateway |
| `--metrics-listen` | | Prometheus metrics |
| `--upstream-ca` | | Extra CAs for upstream TLS (repeatable) |
| `--no-public-roots` | | Trust only `--upstream-ca` |

## Client commands

`run`, `exec`, `session` and `mcp` share these:

| Flag | Environment | Default |
|---|---|---|
| `--server` | `TOKENLESS_URL` | `http://127.0.0.1:8080` |
| `--api-key-file` | `TOKENLESS_API_KEY` (the key itself) | |
| `--vault` | `TOKENLESS_VAULT` | the API key's vault |
| `--bundle` | `TOKENLESS_BUNDLE` | |
| `--proxy` | `TOKENLESS_PROXY_ADDRESS` | `127.0.0.1:3128` |

Inside `run` or behind `session start`, `TOKENLESS_PROXY` is set to the
session port and `HTTPS_PROXY` points at it.
