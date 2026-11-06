<!--
SPDX-FileCopyrightText: 2026 tokenless contributors
SPDX-License-Identifier: MIT OR Apache-2.0
-->

# Connect an MCP client

MCP clients that take a server URL, such as Claude Code and Cursor, use
the proxy's **MCP gateway** instead of `HTTPS_PROXY`. `node run` serves it
on `127.0.0.1:3129` (`--mcp-listen` to move it, `--no-mcp-gateway` to
turn it off).

Each MCP server in a bundle gets a URL of the form
`http://127.0.0.1:3129/mcp/<host>/<path>`, and the client sends a session
token as its bearer token:

```sh
tokenless mcp --bundle code-review                # a `claude mcp add` command per server
tokenless mcp --bundle code-review --format json  # an mcpServers block for other clients
```

For example:

```sh
claude mcp add --transport http github \
  http://127.0.0.1:3129/mcp/api.githubcopilot.com/mcp/ \
  --header 'Authorization: Bearer v4.public...'
```

`mcp` mints one session for the bundle, lasting as long as
**Settings → Session lifetime** allows (`--ttl` for less), because the
client keeps the token in its configuration. The bundle's **Connect** tab
in the console does the same.

The client stores the session token, never the service's credential.
The gateway checks the token, removes it, and forwards the request exactly
as an intercepted HTTPS request: same rule match, same credential, same
MCP tool allowlist, same audit records. Ending the session on the
**Sessions** page, or deleting the bundle, cuts the client off.

To limit which tools an agent may call, open the vault's **Rules** tab
and set the rule's tools. Calls to other tools get an MCP error naming the
tool and never reach the server.

Only the streamable HTTP transport is supported.
