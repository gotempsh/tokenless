<!--
SPDX-FileCopyrightText: 2026 tokenless contributors
SPDX-License-Identifier: MIT OR Apache-2.0
-->

# ADR 0003: An HTTP gateway for MCP clients

- **Status:** Accepted and implemented.
- **Date:** 2026-11-06

## Context

The data plane is a CONNECT proxy. A program reaches a service through
`HTTPS_PROXY` and trusts the broker's interception CA, and the proxy adds
the credential inside the tunnel. That fits agents and scripts the broker
starts (`run`, `exec`), where the launcher sets those variables.

MCP clients are configured differently. A remote MCP server is a URL plus
headers in the client's configuration (`claude mcp add --transport http
<name> <url> --header ...`). The client often runs outside any process
the broker starts, and some clients ignore `HTTPS_PROXY` or keep their own
trust store. Without a URL to give them, MCP servers in a bundle are only
usable from agents started with `run`.

## Decision

Each node also serves an **MCP gateway**: a plain-HTTP reverse proxy,
on loopback by default (`node run --mcp-listen 127.0.0.1:3129`).

- **Addressing.** `/mcp/<host[:port]>/<path>` forwards to
  `https://<host[:port]>/<path>`. The upstream is named in the URL rather
  than by service name, so the node needs nothing new in its snapshot: it
  matches rules on host, method and path exactly as for a tunnel. The CLI
  and console build the URL from the session's discovery data and the
  template's `mcp_path` (where the server answers, e.g. `/mcp`).
- **Authentication.** `Authorization: Bearer <session token>`. The token
  is verified against the snapshot's session keys, and the session's
  expiry, revocation and request limit apply. The token is removed before
  forwarding, whatever header the rule injects, so it never reaches the
  upstream.
- **Reach.** Only hosts covered by a rule of the session. Anything else is
  refused with 403 and audited (`proxy.gateway_denied`); the gateway is
  never a general forward path.
- **Forwarding.** After the checks, a request goes through the same
  handler as an intercepted tunnel: credential injection, placeholders,
  the MCP tool allowlist, the `proxy.inject`/`proxy.response` audit pair,
  and streamed responses (SSE included). The client's connection maps to
  one upstream connection, so parallel streams map to parallel
  connections, as with tunnels.
- **Upstream challenges.** `WWW-Authenticate` is removed from upstream
  responses. The client authenticated to the gateway; an upstream OAuth
  challenge would send it on a flow that bypasses the broker.
- **Tokens.** Sessions minted for MCP clients use `"longest": true`, the
  instance's session lifetime cap (Settings, up to 7 days), because the
  client keeps the token in its configuration and cannot renew it. They
  carry the label `client=mcp`. `tokenless mcp` and the bundle's
  Connect tab mint one and print the client configuration.

## Consequences

- The client stores a session token, not a credential. It is
  scoped to the bundle, expires, and is revoked on the Sessions page, by
  `session revoke`, or by deleting the bundle.
- The client-to-node leg is plain HTTP. On loopback that matches the
  CONNECT listener, which also receives the token in clear. Binding the
  gateway off loopback logs a warning; serving it over TLS is future work.
- A token outlives the default 1-hour cap only if an admin raises
  the cap. That is deliberate: the lifetime of a stored token is the
  instance's decision, not the client's.
- Only the streamable HTTP transport works. The older SSE transport
  hands the client an endpoint URL that drops the `/mcp/<host>` prefix.
- Per-service tokens (one session per MCP server) and a session-port
  variant that adds the token for the client are possible later without
  changing the gateway.
