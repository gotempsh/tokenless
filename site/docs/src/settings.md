<!--
SPDX-FileCopyrightText: 2026 tokenless contributors
SPDX-License-Identifier: MIT OR Apache-2.0
-->

# Settings

Instance-wide settings, under **Settings** in the console (admins only).
Changes reach every proxy at its next policy refresh.

## Other hosts

Agents send all their HTTPS traffic through the proxy. This decides what
happens to hosts that aren't one of their services:

- **Allow** (the default): the connection is passed through untouched.
  The proxy doesn't decrypt it or add any credential.
- **Block**: agents reach only the services in their session, plus the
  [always reachable](#always-reachable) hosts.

## Session lifetime

The longest session anyone may create, from 15 minutes up to 90 days;
7 days by default (an instance created before this default keeps the
1 hour it had). Sessions you hand an agent last at most this long; ones
`tokenless run --bundle` mints are renewed while the agent runs, so they
can stay short. A short lifetime limits how long a leaked session token
is useful.

## Always reachable

Hosts every session may reach even when other hosts are blocked, such as
package registries and documentation, one per line:
`registry.npmjs.org`, `*.pythonhosted.org` (one label), with `:port` for
ports other than 443. They are passed through untouched and never given a
credential.

## Private addresses

By default the proxy won't connect to loopback, private, link-local or
cloud metadata addresses, so an agent can't use it to reach your internal
network. Allow specific ranges here when a service you broker lives on
one. This applies to other hosts and to credential tests; a session's own
services are always reachable.
