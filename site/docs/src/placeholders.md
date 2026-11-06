<!--
SPDX-FileCopyrightText: 2026 tokenless contributors
SPDX-License-Identifier: MIT OR Apache-2.0
-->

# Placeholders and variables

## Placeholders

Most APIs take the key in a header, and the proxy simply sets that
header. Some want it in the query string, the path or the body, and some
tools refuse to start without a key at all. For those, give the service a
**placeholder** on its page: the agent sends `__GITHUB_TOKEN__`, and the
proxy swaps in the real value on its way to that service's hosts, and
nowhere else. Outside the proxy the placeholder is worthless, so it can be
logged or committed.

Each placeholder says where the proxy looks for it:

- **Headers** the agent sends.
- **Query** string.
- **Path**: the value is percent-encoded, so it stays inside one segment.
- **Body**: JSON is escaped and forms are encoded. Compressed bodies,
  bodies over 4 MiB and bodies of unknown length are forwarded untouched,
  and the audit log says so.

A placeholder can name an environment variable, which `run` and
`session start` export, for example `GITHUB_TOKEN=__GITHUB_TOKEN__`. Tools
like `gh` and most SDKs then work without any setup.

## Filling environment variables by reference

`tokenless exec` is `run` with variables filled by reference:

```sh
tokenless exec --bundle deploy \
  GITHUB_TOKEN=cb://github/token REGION=eu-west-1 -- ./release.sh
tokenless exec --bundle deploy --env-file .env.broker -- ./release.sh
```

- `cb://<service>/<field>` becomes that field's placeholder, never the
  secret. `<service>` is the service, rule or template name; `/<field>`
  can be left out when the service has one placeholder.
- Other values are passed through as written.
- An env file holds the same `NAME=value` lines. It contains references,
  not secrets, so it can be committed. Later files and arguments override
  earlier ones; nothing may override the proxy or trust variables.
- A reference that resolves to nothing stops the run before the command
  starts, and lists the references the session does resolve.

## Variables

**Variables** (in the sidebar) are secrets you store once and reference
from any service as `{{NAME}}`, in a credential field or a custom header.
Replacing a variable updates every service that uses it. Like every
secret, a variable can be replaced but never read back.
