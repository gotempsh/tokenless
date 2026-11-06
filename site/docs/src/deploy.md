<!--
SPDX-FileCopyrightText: 2026 tokenless contributors
SPDX-License-Identifier: MIT OR Apache-2.0
-->

# Deploy to production

A production setup is one control plane (`tokenless serve`) and one or
more proxies (`tokenless node run`), usually one on each machine that runs
agents.

## Control plane

`serve` has two listeners:

| Listener | Flag | Default | Who connects |
|---|---|---|---|
| Console and management API | `--api-listen` | `127.0.0.1:8080` | People, API keys, `tokenless run` |
| Node API | `--node-listen` | `127.0.0.1:8443` | Proxies, with mutual TLS |

### HTTPS for the console

The session cookie is `Secure`, so browsers only sign in over HTTPS (or
on `localhost`). Either serve HTTPS directly:

```sh
tokenless serve --data-dir /var/lib/tokenless \
  --api-listen 0.0.0.0:443 \
  --api-tls-cert /etc/tokenless/fullchain.pem \
  --api-tls-key /etc/tokenless/privkey.pem
```

The certificate files are checked every minute and reloaded when they
change, so a renewal needs no restart. Or keep `--api-listen` on loopback
and put a TLS-terminating reverse proxy in front of it.

### The node API

Proxies authenticate to the node API with client certificates issued
when they enrol, so it must be reached directly (TCP), never through a
TLS-terminating proxy. Listen on an address your proxies can reach,
ideally a private network, and name it in the node API certificate:

```sh
tokenless serve ... \
  --node-listen 10.0.0.5:8443 \
  --node-api-name tokenless.internal --node-api-name 10.0.0.5
```

Proxies then join with `--control-url https://tokenless.internal:8443`.

### Validation requests to private services

**Test** on a service sends the template's validation request from the
control plane. For a self-hosted service with a private CA, pass
`--validation-ca ca.pem` (repeatable). If the service is on a private
address, also allow that range under
[Settings → Egress to private addresses](settings.md#private-addresses).

## Proxies

On each machine that runs agents:

```sh
tokenless node join --control-url https://tokenless.internal:8443 \
  --token 'cbj1....' --name build-1 --state /var/lib/tokenless/node.json
tokenless node run --state /var/lib/tokenless/node.json
```

Get the join token from **Proxies → Add a proxy**. It works once and
expires in an hour. `node.json` (mode 0600) is the proxy's identity: keep
it, or the machine has to join again.

Keep the proxy listener (`--listen`, default `127.0.0.1:3128`) and the
MCP gateway (`--mcp-listen`, default `127.0.0.1:3129`) on loopback or a
private network. The proxy refuses traffic once its policy lease lapses
(`serve --lease-secs`, 60 seconds by default), so a proxy cut off from
the control plane fails closed.

For upstreams with a private CA, pass `--upstream-ca ca.pem` (repeatable).
`--no-public-roots` trusts only those.

## systemd

```ini
# /etc/systemd/system/tokenless.service
[Unit]
Description=tokenless control plane
After=network-online.target
Wants=network-online.target

[Service]
User=tokenless
ExecStart=/usr/local/bin/tokenless serve --data-dir /var/lib/tokenless \
  --api-listen 127.0.0.1:8080 --node-listen 10.0.0.5:8443 \
  --node-api-name tokenless.internal
StateDirectory=tokenless
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

A proxy's unit is the same with
`ExecStart=/usr/local/bin/tokenless node run --state /var/lib/tokenless/node.json`.

## Docker Compose

```yaml
services:
  tokenless:
    image: ghcr.io/gotempsh/tokenless:0.1
    restart: unless-stopped
    command:
      - serve
      - --data-dir=/data
      - --api-listen=0.0.0.0:8080
      - --node-listen=0.0.0.0:8443
      - --node-api-name=tokenless.internal
    volumes:
      - tokenless-data:/data
    ports:
      - "127.0.0.1:8080:8080"   # behind your TLS reverse proxy
      - "8443:8443"             # proxies connect here
volumes:
  tokenless-data:
```

## Backups

`data/master.key` encrypts everything sensitive in `data/broker.db`. Back
up **both**, and store them **separately**: either one alone is useless,
which is the point. The database runs in WAL mode; take a consistent copy
while it runs with:

```sh
sqlite3 /var/lib/tokenless/broker.db ".backup '/backups/broker.db'"
```

Losing `master.key` means losing every stored secret. You can't recover
them, by design.

## Upgrades

Replace the binary (or the image tag) and restart. Database migrations run
on start. The console is part of the binary, so it upgrades with it.
Upgrade the control plane before the proxies.

## Logs and metrics

Logs are JSON lines on stdout. Set `RUST_LOG` to change the level, for
example `RUST_LOG=debug`. Proxies expose Prometheus metrics with
`node run --metrics-listen 127.0.0.1:9090`. Every change, injection and
refusal is also in the **Audit log**.
