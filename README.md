<!--
SPDX-FileCopyrightText: 2026 credential-broker contributors
SPDX-License-Identifier: MIT OR Apache-2.0
-->

# credential-broker

A credential broker for AI agents. Agents send HTTPS traffic through a
local forward proxy using a short-lived session token. For hosts that
have a rule, the proxy terminates TLS and injects the real credential.
The agent never sees it. Every other host is tunnelled untouched (or
denied, depending on policy).

- **Write-only secrets.** Credentials are encrypted at rest with
  AES-256-GCM. Nobody, admins included, can read one back.
- **Scoped, short-lived sessions.** Each session is a PASETO v4.public
  token bound to a vault, a subset of rules, a TTL (15 min by default,
  1 h maximum), an optional request limit, and audit labels. Revocation
  reaches the proxy within seconds.
- **Fails closed.** The proxy runs from an Ed25519-signed, leased policy
  snapshot. When the lease lapses it refuses traffic, and it refuses to
  inject when it cannot record an audit event.
- **No pivoting into private networks.** By default the proxy will not
  tunnel to loopback, private, link-local or metadata addresses. Allow
  specific ranges in **Settings**.

The design, the threat model and the trade-offs are in
[docs/adr/0001-architecture.md](docs/adr/0001-architecture.md).

## Quickstart

Requirements: Rust 1.85+ and [bun](https://bun.sh) for the UI.

```sh
# Build the binary and the console
cargo build --release
(cd broker-ui && bun install && bun run build)

# 1. Start the control plane. On first start it prints a single-use setup token.
./target/release/credential-broker serve --data-dir ./data --ui-dir broker-ui/dist
```

Open <http://127.0.0.1:8080/> and complete these steps:

1. Create the admin. Enter the setup token and choose a password.
   Enrolling an authenticator app (TOTP) is optional but recommended.
2. **Vaults → Create vault**.
3. **Credentials → Add a credential**. Pick a template (for example
   GitHub) and paste the token. The form is write-only.
   Use **Test** next to it to send the template's validation request
   (status code only, to the credential's own host).
4. **Rules → Add a rule** for that credential. Leave the scope empty to
   use the template's maximum, or narrow it.
5. **Nodes → Create join token**.
6. Optionally, **People → Invite someone** as `viewer`, `editor` or
   `admin`, and send them the one-time link.

Enrol and run a data plane next to the agent:

```sh
./target/release/credential-broker node join \
  --control-url https://127.0.0.1:8443 --token 'cbj1....' --state ./node.json
./target/release/credential-broker node run --state ./node.json   # listens on 127.0.0.1:3128
```

Back in the console, open **Sessions → Mint session**, select the rule,
and copy the token (it is shown once). Then point the agent at the proxy
and trust the interception CA:

```sh
curl -s http://127.0.0.1:8080/api/v1/ca/interception.pem -o broker-ca.pem
HTTPS_PROXY="http://<session-token>@127.0.0.1:3128" \
  curl --cacert broker-ca.pem https://api.github.com/user
```

The request reaches GitHub with `Authorization: Bearer <stored token>`.
Any `Authorization` header the client sent is replaced. Requests without
a valid session get `407`.

### Automation

Create a vault-scoped API key under **API keys** (the `session_issuer`
role can only mint sessions), then:

```sh
curl -s -X POST http://127.0.0.1:8080/api/v1/vaults/<vault-id>/sessions \
  -H "Authorization: Bearer cbk_..." -H 'content-type: application/json' \
  -d '{"rule_ids":["<rule-id>"],"ttl_secs":900,"labels":{"agent":"build-bot"}}'
```

### Deployment notes

- The management API serves plain HTTP on loopback by default. For
  anything beyond `localhost`, serve HTTPS directly or put a
  TLS-terminating reverse proxy in front, because the session cookie is
  `Secure`:

  ```sh
  ./target/release/credential-broker serve --data-dir ./data --ui-dir broker-ui/dist \
    --api-listen 0.0.0.0:443 --api-tls-cert /etc/broker/fullchain.pem --api-tls-key /etc/broker/privkey.pem
  ```

  The certificate files are checked every minute and reloaded when they
  change, so a renewal does not need a restart.
- Validation requests to a self-hosted service with a private CA need
  `--validation-ca ca.pem` (repeatable). If the service is on a private
  address, also allow that range under **Settings → Egress to private addresses**.
- Use `--node-listen` and `--node-api-name` to expose the node API on a
  private address.
- Keep the proxy listener (`node run --listen`) on loopback or a private
  network.
- `data/master.key` (mode 0600) encrypts everything sensitive in
  `data/broker.db`. Back up both, separately.
- Logs are JSON lines on stdout. Set `RUST_LOG` (for example
  `RUST_LOG=debug`) to change the level.
- Data plane metrics are exposed in Prometheus format with
  `node run --metrics-listen 127.0.0.1:9090`.

## Development

```sh
cargo build
cargo clippy --all-targets -- -D warnings
cargo test                      # unit tests, conformance suites, end-to-end test
(cd broker-ui && bun run typecheck && bun run build)
(cd broker-ui && bun run dev)   # UI dev server, proxies /api to 127.0.0.1:8080
```

| Path | Contents |
|---|---|
| `crates/broker-core` | Rules, scopes, templates, injection, sessions, snapshots (no I/O) |
| `crates/broker-auth` | Passwords, TOTP, tokens, CSRF, cookies |
| `crates/broker-control` | Services and the store / authorizer traits |
| `crates/broker-conformance` | Suites every trait implementation must pass |
| `crates/broker-dataplane` | The forward proxy and node client |
| `crates/broker-server` | HTTP APIs, SQLite store and the `credential-broker` binary |
| `broker-ui` | Management console |
| `tools/catalog` | Source of the built-in service catalogue and its logos |

### Adding a built-in service

The built-in templates and their logos are generated from
`tools/catalog/services.toml`; never edit `crates/broker-core/templates/`,
`builtin_catalog.rs` or `broker-ui/src/assets/logos/` by hand.

```sh
tools/catalog/fetch-sources.sh       # once: pinned logo sets into tools/catalog/.cache
# add a [[service]] entry to tools/catalog/services.toml (keys documented at its top)
python3 tools/catalog/generate.py    # templates, builtin_catalog.rs, logos and NOTICE.md
python3 tools/catalog/generate.py --check   # what CI should run: fails if anything is stale
```

A logo is found automatically by name in svgl, Lobe Icons, Simple Icons and
gilbarbara/logos, in that order; pin one with `icon = "simple:slug"` or opt
out with `icon = "none"`. Each logo's source and licence is recorded in the
generated `broker-ui/src/assets/logos/NOTICE.md`. Templates are seeded once per
id and version, so bump `version` whenever you change what an existing
service injects or allows.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT), at your option.
