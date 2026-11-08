<!--
SPDX-FileCopyrightText: 2026 tokenless contributors
SPDX-License-Identifier: MIT OR Apache-2.0
-->

# Embed it in your platform

A platform that runs code it does not trust (sandboxes, CI runners, agent
hosts) can run the tokenless data plane inside its own process instead of
next to it. Each workload gets a proxy connection that is a plain byte
stream. It never holds a session token or a credential, and every
request it makes with one is checked, injected and audited as usual.

The crates are not on crates.io yet. Depend on them from the repository,
pinned to a commit:

```toml
[dependencies]
tokenless-control = { git = "https://github.com/gotempsh/tokenless", rev = "<commit>" }
tokenless-dataplane = { git = "https://github.com/gotempsh/tokenless", rev = "<commit>" }
```

`examples/embedded-host` is a complete program that does everything on
this page and checks each step. Run it with `cargo run` in that directory.

## Start the data plane

`DataPlane::start_embedded` runs the proxy without fetching anything. You
hand it each signed snapshot through the returned installer, which
verifies it exactly as a standalone proxy does: signature, node id,
version, lease. Audit batches go to an `AuditShipper` you provide.

```rust
let registered = control.nodes.register_embedded(&host, "embedded", &seal_public_key).await?;
let (dataplane, installer) = DataPlane::start_embedded(
    DataPlaneConfig::default(),
    NodeKeys {
        node_id: registered.node.id,
        seal_secret,
        snapshot_key: registered.snapshot_verify_key,
    },
    Arc::new(MyShipper { /* sends batches to ingest_audit */ }),
)
.await?;
```

A node registered this way holds only the credentials of the sessions
minted for it, so a snapshot carries nothing a workload on this host
could not use anyway. Install a new snapshot after each mint, renewal and
revocation, and before the lease runs out: until a snapshot is installed,
and once its lease lapses, every request is refused.

## Bind each workload

Mint the workload's sessions for this node and this workload, then bind
them:

```rust
let minted = control.sessions.mint(&host, &vault.id, MintSession {
    rule_ids: vec![rule.id],
    node_id: Some(node.id),
    binding: Some(SessionBinding { id: "sbx-42".into(), generation: 1 }),
    not_after: Some(grant_ends_at),
    ttl_secs: Some(900),
    ..
}).await?;
let version = installer.install(&control.nodes.build_snapshot(&node).await?)?;
let binding = dataplane.bind(BindingSpec {
    binding_id: "sbx-42".into(),
    generation: 1,
    sessions: vec![minted.token],
    max_connections: 8,
})?;
binding.ready(version, Duration::from_secs(5)).await?;
tokio::spawn(async move { binding.serve(workload_connection).await });
```

- Minting for a node takes node management (an admin, or a service
  principal not bound to a vault), because it decides which node receives
  the credentials. Being able to mint in the vault isn't enough, and the
  node must exist and not be revoked.
- A bound session works only through its binding, never as
  `HTTPS_PROXY` credentials. A workload restarted under the same id gets
  a new generation, which stops its old sessions.
- `serve` takes any byte stream: a TCP or Unix socket, a container relay,
  vsock. Call it once per connection the workload opens.
- `binding.revoke()` cuts everything the workload has open and refuses
  new connections.

## Deadlines

Give a binding one session per group of services that end at the same
time. When one session ends, the others keep working. Two sessions of a
binding may not cover the same host. `bind` refuses them when the
snapshot in force already has their rules; otherwise `ready` fails with
`overlapping_sessions` once the snapshot that has them arrives.

`not_after` is an absolute deadline: it caps the session's lifetime, and
once it has passed no session is minted with it. Pass the same
`not_after` on every renewal and a renewal can never extend access past
it.

A service's secret can carry its own expiry (`not_after` when you create
the service or replace its secret, or **Expires** in the console). After
it, the proxy stops sending that secret and answers `503` until it is
replaced.

## Know when it can carry traffic

Read the data plane's state instead of its logs:

- `dataplane.status()` gives the snapshot version, the lease and, for
  each binding, its open connections, each session's expiry and the last
  upstream failure (unreachable, the credential rejected with a `401`, or
  the credential expired).
- Anything that stops traffic has a typed reason: provisioning, stale
  policy, not configured, expired, revoked, binding revoked, invalid
  session, overlapping sessions.
- `dataplane.events()` is a `watch` of the latest status, updated on each
  change, so you never poll.
- `binding.ready(version, timeout)` resolves once that snapshot is in
  force and every session of the binding can be used.

Nothing in the status holds a token or a secret.

## Stop it

```rust
let report = dataplane.shutdown(Duration::from_secs(30)).await;
```

New connections are refused at once. Open tunnels and MCP gateway
streams get the drain time to finish, idle connections close, and
revocations still cut traffic. At
the deadline whatever is still open is cut, the audit queue gets one last
try to ship, and the report says how many connections were cut and how
many audit events never shipped. `dataplane.abort()` stops at once
without draining.

## What the audit log guarantees

An event counts as recorded once your shipper returns `Ok` for its batch.
Until then it is only in memory, so a crash loses up to
`audit_capacity` events (4096 by default) plus the batch being shipped.
When the queue is full, the proxy refuses to inject rather than inject
without a record. A shipper that keeps failing therefore stops
injection; it never lets the loss grow.

## Check your integration

`tokenless-conformance` has a suite for an embedded data plane. Run it
against your own control services and stores:

```rust
#[tokio::test(flavor = "multi_thread")]
async fn my_platform_passes_the_dataplane_suite() {
    let control = my_control_services(ControlConfig { lease_secs: 3, ..Default::default() }).await;
    let host = Caller::service(Principal::service("my-platform", Role::Admin, None));
    tokenless_conformance::dataplane::dataplane_suite(control, &host).await.unwrap();
}
```

It creates a vault and registers an embedded node of its own, deletes the
vault and revokes the node at the end, pass or fail, and checks that:

- a workload reaches only its own sessions' services, whatever
  `Proxy-Authorization` it sends;
- a session minted for an earlier start of a workload doesn't bind to a
  later one;
- two sessions covering one host aren't bound together;
- revoking a session cuts its open connection, and an idle connection
  closes when its session expires (it keeps installing fresh policy, so
  the lease running out never passes these checks);
- traffic is refused once the lease runs out;
- no token or secret shows up in the status, errors, debug output, the
  proxy's answers or the audit log, including the record of a request it
  injected into. That request's host doesn't resolve, so nothing reaches
  a real service.

It takes a few seconds more than the lease, which is why the lease must be
short (10 seconds at most).
