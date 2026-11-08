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
them. A rule for a Git host can name the repositories a workload may
clone or push (`CreateRule { git: Some(GitScope::new(repos, push)?), .. }`;
see [Git over HTTPS](agents.md#git-over-https)):

```rust
let minted = control.sessions.mint(&host, &vault.id, MintSession {
    rule_ids: vec![rule.id],
    node_id: Some(node.id),
    binding: Some(SessionBinding { id: "sbx-42".into(), generation: 1 }),
    not_after: Some(grant_ends_at),
    strict: true,
    ttl_secs: Some(900),
    ..Default::default()
}).await?;
let version = installer.install(&control.nodes.build_snapshot(&node).await?)?;
let binding = dataplane.bind(BindingSpec {
    binding_id: "sbx-42".into(),
    generation: 1,
    sessions: vec![minted.token],
    version: 1,
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
- `binding.update(BindingUpdate { version, sessions })` replaces its
  sessions: to add or remove a grant, or to renew. The version must be
  higher than the binding's, so a delayed command can't bring back an
  older set (`StaleBindingUpdate`). New connections use the new sessions.
  Open traffic under a rule a new session still grants carries on, so a
  renewal interrupts nothing; traffic under a rule none grants is cut.

## Deadlines

`not_after` is an absolute deadline: it caps the session's lifetime, and
once it has passed no session is minted with it. Pass the same
`not_after` on every renewal and a renewal can never extend access past
it.

Grants that end at different times can share one session, even on the
same host: `rule_not_after` gives each rule its own earlier deadline.
After it the rule is refused (`403`) while the session's other rules
keep working. Pass the same deadlines on every renewal; one that has
passed refuses the mint, so a late renewal can't bring a grant back.

Mint with `strict: true` when you promise access for a set time. Without
it, a deadline stops new requests and open traffic gets a grace period
(an hour), so a tunnel doesn't break at every renewal. With it, open
traffic stops at the deadline itself:

- each request's upload and response are cut at the earliest of the
  session's expiry, their rule's deadline and the credential's
  `not_after`, so one grant ending leaves the others' streams running;
- a tunnel closes when the last grant that covers its host ends, and a
  tunnel to an uncovered host when the session expires;
- deadlines are checked against a clock that setting the system time
  back cannot rewind, and fresh snapshots arriving don't move them.

A node that predates strict sessions or rule deadlines refuses their
tokens rather than enforcing less.

Two sessions of a binding may not cover the same host: give grants on
one host to one session, with their own deadlines. `bind` refuses
overlapping sessions when the snapshot in force already has their rules;
otherwise `ready` fails with `overlapping_sessions` once the snapshot
that has them arrives. A binding holds at most 16 sessions.

A service's secret can carry its own expiry (`not_after` when you create
the service or replace its secret, or **Expires** in the console). After
it, the proxy stops sending that secret and answers `503` until it is
replaced.

## Refresh a secret you mint

When the host mints the secret itself (an installation token, an OAuth
access token), the host owns its refresh: when to refresh (before the
secret's `not_after`, or after the upstream refuses it) and how to mint
the new one. Tokenless stores what you give it and keeps two refreshers
from overwriting each other:

```rust
let refresher = CredentialRefresher::new(); // one per process
let outcome = refresher
    .refresh(&control.policy, &host, &credential.id, credential.secret_generation, |_| async {
        let token = mint_installation_token().await?;
        Ok(FreshSecret { fields: [("token".into(), token.value)].into(), not_after: Some(token.expires_at) })
    })
    .await?;
```

- **Generations.** Every secret has a `secret_generation`, 1 when the
  service is created and one more on each replacement. A refresh names
  the generation it replaces; if another refresh replaced it first, the
  newer secret is kept and yours is discarded (`Superseded`; revoke it
  upstream if you can).
- **One refresh at a time.** Refreshes of one credential in one process
  wait for each other and do not mint again once the secret has moved
  on. Across processes the generation decides.
- **Retries.** Each refresh has a rotation id; retrying a replacement
  whose answer was lost returns the credential as the first attempt left
  it instead of replacing it twice.
- **Failures.** A failed mint stores nothing. The current secret is used
  until its `not_after`; then the proxy answers `503`
  (`credential_expired`) until a refresh succeeds.

Over HTTP the same fence is `PUT /api/v1/credentials/{id}/secret` with
`expected_generation` and `rotation_id`; a stale one is a `409` with code
`stale_generation`.

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

## Know when a revocation is enforced

Revoking returns once the decision is stored; it does not mean every
data plane has stopped forwarding. Wait for that on each data plane
that served the workload:

```rust
control.sessions.revoke(&host, &session_id).await?;
installer.install(&control.nodes.build_snapshot(&node).await?)?;
let report = dataplane.session_cut(session_id, Duration::from_secs(5)).await?;
// or, for a whole workload:
let report = binding.revoke_and_wait(Duration::from_secs(5)).await?;
```

- `session_cut` resolves once a snapshot revoking the session is in
  force here and nothing the session opened (tunnels, MCP gateway
  streams) is still open. `revoke_and_wait` revokes the binding and
  resolves once its last connection has closed. Upstream connections
  close with their tunnels.
- The report gives the snapshot version in force and how many
  connections were closed.
- At the timeout both fail with `NotCut`: how many connections are
  still open, whether the revocation has been installed, and how long
  until the lease ends all traffic anyway, which bounds a data plane you
  can no longer reach. `ControlConfig::lease_secs` sets that bound.
- Neither can undo a request an upstream already accepted.

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
- `session_cut` and `revoke_and_wait` return once nothing is left open;
- in a strict session, a rule's own deadline closes that grant's
  connection while the other grant keeps working;
- updating a binding cuts only the grant it removes, and an update with
  an old version is refused;
- a Git-scoped rule refuses another repository, a push and an extra
  query at discovery;
- the data plane reports every capability it enforces;
- traffic is refused once the lease runs out;
- no token or secret shows up in the status, errors, debug output, the
  proxy's answers or the audit log, including the record of a request it
  injected into. That request's host doesn't resolve, so nothing reaches
  a real service.

It takes a few seconds more than the lease, which is why the lease must be
short (10 seconds at most).

The store suites (`credential_store_suite` and the others) check your own
stores the same way, including that replacing a secret is fenced on its
generation and that a retried rotation is applied once.

## Compatibility

What you may build on, and what may change under you:

- **Supported:** the `tokenless-control` services (`ControlServices` and
  its `policy`, `sessions`, `nodes`, `audit` and `variables`), the store
  traits in `tokenless_control::store`, `CredentialRefresher`, the
  `tokenless-dataplane` types re-exported at its root (`DataPlane`,
  `Binding`, `BindingSpec`, `BindingUpdate`, `CutReport`, the status
  types and `DataPlaneError`), its `capabilities` module, the
  `tokenless-conformance` suites, and `/api/v1` over HTTP.
- **Internal:** every other module, even where it is `pub` (`proxy`,
  `state`, `tls`, `upstream` and the like), and the snapshot's wire
  format. They change without notice.
- **Releases:** until 1.0, a minor version (0.x) may change a supported
  surface; the release notes say how to move. Pin a commit or a tag
  (`rev = "<commit>"` or `tag = "v0.2.0"`), not a branch, and upgrade the
  control services and the data plane together.

Snapshots and sessions are where versions meet when the control plane
and the proxies are deployed separately:

- **Snapshots** carry a format. A proxy tells the control plane the
  newest format it reads; rules that need a newer one (a secret with an
  expiry, a Git scope) are left out of its snapshot, so it refuses their
  requests rather than enforcing them partly. The control plane logs a
  warning naming the proxy. A snapshot newer than the proxy reads is
  refused whole.
- **Session tokens** a proxy does not fully understand (a strict
  session, rule deadlines) are refused (`407`, or `bind` fails), never
  accepted with the parts it doesn't know dropped.

An embedded data plane is built into your binary, so check what it
enforces before attaching workloads that rely on it:

```rust
use tokenless_dataplane::capabilities::Capability;

dataplane.capabilities().require(&[Capability::StrictExpiry, Capability::RevocationAck])?;
```

`require` fails with `DataPlaneError::Unsupported`, naming each missing
capability. `capabilities()` also reports the snapshot formats it reads.
