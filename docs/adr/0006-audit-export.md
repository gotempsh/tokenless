<!--
SPDX-FileCopyrightText: 2026 tokenless contributors
SPDX-License-Identifier: MIT OR Apache-2.0
-->

# ADR 0006: Sending the audit log to webhooks

- **Status:** Accepted and implemented.
- **Date:** 2026-11-09

## Context

For a credential broker the audit trail is half the point, and it lived
only in the control plane's database. A security team wants it in its
own system, where the instance's admins can't rewrite it, alerts can be
built on it, and it outlives the instance. Every SIEM and log pipeline
accepts an HTTPS POST, so a webhook covers the most receivers with the
least code; syslog and OpenTelemetry can follow on the same delivery.

## Decision

- **The audit log is the outbox.** Each event gets a sequence number,
  `seq`, assigned in commit order: SQLite writes take the write lock at
  `BEGIN`, so `MAX(seq) + 1` inside the transaction can't be overtaken
  by a transaction that commits earlier. It is a column, not the rowid,
  which `VACUUM` may renumber. Migration 0017 numbers existing events in
  the order they were written. Nothing new is written at event time, so
  recording an event costs what it did.
- **Each destination keeps a cursor**, the last `seq` it has been sent or
  passed over by its filter. The sender reads the next events after it,
  posts them, and moves the cursor with a compare-and-set
  (`WHERE cursor = from`), so two senders can't both move it. A failure
  moves nothing: the same batch is retried after 1 second, doubling to 5
  minutes. A receiver that was down gets everything it missed, in order.
- **At least once.** The batch ID, `{destination}.{first}-{last}`, is the
  same on every retry, so a receiver can drop a repeat. A failure stores
  the batch's last sequence number with the destination, and the retry
  stops there even when newer events were written meanwhile or the server
  restarted. Changing the destination's settings forgets it: other
  settings can select other events from the same range, which must not
  go out under an ID the receiver may already have. Exactly once
  would need the receiver's cooperation and buys nothing a SIEM's
  deduplication doesn't.
- **Standard Webhooks signing.** A `whsec_` secret per destination,
  HMAC-SHA256 over `{id}.{timestamp}.{body}`, in the `webhook-id`,
  `webhook-timestamp` and `webhook-signature` headers, so receivers use
  the specification's libraries instead of ours. The secret is shown
  once, when it is made. An optional auth header carries the receiver's
  own token. Both are encrypted with the instance key (the destination's
  ID in the associated data) and included in key rotation.
- **One sender loop in the control plane** polls every second and runs at
  most one pass per destination at a time, each at most 20 batches of at
  most 500 events and 1 MiB. Delivery writes no audit events (an event
  per batch would feed itself); the destination's status, last error and
  failure count show what happened.
- **Managing destinations** is the instance-level `audit_export_manage`
  action, admin-only and behind step-up, and every change, skip, test and
  new secret is audited. At most 10 destinations. Audit details and logs
  name a receiver by its scheme and host only: some receivers carry an
  ingest token in the URL's path, and the audit log is readable by viewers
  and exported itself.
- **Receiver traffic** trusts what credential validation trusts, follows
  no redirects, times out after 10 seconds and reads at most 64 KiB of a
  reply. As for identity providers, the agents' egress policy doesn't
  apply: an admin names the receiver, and a SIEM is usually on the
  internal network. Only `https`, or `http` to loopback.

## Consequences

- A receiver that is down long enough holds its destination's cursor
  back indefinitely; nothing is dropped. **Skip to now** gives the
  backlog up on purpose, and is audited. Audit log retention, when it
  comes, has to respect the slowest destination's cursor or say what it
  skips.
- A secret's rotation takes effect at once: there is no window in which
  both secrets sign. A receiver accepting several `v1` signatures could
  allow one later.
- The backoff is in memory, so a restart retries at once.
- Several control planes on one database (planned with Postgres) need a
  commit-order cursor that SQLite's single writer gives for free:
  `(transaction ID, seq)` read below the oldest running transaction's
  horizon. The compare-and-set already keeps the cursor right when two
  senders race, though both may send the batch.
