-- SPDX-FileCopyrightText: 2026 tokenless contributors
-- SPDX-License-Identifier: MIT OR Apache-2.0

-- Audit export: webhook receivers audit events are sent to.

-- Each audit event's sequence number, in the order events were committed.
-- Every write takes the write lock up front (BEGIN IMMEDIATE) and numbers
-- its events from the highest so far, so a number is never assigned out
-- of commit order and no gap is filled later. A sender's cursor is one of
-- these numbers. It is a column, not the rowid, because VACUUM may
-- renumber the rowids of a table without an INTEGER PRIMARY KEY.
ALTER TABLE audit_events ADD COLUMN seq INTEGER;
UPDATE audit_events SET seq = rowid;
CREATE UNIQUE INDEX audit_events_seq ON audit_events (seq);

CREATE TABLE audit_destinations (
    id                     TEXT PRIMARY KEY,
    name                   TEXT NOT NULL UNIQUE,
    url                    TEXT NOT NULL,
    format                 TEXT NOT NULL,
    auth_header_name       TEXT,
    -- Encrypted with the instance's data key.
    auth_header_value_enc  BLOB,
    signing_secret_enc     BLOB NOT NULL,
    filter                 TEXT NOT NULL,
    paused                 INTEGER NOT NULL,
    created_at             TEXT NOT NULL,
    updated_at             TEXT NOT NULL,
    -- Delivery state, written only by the sender (and a skip).
    cursor                 INTEGER NOT NULL,
    last_success_at        TEXT,
    last_attempt_at        TEXT,
    failing_since          TEXT,
    last_error             TEXT,
    consecutive_failures   INTEGER NOT NULL DEFAULT 0,
    -- The end of the batch that failed, so its retry is the same batch.
    retry_until            INTEGER
);
