-- SPDX-FileCopyrightText: 2026 credential-broker contributors
-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Timestamps are fixed-width RFC 3339 UTC strings (microseconds, Z suffix)
-- so lexical order is chronological order. Portable to PostgreSQL by
-- switching the TEXT timestamps to TIMESTAMPTZ and BLOB to BYTEA.

CREATE TABLE vaults (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    scope       TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE TABLE credentials (
    id                TEXT PRIMARY KEY,
    vault_id          TEXT NOT NULL,
    name              TEXT NOT NULL,
    template_id       TEXT NOT NULL,
    template_version  INTEGER NOT NULL,
    host_override     TEXT NOT NULL,
    field_names       TEXT NOT NULL,
    created_by        TEXT NOT NULL,
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL,
    -- AES-256-GCM ciphertext produced by the control plane; never plaintext.
    secret            BLOB NOT NULL,
    UNIQUE (vault_id, name)
);
CREATE INDEX credentials_vault ON credentials (vault_id, created_at);

CREATE TABLE templates (
    id           TEXT NOT NULL,
    version      INTEGER NOT NULL,
    yaml         TEXT NOT NULL,
    source       TEXT NOT NULL,
    status       TEXT NOT NULL,
    imported_by  TEXT,
    approved_by  TEXT,
    created_at   TEXT NOT NULL,
    PRIMARY KEY (id, version)
);

CREATE TABLE rules (
    id             TEXT PRIMARY KEY,
    vault_id       TEXT NOT NULL,
    credential_id  TEXT NOT NULL,
    name           TEXT NOT NULL,
    allow          TEXT NOT NULL,
    enabled        INTEGER NOT NULL,
    created_by     TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL,
    UNIQUE (vault_id, name)
);
CREATE INDEX rules_credential ON rules (credential_id);
CREATE INDEX rules_enabled ON rules (enabled);

CREATE TABLE proxy_sessions (
    id             TEXT PRIMARY KEY,
    vault_id       TEXT NOT NULL,
    rule_ids       TEXT NOT NULL,
    labels         TEXT NOT NULL,
    request_limit  INTEGER,
    created_by     TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    expires_at     TEXT NOT NULL,
    revoked_at     TEXT
);
CREATE INDEX proxy_sessions_vault ON proxy_sessions (vault_id, created_at);
CREATE INDEX proxy_sessions_expiry ON proxy_sessions (expires_at);

CREATE TABLE settings (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);

CREATE TABLE audit_events (
    id        TEXT PRIMARY KEY,
    at        TEXT NOT NULL,
    actor     TEXT NOT NULL,
    action    TEXT NOT NULL,
    outcome   TEXT NOT NULL,
    vault_id  TEXT,
    target    TEXT,
    detail    TEXT NOT NULL
);
CREATE INDEX audit_events_at ON audit_events (at);
CREATE INDEX audit_events_vault_at ON audit_events (vault_id, at);

CREATE TABLE users (
    id               TEXT PRIMARY KEY,
    username         TEXT NOT NULL UNIQUE,
    password_hash    TEXT NOT NULL,
    totp_secret_enc  BLOB NOT NULL,
    totp_last_step   INTEGER,
    role             TEXT NOT NULL,
    created_at       TEXT NOT NULL
);

CREATE TABLE ui_sessions (
    token_hash  TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    step_up_at  TEXT
);
CREATE INDEX ui_sessions_expiry ON ui_sessions (expires_at);

CREATE TABLE setup_tokens (
    singleton   INTEGER PRIMARY KEY CHECK (singleton = 1),
    token_hash  TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE TABLE api_keys (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    prefix        TEXT NOT NULL UNIQUE,
    secret_hash   TEXT NOT NULL,
    vault_id      TEXT NOT NULL,
    role          TEXT NOT NULL,
    created_by    TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    expires_at    TEXT NOT NULL,
    revoked_at    TEXT,
    last_used_at  TEXT
);

CREATE TABLE join_tokens (
    id           TEXT PRIMARY KEY,
    secret_hash  TEXT NOT NULL,
    created_by   TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    consumed_at  TEXT
);

CREATE TABLE nodes (
    id               TEXT PRIMARY KEY,
    name             TEXT NOT NULL,
    seal_public_key  TEXT NOT NULL,
    cert_serial      TEXT NOT NULL,
    cert_not_after   TEXT NOT NULL,
    enrolled_at      TEXT NOT NULL,
    last_seen_at     TEXT,
    revoked_at       TEXT
);

CREATE TABLE key_material (
    name   TEXT PRIMARY KEY,
    -- Encrypted with the master key.
    value  BLOB NOT NULL
);

CREATE TABLE counters (
    name   TEXT PRIMARY KEY,
    value  INTEGER NOT NULL
);
INSERT INTO counters (name, value) VALUES ('snapshot_version', 0);
