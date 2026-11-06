-- SPDX-FileCopyrightText: 2026 credential-broker contributors
-- SPDX-License-Identifier: MIT OR Apache-2.0

-- An authenticator is optional: password-only accounts have no TOTP
-- secret. SQLite cannot drop NOT NULL in place, so the table is rebuilt.

CREATE TABLE users_new (
    id               TEXT PRIMARY KEY,
    username         TEXT NOT NULL UNIQUE,
    password_hash    TEXT NOT NULL,
    totp_secret_enc  BLOB,
    totp_last_step   INTEGER,
    role             TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    disabled_at      TEXT
);
INSERT INTO users_new (id, username, password_hash, totp_secret_enc, totp_last_step, role, created_at, disabled_at)
    SELECT id, username, password_hash, totp_secret_enc, totp_last_step, role, created_at, disabled_at FROM users;
DROP TABLE users;
ALTER TABLE users_new RENAME TO users;
