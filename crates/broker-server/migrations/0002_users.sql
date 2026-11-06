-- SPDX-FileCopyrightText: 2026 credential-broker contributors
-- SPDX-License-Identifier: MIT OR Apache-2.0

-- User management: disabling accounts and single-use invitations.

ALTER TABLE users ADD COLUMN disabled_at TEXT;

CREATE TABLE invites (
    id           TEXT PRIMARY KEY,
    token_hash   TEXT NOT NULL UNIQUE,
    role         TEXT NOT NULL,
    created_by   TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    accepted_at  TEXT,
    accepted_by  TEXT,
    revoked_at   TEXT
);
CREATE INDEX invites_created_at ON invites (created_at);
CREATE INDEX ui_sessions_user ON ui_sessions (user_id);
