-- SPDX-FileCopyrightText: 2026 tokenless contributors
-- SPDX-License-Identifier: MIT OR Apache-2.0

-- Sign-ins people can list and revoke: a public id, when each was last
-- used (for idle expiry) and the client that signed in.
ALTER TABLE ui_sessions ADD COLUMN id TEXT;
ALTER TABLE ui_sessions ADD COLUMN last_used_at TEXT;
ALTER TABLE ui_sessions ADD COLUMN user_agent TEXT;
-- Sign-ins from before this get a random UUID-shaped id.
UPDATE ui_sessions SET
    id = lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-4'
        || substr(lower(hex(randomblob(2))), 2) || '-a'
        || substr(lower(hex(randomblob(2))), 2) || '-' || lower(hex(randomblob(6))),
    last_used_at = created_at;
CREATE UNIQUE INDEX ui_sessions_id ON ui_sessions (id);
-- A person's sign-ins list newest first.
DROP INDEX ui_sessions_user;
CREATE INDEX ui_sessions_user ON ui_sessions (user_id, created_at);
