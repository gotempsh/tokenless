-- SPDX-FileCopyrightText: 2026 tokenless contributors
-- SPDX-License-Identifier: MIT OR Apache-2.0

-- Decoy credentials planted on agents' machines; every proxy is sent them
-- and cuts off a session that sends one. The decoy opens nothing, so it is
-- stored as is.
CREATE TABLE tripwires (
    id               TEXT PRIMARY KEY,
    vault_id         TEXT NOT NULL,
    name             TEXT NOT NULL,
    kind             TEXT NOT NULL,
    value            TEXT NOT NULL,
    prefix           TEXT NOT NULL,
    created_by       TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    last_tripped_at  TEXT,
    UNIQUE (vault_id, name)
);
CREATE INDEX tripwires_vault ON tripwires (vault_id, created_at);
CREATE INDEX tripwires_created ON tripwires (created_at);
