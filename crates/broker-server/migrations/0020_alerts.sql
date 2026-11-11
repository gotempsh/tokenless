-- SPDX-FileCopyrightText: 2026 tokenless contributors
-- SPDX-License-Identifier: MIT OR Apache-2.0

-- Alerts raised from audit signals: a session cut off, a tripwire hit, a
-- session refused often or used through a second proxy.
CREATE TABLE alerts (
    id               TEXT PRIMARY KEY,
    kind             TEXT NOT NULL,
    -- The same signal on the same session raises one alert.
    dedup_key        TEXT NOT NULL UNIQUE,
    summary          TEXT NOT NULL,
    vault_id         TEXT,
    session_id       TEXT,
    node_id          TEXT,
    -- JSON object of flat strings.
    detail           TEXT NOT NULL,
    raised_at        TEXT NOT NULL,
    acknowledged_at  TEXT,
    acknowledged_by  TEXT
);
CREATE INDEX alerts_raised ON alerts (raised_at);
CREATE INDEX alerts_open ON alerts (acknowledged_at, raised_at);
CREATE INDEX alerts_session ON alerts (session_id, raised_at);
CREATE INDEX alerts_kind ON alerts (kind, raised_at);
