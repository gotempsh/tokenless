-- SPDX-FileCopyrightText: 2026 tokenless contributors
-- SPDX-License-Identifier: MIT OR Apache-2.0

-- A live session's page asks for its audit events every few seconds, so
-- finding them must not read the whole log. session_ref is the session an
-- event is about: the one it targets (minted, relabelled, revoked), else
-- the one that made the request (the proxy's session_id detail). It is
-- computed, not stored, so existing rows are covered and writes are
-- unchanged.
ALTER TABLE audit_events ADD COLUMN session_ref TEXT GENERATED ALWAYS AS (
    CASE
        WHEN substr(target, 1, 8) = 'session:' THEN substr(target, 9)
        ELSE json_extract(detail, '$.session_id')
    END
) VIRTUAL;
CREATE INDEX audit_events_session_at ON audit_events (session_ref, at);
