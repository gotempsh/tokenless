-- SPDX-FileCopyrightText: 2026 tokenless contributors
-- SPDX-License-Identifier: MIT OR Apache-2.0

-- A service's page lists its log: the requests that used its credential and
-- what was done to it. credential_ref is the service an event is about: the
-- one it targets (created, secret replaced, deleted), else the one its
-- credential_id detail names (a brokered request, a rule over it). Computed,
-- not stored, like session_ref (0010).
ALTER TABLE audit_events ADD COLUMN credential_ref TEXT GENERATED ALWAYS AS (
    CASE
        WHEN substr(target, 1, 11) = 'credential:' THEN substr(target, 12)
        ELSE json_extract(detail, '$.credential_id')
    END
) VIRTUAL;
CREATE INDEX audit_events_credential_at ON audit_events (credential_ref, at);
