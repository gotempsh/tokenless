-- SPDX-FileCopyrightText: 2026 tokenless contributors
-- SPDX-License-Identifier: MIT OR Apache-2.0

-- A service's page lists its log: the requests that used its credential and
-- what was done to it. credential_ref is the service an event is about: the
-- one it targets (created, secret replaced, deleted), else the one its
-- credential_id detail names (a brokered request, a rule over it). rule.create
-- recorded it as `credential` before this release, so older rule creations
-- are read from that key. Computed, not stored, like session_ref (0010), so
-- existing rows are covered as far as they recorded the service: older API
-- answers and rule edits and deletions did not, and stay out of the log.
ALTER TABLE audit_events ADD COLUMN credential_ref TEXT GENERATED ALWAYS AS (
    CASE
        WHEN substr(target, 1, 11) = 'credential:' THEN substr(target, 12)
        WHEN action = 'rule.create' THEN
            coalesce(json_extract(detail, '$.credential_id'), json_extract(detail, '$.credential'))
        ELSE json_extract(detail, '$.credential_id')
    END
) VIRTUAL;
CREATE INDEX audit_events_credential_at ON audit_events (credential_ref, at);
