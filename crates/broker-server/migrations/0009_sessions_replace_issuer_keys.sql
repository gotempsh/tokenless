-- SPDX-FileCopyrightText: 2026 tokenless contributors
-- SPDX-License-Identifier: MIT OR Apache-2.0

-- Agents get a session token, not an API key: the session_issuer role is
-- gone, and so are the keys that had it.
DELETE FROM api_keys WHERE role = 'session_issuer';

-- The default longest session went from 1 hour to 7 days. An instance that
-- already exists keeps the cap it had until an admin changes it.
UPDATE settings
SET value = json_set(value, '$.max_session_ttl_secs', 3600)
WHERE key = 'instance'
  AND json_extract(value, '$.max_session_ttl_secs') IS NULL;

INSERT INTO settings (key, value)
SELECT 'instance', '{"unmatched_host_policy":"passthrough","max_session_ttl_secs":3600}'
WHERE NOT EXISTS (SELECT 1 FROM settings WHERE key = 'instance')
  AND EXISTS (SELECT 1 FROM vaults);
