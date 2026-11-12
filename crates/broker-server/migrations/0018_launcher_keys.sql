-- SPDX-FileCopyrightText: 2026 tokenless contributors
-- SPDX-License-Identifier: MIT OR Apache-2.0

-- A launcher key is an API key that can only start sessions from one access
-- bundle, within limits it carries (JSON: bundle_id, max_ttl_secs and the
-- optional request_limit, node_id and labels). NULL for an ordinary key.
ALTER TABLE api_keys ADD COLUMN launch TEXT;
ALTER TABLE api_keys ADD COLUMN launch_bundle_id TEXT;
CREATE INDEX api_keys_launch_bundle ON api_keys (vault_id, launch_bundle_id, created_at);
