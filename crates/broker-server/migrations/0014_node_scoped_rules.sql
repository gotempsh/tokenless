-- SPDX-FileCopyrightText: 2026 tokenless contributors
-- SPDX-License-Identifier: MIT OR Apache-2.0

-- A session minted for one node records it, and a node can be sent only the
-- rules of live sessions minted for it instead of every enabled rule, so it
-- never holds sealed credentials for workloads it does not run. Existing
-- nodes keep receiving every rule; existing sessions name no node.
ALTER TABLE nodes ADD COLUMN scoped_rules INTEGER NOT NULL DEFAULT 0;
ALTER TABLE proxy_sessions ADD COLUMN node_id TEXT;
CREATE INDEX proxy_sessions_node ON proxy_sessions (node_id, expires_at) WHERE node_id IS NOT NULL;
