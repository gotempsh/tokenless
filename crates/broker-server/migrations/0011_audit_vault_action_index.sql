-- SPDX-FileCopyrightText: 2026 tokenless contributors
-- SPDX-License-Identifier: MIT OR Apache-2.0

-- The vault list shows when each vault last brokered a request. That is the
-- newest proxy.inject event of the vault, which this index finds by reading
-- one entry however long the vault's history grows.
CREATE INDEX audit_events_vault_action_at ON audit_events (vault_id, action, at);
