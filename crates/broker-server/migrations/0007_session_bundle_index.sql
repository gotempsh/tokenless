-- SPDX-FileCopyrightText: 2026 credential-broker contributors
-- SPDX-License-Identifier: MIT OR Apache-2.0

-- A bundle's page lists the sessions minted from it, newest first.
CREATE INDEX proxy_sessions_bundle ON proxy_sessions (bundle_id, created_at);
