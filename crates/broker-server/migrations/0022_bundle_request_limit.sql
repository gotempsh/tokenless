-- SPDX-FileCopyrightText: 2026 tokenless contributors
-- SPDX-License-Identifier: MIT OR Apache-2.0

-- The most requests each session minted from a bundle may make; NULL for
-- no limit. Whoever mints a session may ask for fewer, never more.
ALTER TABLE access_bundles ADD COLUMN request_limit INTEGER;
