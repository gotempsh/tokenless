-- SPDX-FileCopyrightText: 2026 tokenless contributors
-- SPDX-License-Identifier: MIT OR Apache-2.0

-- A secret that expires upstream (an installation token, say) carries its
-- deadline, so the proxy stops injecting it then. Set with the secret and
-- replaced with it; existing credentials have none.
ALTER TABLE credentials ADD COLUMN not_after TEXT;
