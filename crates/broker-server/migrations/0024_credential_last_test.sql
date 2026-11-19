-- SPDX-FileCopyrightText: 2026 tokenless contributors
-- SPDX-License-Identifier: MIT OR Apache-2.0

-- How the last test of a credential's current secret went (JSON: outcome,
-- host, request line, status, when and by whom; never a response body).
-- NULL until it is tested, and again once the secret is replaced.
ALTER TABLE credentials ADD COLUMN last_test TEXT;
