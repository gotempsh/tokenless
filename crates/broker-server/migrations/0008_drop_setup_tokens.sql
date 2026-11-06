-- SPDX-FileCopyrightText: 2026 tokenless contributors
-- SPDX-License-Identifier: MIT OR Apache-2.0

-- The first admin is created with a generated password on first start, so
-- there is no setup token to keep.
DROP TABLE IF EXISTS setup_tokens;
