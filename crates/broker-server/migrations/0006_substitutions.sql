-- SPDX-FileCopyrightText: 2026 credential-broker contributors
-- SPDX-License-Identifier: MIT OR Apache-2.0

-- Substitutions are configuration (JSON): a placeholder, the secret field
-- that replaces it and where the proxy looks. Values stay in `secret`.
ALTER TABLE credentials ADD COLUMN substitutions TEXT NOT NULL DEFAULT '[]';
