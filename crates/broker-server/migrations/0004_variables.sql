-- SPDX-FileCopyrightText: 2026 credential-broker contributors
-- SPDX-License-Identifier: MIT OR Apache-2.0

-- Variables: named secrets referenced as {{KEY}} from credential fields and
-- custom headers. Values are AES-256-GCM ciphertext, never plaintext.
CREATE TABLE variables (
    id          TEXT PRIMARY KEY,
    key         TEXT NOT NULL UNIQUE,
    value       BLOB NOT NULL,
    created_by  TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    updated_by  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

-- Custom headers are configuration (JSON); variable_refs lists the keys the
-- secret fields and custom headers reference, so usage can be found and a
-- referenced variable cannot be deleted.
ALTER TABLE credentials ADD COLUMN custom_headers TEXT NOT NULL DEFAULT '[]';
ALTER TABLE credentials ADD COLUMN variable_refs TEXT NOT NULL DEFAULT '[]';
