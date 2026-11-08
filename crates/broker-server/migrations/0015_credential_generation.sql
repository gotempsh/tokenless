-- SPDX-FileCopyrightText: 2026 tokenless contributors
-- SPDX-License-Identifier: MIT OR Apache-2.0

-- Each rotation bumps the secret's generation, and a rotation may name the
-- generation it replaces, so two refreshers cannot overwrite each other.
-- rotation_id is the caller's id for the rotation that set the secret, so
-- a retried rotation is not applied twice. Existing secrets are the first.
ALTER TABLE credentials ADD COLUMN secret_generation INTEGER NOT NULL DEFAULT 1;
ALTER TABLE credentials ADD COLUMN rotation_id TEXT;
