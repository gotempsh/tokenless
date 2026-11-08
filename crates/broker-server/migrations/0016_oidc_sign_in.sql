-- SPDX-FileCopyrightText: 2026 tokenless contributors
-- SPDX-License-Identifier: MIT OR Apache-2.0

-- Single sign-on with OpenID Connect providers.

-- The provider account a person signs in as; NULL for a password account.
ALTER TABLE users ADD COLUMN sso_provider_id TEXT;
ALTER TABLE users ADD COLUMN sso_subject TEXT;
CREATE UNIQUE INDEX users_sso ON users (sso_provider_id, sso_subject)
    WHERE sso_provider_id IS NOT NULL;

CREATE TABLE oidc_providers (
    id                 TEXT PRIMARY KEY,
    slug               TEXT NOT NULL UNIQUE,
    name               TEXT NOT NULL,
    issuer             TEXT NOT NULL,
    client_id          TEXT NOT NULL,
    -- Encrypted with the instance's data key; NULL for a public client.
    client_secret_enc  BLOB,
    redirect_uri       TEXT NOT NULL,
    scopes             TEXT NOT NULL,
    groups_claim       TEXT NOT NULL,
    username_claim     TEXT NOT NULL,
    role_mappings      TEXT NOT NULL,
    enabled            INTEGER NOT NULL,
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL
);
