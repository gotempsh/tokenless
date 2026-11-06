-- SPDX-FileCopyrightText: 2026 credential-broker contributors
-- SPDX-License-Identifier: MIT OR Apache-2.0

-- Access bundles: named lists of a vault's rules that sessions are minted
-- from (`run --bundle code-review`). Membership is a join table so that
-- deleting a rule can drop it from every bundle in one statement.
CREATE TABLE access_bundles (
    id           TEXT PRIMARY KEY,
    vault_id     TEXT NOT NULL,
    name         TEXT NOT NULL,
    description  TEXT NOT NULL,
    created_by   TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL,
    UNIQUE (vault_id, name)
);

CREATE TABLE access_bundle_rules (
    bundle_id  TEXT NOT NULL,
    rule_id    TEXT NOT NULL,
    PRIMARY KEY (bundle_id, rule_id)
);
CREATE INDEX access_bundle_rules_rule ON access_bundle_rules (rule_id);

-- The bundle a session was minted from, as it was named at the time.
ALTER TABLE proxy_sessions ADD COLUMN bundle_id TEXT;
ALTER TABLE proxy_sessions ADD COLUMN bundle_name TEXT;
