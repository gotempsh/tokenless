-- SPDX-FileCopyrightText: 2026 tokenless contributors
-- SPDX-License-Identifier: MIT OR Apache-2.0

-- Least privilege: people hold an instance role (admin or member) and a
-- role in each vault they belong to. Existing accounts keep their access:
-- everyone becomes a member of every vault with the role they held, and
-- editors and viewers become instance members. What is still to come gets
-- less: a pending admin invitation, or a group mapped to admin, makes an
-- instance admin who oversees vaults and joins one to change it, and a
-- terminal sign-in from before only starts sessions.

CREATE TABLE vault_members (
    vault_id  TEXT NOT NULL,
    user_id   TEXT NOT NULL,
    -- admin, editor, viewer or runner.
    role      TEXT NOT NULL,
    -- The audit actor who added the person or last set their role;
    -- `sso:<provider slug>` when their groups gave it.
    added_by  TEXT NOT NULL,
    added_at  TEXT NOT NULL,
    PRIMARY KEY (vault_id, user_id)
);
CREATE INDEX vault_members_user ON vault_members (user_id);

INSERT INTO vault_members (vault_id, user_id, role, added_by, added_at)
    SELECT v.id, u.id, u.role,
        CASE WHEN u.sso_provider_id IS NULL THEN 'system'
            ELSE coalesce(
                (SELECT 'sso:' || p.slug FROM oidc_providers p WHERE p.id = u.sso_provider_id),
                'system')
        END,
        v.created_at
    FROM vaults v CROSS JOIN users u
    WHERE u.role IN ('admin', 'editor', 'viewer');
UPDATE users SET role = 'member' WHERE role IN ('editor', 'viewer');

-- The vaults an invitation gives roles in, as JSON
-- `[{"vault_id": ..., "role": ...}]`. A pending editor or viewer
-- invitation keeps offering that role in every vault.
ALTER TABLE invites ADD COLUMN vaults TEXT NOT NULL DEFAULT '[]';
UPDATE invites SET
    vaults = (SELECT json_group_array(json_object('vault_id', v.id, 'role', invites.role))
              FROM vaults v),
    role = 'member'
WHERE role IN ('editor', 'viewer');

-- A group mapped to editor or viewer now maps to member, with that role in
-- every vault.
UPDATE oidc_providers SET role_mappings = (
    SELECT json_group_array(
        CASE WHEN json_extract(m.value, '$.role') IN ('editor', 'viewer') THEN
            json_object(
                'group', json_extract(m.value, '$.group'),
                'role', 'member',
                'vaults', json((SELECT json_group_array(json_object(
                    'vault_id', v.id, 'role', json_extract(m.value, '$.role')))
                    FROM vaults v)))
        ELSE json(m.value) END)
    FROM json_each(oidc_providers.role_mappings) m);

-- What a sign-in may do: `full`, or `launch` (only start sessions). A
-- `tokenless login` from before is what `tokenless run` uses, so it keeps
-- only that; managing from the terminal takes `tokenless login --manage`.
ALTER TABLE ui_sessions ADD COLUMN scope TEXT NOT NULL DEFAULT 'full';
UPDATE ui_sessions SET scope = 'launch' WHERE user_agent LIKE 'tokenless/%';
