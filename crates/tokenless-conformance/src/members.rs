// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! What a [`MembershipStore`] must do: make a vault's creator its admin
//! with the vault, keep each person's role per vault, never leave a vault
//! without an admin, give an invitation's vault roles with the account,
//! drop a vault's members with it, and narrow lists to a set of vaults.

use tokenless_control::model::{AuditQuery, PageRequest, VaultGrant, VaultMember, VaultScope};
use tokenless_control::store::{AuditSink, IdentityStore, MembershipStore, PolicyStore};
use tokenless_control::StoreError;
use tokenless_core::audit::{AuditEvent, AuditOutcome};
use tokenless_core::authz::Role;
use tokenless_core::ids::{UserId, VaultId};

use crate::{at, backend, invite, person, vault, ConformanceFailure};

const S: &str = "membership_store";

fn member(vault_id: VaultId, user_id: UserId, role: Role) -> VaultMember {
    VaultMember {
        vault_id,
        user_id,
        username: String::new(),
        role,
        added_by: "user:conformance".into(),
        added_at: at(0),
    }
}

fn event(action: &str, vault_id: VaultId) -> AuditEvent {
    let mut e = AuditEvent::new("user:conformance", action, AuditOutcome::Success)
        .vault(vault_id)
        .target(format!("vault:{vault_id}"));
    e.at = at(0);
    e
}

/// Expects an empty store.
pub async fn membership_store_suite<St>(store: &St) -> Result<(), ConformanceFailure>
where
    St: MembershipStore + PolicyStore + IdentityStore + AuditSink,
{
    let alice = person("alice", Role::Admin, -30);
    let bob = person("bob", Role::Member, -20);
    let carol = person("carol", Role::Member, -10);
    for p in [&alice, &bob, &carol] {
        store
            .insert_user(p.clone(), &[])
            .await
            .map_err(backend(S, "people"))?;
    }

    // The creator is the vault's admin from the moment it exists.
    let ops = vault("members-ops", 0);
    store
        .insert_vault_with_admin(
            ops.clone(),
            member(ops.id, alice.id, Role::Viewer),
            &[event("vault.create", ops.id)],
        )
        .await
        .map_err(backend(S, "create"))?;
    let role = store
        .vault_role(&ops.id, &alice.id)
        .await
        .map_err(backend(S, "create_role"))?;
    ensure!(
        S,
        "create_role",
        role == Some(Role::Admin),
        "creator's role is {role:?}, not admin"
    );
    let membership = store
        .vault_member(&ops.id, &alice.id)
        .await
        .map_err(backend(S, "get_member"))?;
    ensure!(
        S,
        "get_member",
        membership.as_ref().is_some_and(|m| m.role == Role::Admin
            && m.username == alice.username
            && m.added_by == "user:conformance"),
        "the creator's membership reads back as {membership:?}"
    );
    let nobody = store
        .vault_member(&ops.id, &UserId::new())
        .await
        .map_err(backend(S, "get_member_missing"))?;
    ensure!(
        S,
        "get_member_missing",
        nobody.is_none(),
        "a stranger reads as {nobody:?}"
    );
    let created = store
        .query(&AuditQuery {
            action_prefix: Some("vault.create".into()),
            page: PageRequest::default(),
            ..AuditQuery::default()
        })
        .await
        .map_err(backend(S, "create_audit"))?;
    ensure!(
        S,
        "create_audit",
        created.total == 1,
        "vault.create recorded {} times",
        created.total
    );
    let dup = store
        .insert_vault_with_admin(
            vault("members-ops", 1),
            member(VaultId::new(), alice.id, Role::Admin),
            &[],
        )
        .await;
    ensure!(
        S,
        "create_duplicate",
        matches!(dup, Err(StoreError::Conflict { .. })),
        "a second vault named members-ops gave {dup:?}, not Conflict"
    );
    let orphan = vault("members-orphan", 2);
    let res = store
        .insert_vault_with_admin(
            orphan.clone(),
            member(orphan.id, UserId::new(), Role::Admin),
            &[],
        )
        .await;
    let inserted = store
        .get_vault(&orphan.id)
        .await
        .map_err(backend(S, "create_missing_user"))?;
    ensure!(
        S,
        "create_missing_user",
        matches!(res, Err(StoreError::NotFound { .. })) && inserted.is_none(),
        "creating a vault for a missing person gave {res:?} and left the vault {inserted:?}"
    );

    // Roles per vault, listed by username.
    let dev = vault("members-dev", 3);
    store
        .insert_vault(dev.clone(), &[])
        .await
        .map_err(backend(S, "dev"))?;
    for (v, p, r) in [
        (&ops, &bob, Role::Editor),
        (&ops, &carol, Role::Runner),
        (&dev, &bob, Role::Viewer),
    ] {
        store
            .put_vault_member(member(v.id, p.id, r), &[event("vault.member.put", v.id)])
            .await
            .map_err(backend(S, "put"))?;
    }
    let listed = store
        .list_vault_members(&ops.id, PageRequest::default())
        .await
        .map_err(backend(S, "list"))?;
    let names: Vec<_> = listed
        .items
        .iter()
        .map(|m| (m.username.as_str(), m.role))
        .collect();
    ensure!(
        S,
        "list",
        listed.total == 3
            && names
                == [
                    ("alice", Role::Admin),
                    ("bob", Role::Editor),
                    ("carol", Role::Runner)
                ],
        "members of ops are {names:?} (total {})",
        listed.total
    );
    let mut expected = vec![
        VaultGrant {
            vault_id: ops.id,
            role: Role::Editor,
        },
        VaultGrant {
            vault_id: dev.id,
            role: Role::Viewer,
        },
    ];
    expected.sort_by_key(|g| g.vault_id.to_string());
    let grants = store
        .user_vaults(&bob.id)
        .await
        .map_err(backend(S, "user_vaults"))?;
    ensure!(
        S,
        "user_vaults",
        grants == expected,
        "bob's vaults are {grants:?}, not {expected:?}"
    );
    store
        .put_vault_member(member(ops.id, bob.id, Role::Viewer), &[])
        .await
        .map_err(backend(S, "change_role"))?;
    let role = store
        .vault_role(&ops.id, &bob.id)
        .await
        .map_err(backend(S, "change_role"))?;
    ensure!(
        S,
        "change_role",
        role == Some(Role::Viewer),
        "bob's changed role is {role:?}"
    );
    let none = store
        .vault_role(&dev.id, &carol.id)
        .await
        .map_err(backend(S, "not_member"))?;
    ensure!(
        S,
        "not_member",
        none.is_none(),
        "carol has role {none:?} in a vault she never joined"
    );

    let res = store
        .put_vault_member(member(VaultId::new(), bob.id, Role::Viewer), &[])
        .await;
    ensure!(
        S,
        "put_missing_vault",
        matches!(res, Err(StoreError::NotFound { .. })),
        "gave {res:?}"
    );
    let res = store
        .put_vault_member(member(ops.id, UserId::new(), Role::Viewer), &[])
        .await;
    ensure!(
        S,
        "put_missing_user",
        matches!(res, Err(StoreError::NotFound { .. })),
        "gave {res:?}"
    );

    // A vault always keeps an admin.
    let res = store
        .put_vault_member(
            member(ops.id, alice.id, Role::Editor),
            &[event("vault.member.put", ops.id)],
        )
        .await;
    let role = store
        .vault_role(&ops.id, &alice.id)
        .await
        .map_err(backend(S, "last_admin"))?;
    ensure!(
        S,
        "demote_last_admin",
        matches!(res, Err(StoreError::Conflict { .. })) && role == Some(Role::Admin),
        "demoting the only admin gave {res:?} and left the role {role:?}"
    );
    let res = store.remove_vault_member(&ops.id, &alice.id, &[]).await;
    ensure!(
        S,
        "remove_last_admin",
        matches!(res, Err(StoreError::Conflict { .. })),
        "removing the only admin gave {res:?}"
    );
    store
        .put_vault_member(member(ops.id, bob.id, Role::Admin), &[])
        .await
        .map_err(backend(S, "second_admin"))?;
    store
        .put_vault_member(member(ops.id, alice.id, Role::Editor), &[])
        .await
        .map_err(backend(S, "demote_with_another_admin"))?;
    let removed = store
        .remove_vault_member(&ops.id, &carol.id, &[event("vault.member.remove", ops.id)])
        .await
        .map_err(backend(S, "remove"))?;
    let again = store
        .remove_vault_member(&ops.id, &carol.id, &[])
        .await
        .map_err(backend(S, "remove_again"))?;
    ensure!(
        S,
        "remove",
        removed && !again,
        "remove gave {removed}, then {again}"
    );
    // A vault nobody administers yet (made without a person) may gain
    // members of any role.
    store
        .put_vault_member(member(dev.id, carol.id, Role::Runner), &[])
        .await
        .map_err(backend(S, "no_admin_yet"))?;

    // An invitation's vault roles come with the account; a vault deleted
    // since is skipped.
    let gone = vault("members-gone", 4);
    store
        .insert_vault(gone.clone(), &[])
        .await
        .map_err(backend(S, "gone"))?;
    let mut offer = invite("members-invite", Role::Member, -1, 100);
    offer.vaults = vec![
        VaultGrant {
            vault_id: dev.id,
            role: Role::Runner,
        },
        VaultGrant {
            vault_id: gone.id,
            role: Role::Editor,
        },
    ];
    store
        .insert_invite(offer.clone(), &[])
        .await
        .map_err(backend(S, "invite"))?;
    let stored = store
        .get_invite_by_token_hash("members-invite")
        .await
        .map_err(backend(S, "invite_round_trip"))?;
    ensure!(
        S,
        "invite_round_trip",
        stored.as_ref().is_some_and(|i| i.vaults == offer.vaults),
        "the invitation came back as {stored:?}"
    );
    store
        .delete_vault(&gone.id, at(1), &[])
        .await
        .map_err(backend(S, "gone"))?;
    let dave = person("dave", Role::Member, 1);
    let accepted = store
        .accept_invite("members-invite", dave.clone(), &[])
        .await
        .map_err(backend(S, "accept"))?;
    let grants = store
        .user_vaults(&dave.id)
        .await
        .map_err(backend(S, "accept"))?;
    ensure!(
        S,
        "accept_gives_vaults",
        accepted
            && grants
                == [VaultGrant {
                    vault_id: dev.id,
                    role: Role::Runner
                }],
        "accepting gave {accepted} and the vaults {grants:?}"
    );

    // Lists narrow to a set of vaults; instance-wide events are only in
    // an unscoped one.
    let only_dev = VaultScope::one(dev.id);
    let vaults = store
        .list_vaults(&only_dev, PageRequest::default())
        .await
        .map_err(backend(S, "list_scoped"))?;
    ensure!(
        S,
        "list_scoped",
        vaults.total == 1 && vaults.items.iter().map(|v| v.id).eq([dev.id]),
        "a list within dev gave {} vaults",
        vaults.total
    );
    let nothing = store
        .list_vaults(&VaultScope::Only(Vec::new()), PageRequest::default())
        .await
        .map_err(backend(S, "list_empty_scope"))?;
    ensure!(
        S,
        "list_empty_scope",
        nothing.total == 0 && nothing.items.is_empty(),
        "an empty scope listed {} vaults",
        nothing.total
    );
    let everything = store
        .list_vaults(&VaultScope::All, PageRequest::default())
        .await
        .map_err(backend(S, "list_all"))?;
    ensure!(
        S,
        "list_all",
        everything.total == 2,
        "every vault is {} vaults, not 2",
        everything.total
    );
    store
        .record(&[AuditEvent::new(
            "user:conformance",
            "settings.update",
            AuditOutcome::Success,
        )])
        .await
        .map_err(backend(S, "audit_scoped"))?;
    let scoped = store
        .query(&AuditQuery {
            within: VaultScope::one(ops.id),
            page: PageRequest::new(Some(1), Some(100)),
            ..AuditQuery::default()
        })
        .await
        .map_err(backend(S, "audit_scoped"))?;
    ensure!(
        S,
        "audit_scoped",
        scoped.total > 0 && scoped.items.iter().all(|e| e.vault_id == Some(ops.id)),
        "audit within ops gave {:?}",
        scoped
            .items
            .iter()
            .map(|e| (&e.action, e.vault_id))
            .collect::<Vec<_>>()
    );
    let none = store
        .query(&AuditQuery {
            within: VaultScope::Only(Vec::new()),
            page: PageRequest::default(),
            ..AuditQuery::default()
        })
        .await
        .map_err(backend(S, "audit_empty_scope"))?;
    ensure!(
        S,
        "audit_empty_scope",
        none.total == 0,
        "an empty scope gave {} events",
        none.total
    );

    // Deleting a vault drops its members.
    store
        .delete_vault(&ops.id, at(2), &[])
        .await
        .map_err(backend(S, "delete"))?;
    let role = store
        .vault_role(&ops.id, &bob.id)
        .await
        .map_err(backend(S, "delete"))?;
    let members = store
        .list_vault_members(&ops.id, PageRequest::default())
        .await
        .map_err(backend(S, "delete"))?;
    ensure!(
        S,
        "delete_drops_members",
        role.is_none() && members.total == 0,
        "after deleting ops, bob's role is {role:?} and it lists {} members",
        members.total
    );
    Ok(())
}
