// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use chrono::{TimeDelta, Utc};
use rand::rngs::OsRng;
use tokenless_core::audit::{AuditEvent, AuditOutcome};
use tokenless_core::authz::{Principal, PrincipalKind, Role};
use tokenless_core::protocol::AuditBatch;
use tokenless_core::seal::{encode_public_key, open, SealPublicKey, SealSecretKey};
use tokenless_core::snapshot::{tripwires_aad, SnapshotTripwire, TRIPWIRE_ACTION, TRIPWIRE_FORMAT};

use super::*;
use crate::model::{AlertFilter, AlertKind, AuditQuery};
use crate::service::sessions::MintSession;
use crate::service::testing::{services, vault_with_rule};
use crate::store::AuditSink;

fn person(role: Role, vault: Option<VaultId>, step_up_age: i64) -> Caller {
    Caller {
        principal: Principal {
            kind: PrincipalKind::User,
            actor: format!("user:{role}"),
            role,
            vault,
        },
        step_up_at: Some(Utc::now() - TimeDelta::seconds(step_up_age)),
        second_factor: true,
        launch: None,
    }
}

fn host() -> Caller {
    Caller::service(Principal::service("host", Role::Admin, None))
}

#[test]
fn planting_an_aws_decoy_gives_the_credentials_file_and_both_halves() {
    let ways = plant(TripwireKind::Aws, "AKIAEXAMPLEDECOY0000", Some("s3cr3t"));
    assert_eq!(ways[0].place, "~/.aws/credentials");
    assert!(ways[0]
        .text
        .contains("aws_access_key_id = AKIAEXAMPLEDECOY0000"));
    assert!(ways[0].text.contains("aws_secret_access_key = s3cr3t"));
    assert!(ways[1].text.contains("export AWS_SECRET_ACCESS_KEY=s3cr3t"));
    let gh = plant(TripwireKind::Github, "ghp_x", None);
    assert_eq!(gh.len(), 2);
    assert_eq!(gh[1].text, "GITHUB_TOKEN=ghp_x");
}

#[tokio::test]
async fn a_tripwire_is_created_once_shown_and_listed_without_its_decoy() {
    let (store, cs) = services().await;
    let (vault, _) = vault_with_rule(&cs, &host()).await;
    let editor = person(Role::Editor, Some(vault), 3600);
    let created = cs
        .tripwires
        .create(&editor, &vault, "  build-runner ", TripwireKind::Aws)
        .await
        .unwrap();
    assert_eq!(created.tripwire.name, "build-runner");
    assert!(created.value.starts_with("AKIA") && created.secret.is_some());
    assert_eq!(created.tripwire.prefix, created.value[..8]);
    assert!(!format!("{created:?}").contains(&created.value));

    let listed = cs
        .tripwires
        .list(&editor, &vault, PageRequest::new(Some(1), Some(10)))
        .await
        .unwrap();
    assert_eq!(listed.total, 1);
    let json = serde_json::to_string(&listed).unwrap();
    assert!(!json.contains(&created.value), "never listed: {json}");

    let audit = store
        .query(&AuditQuery {
            action_prefix: Some("tripwire.".into()),
            page: PageRequest::new(Some(1), Some(10)),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(audit.total, 1);
    assert_eq!(audit.items[0].detail["kind"], "aws");
    assert!(audit.items[0]
        .detail
        .values()
        .all(|v| !v.contains(&created.value)));

    let err = cs
        .tripwires
        .create(&editor, &vault, "build-runner", TripwireKind::Github)
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            ControlError::Store(crate::StoreError::Conflict { .. }) | ControlError::Conflict { .. }
        ),
        "{err:?}"
    );
}

#[tokio::test]
async fn names_vaults_roles_and_the_limit_are_checked() {
    let (_, cs) = services().await;
    let (vault, _) = vault_with_rule(&cs, &host()).await;
    let editor = person(Role::Editor, Some(vault), 0);
    for bad in ["", "   ", &"x".repeat(MAX_NAME_LEN + 1)] {
        let err = cs
            .tripwires
            .create(&editor, &vault, bad, TripwireKind::Generic)
            .await
            .unwrap_err();
        assert!(matches!(err, ControlError::Validation { .. }), "{err:?}");
    }
    let viewer = person(Role::Viewer, Some(vault), 0);
    let err = cs
        .tripwires
        .create(&viewer, &vault, "laptop", TripwireKind::Generic)
        .await
        .unwrap_err();
    assert!(matches!(err, ControlError::Forbidden { .. }), "{err:?}");
    let missing = VaultId::new();
    let err = cs
        .tripwires
        .create(&host(), &missing, "laptop", TripwireKind::Generic)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, ControlError::NotFound { entity: "vault", id } if *id == missing.to_string()),
        "{err:?}"
    );
    for i in 0..MAX_TRIPWIRES_PER_VAULT {
        cs.tripwires
            .create(&editor, &vault, &format!("m{i}"), TripwireKind::Generic)
            .await
            .unwrap();
    }
    let err = cs
        .tripwires
        .create(&editor, &vault, "one-too-many", TripwireKind::Generic)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("delete one first"), "{err}");
}

#[tokio::test]
async fn deleting_one_needs_a_step_up_and_its_own_vault() {
    let (_, cs) = services().await;
    let (vault, _) = vault_with_rule(&cs, &host()).await;
    let created = cs
        .tripwires
        .create(&host(), &vault, "laptop", TripwireKind::Openai)
        .await
        .unwrap();
    let id = created.tripwire.id;
    let elsewhere = person(Role::Editor, Some(VaultId::new()), 0);
    let err = cs.tripwires.delete(&elsewhere, &id).await.unwrap_err();
    assert!(matches!(err, ControlError::NotFound { .. }), "{err:?}");
    let stale = person(Role::Editor, Some(vault), 3600);
    let err = cs.tripwires.delete(&stale, &id).await.unwrap_err();
    assert!(
        matches!(err, ControlError::StepUpRequired { .. }),
        "{err:?}"
    );
    let fresh = person(Role::Editor, Some(vault), 0);
    assert_eq!(cs.tripwires.delete(&fresh, &id).await.unwrap().id, id);
    let err = cs.tripwires.delete(&fresh, &id).await.unwrap_err();
    assert!(
        matches!(&err, ControlError::NotFound { entity: "tripwire", id: missing } if *missing == id.to_string()),
        "{err:?}"
    );
}

#[tokio::test]
async fn proxies_get_every_decoy_sealed_and_a_trip_revokes_and_alerts() {
    let (store, cs) = services().await;
    let (vault, rule) = vault_with_rule(&cs, &host()).await;
    let created = cs
        .tripwires
        .create(&host(), &vault, "laptop", TripwireKind::Github)
        .await
        .unwrap();
    let secret = SealSecretKey::random_from_rng(OsRng);
    let node = cs
        .nodes
        .register_embedded(
            &host(),
            "edge-1",
            &encode_public_key(&SealPublicKey::from(&secret)),
        )
        .await
        .unwrap();

    // The current format carries them, sealed to the node.
    let snapshot = cs
        .nodes
        .build_snapshot_for(&node.node, TRIPWIRE_FORMAT)
        .await
        .unwrap()
        .snapshot;
    assert!(
        !snapshot.body.contains(&created.value),
        "never in the clear"
    );
    let body = snapshot
        .verify(&cs.keys.snapshot_key.verifying_key())
        .unwrap();
    assert_eq!(body.format, TRIPWIRE_FORMAT);
    let plain = open(
        &secret,
        body.tripwires.as_ref().unwrap(),
        &tripwires_aad(&node.node.id),
    )
    .unwrap();
    let decoys: Vec<SnapshotTripwire> = serde_json::from_slice(&plain).unwrap();
    assert_eq!(decoys.len(), 1);
    assert_eq!(decoys[0].value, created.value);
    assert!(decoys[0]
        .hosts
        .iter()
        .any(|h| h.matches("api.github.com", 443)));
    // An older node gets none, and a format it reads.
    let old = cs
        .nodes
        .build_snapshot_for(&node.node, 4)
        .await
        .unwrap()
        .snapshot;
    let old = old.verify(&cs.keys.snapshot_key.verifying_key()).unwrap();
    assert!(old.tripwires.is_none() && old.format <= 4);

    let minted = cs
        .sessions
        .mint(
            &host(),
            &vault,
            MintSession {
                rule_ids: vec![rule],
                ttl_secs: Some(600),
                ..MintSession::default()
            },
        )
        .await
        .unwrap();
    let trip = AuditEvent::new("node:x", TRIPWIRE_ACTION, AuditOutcome::Denied)
        .detail("scope", format!("vault:{vault}"))
        .detail("session_id", minted.session.id.to_string())
        .detail("tripwire_id", created.tripwire.id.to_string())
        .detail("tripwire", "laptop")
        .detail("found_in", "header authorization")
        .detail("host", "api.github.com:443");
    cs.nodes
        .ingest_audit(&node.node, AuditBatch { events: vec![trip] })
        .await
        .unwrap();

    let session = cs.sessions.get(&host(), &minted.session.id).await.unwrap();
    assert!(session.revoked_at.is_some());
    let revoke = store
        .query(&AuditQuery {
            action_prefix: Some("session.revoke".into()),
            page: PageRequest::new(Some(1), Some(10)),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(revoke.items[0].detail["reason"], "tripwire");
    assert_eq!(revoke.items[0].detail["tripwire"], "laptop");

    let alerts = cs
        .alerts
        .list(
            &host(),
            AlertFilter::default(),
            PageRequest::new(Some(1), Some(10)),
        )
        .await
        .unwrap();
    assert_eq!(alerts.total, 1);
    assert_eq!(alerts.items[0].kind, AlertKind::Tripwire);
    assert_eq!(alerts.items[0].session_id, Some(minted.session.id));
    assert!(alerts.items[0]
        .summary
        .contains("tripwire 'laptop' to api.github.com:443"));

    let listed = cs
        .tripwires
        .list(&host(), &vault, PageRequest::new(Some(1), Some(10)))
        .await
        .unwrap();
    assert!(listed.items[0].last_tripped_at.is_some());
}
