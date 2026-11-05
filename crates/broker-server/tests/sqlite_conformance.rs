// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Runs the trait conformance suites against the SQLite store.

#![allow(clippy::expect_used)]

use broker_server::store::SqliteStore;

async fn store() -> (tempfile::TempDir, SqliteStore) {
    let dir = tempfile::tempdir().expect("tempdir");
    let url = format!("sqlite://{}", dir.path().join("broker.db").display());
    let store = SqliteStore::connect(&url).await.expect("connect");
    (dir, store)
}

macro_rules! suite {
    ($name:ident) => {
        #[tokio::test]
        async fn $name() {
            let (_dir, store) = store().await;
            if let Err(failure) = broker_conformance::$name(&store).await {
                panic!("{failure}");
            }
        }
    };
}

suite!(credential_store_suite);
suite!(policy_store_suite);
suite!(audit_sink_suite);
suite!(identity_store_suite);
suite!(node_store_suite);
