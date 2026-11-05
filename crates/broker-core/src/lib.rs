// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pure policy logic shared by every part of the credential broker.
//!
//! Nothing in this crate performs I/O. It defines the vocabulary the control
//! plane and the data plane agree on: opaque scopes, host/path/method rules,
//! service templates, injection methods, signed session claims, sealed
//! credential envelopes and signed policy snapshots.

pub mod audit;
pub mod authz;
pub mod error;
pub mod host;
pub mod ids;
pub mod injection;
pub mod path;
pub mod protocol;
pub mod rule;
pub mod scope;
pub mod seal;
pub mod session;
pub mod snapshot;
pub mod template;

pub use error::CoreError;
