// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Control plane services for the credential broker.
//!
//! Everything durable goes through the traits in [`store`]; everything
//! secret goes through [`cipher::SecretCipher`]. The services know nothing
//! about HTTP, SQL or any embedding platform.

pub mod cipher;
pub mod error;
pub mod keys;
pub mod memory;
pub mod model;
pub mod notify;
pub mod pki;
pub mod service;
pub mod store;

pub use error::{ControlError, StoreError};
pub use service::{Caller, ControlConfig, ControlPlane, Stores};
