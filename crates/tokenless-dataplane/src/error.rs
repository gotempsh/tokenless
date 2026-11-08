// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;
use tokenless_core::CoreError;

#[derive(Debug, Error)]
pub enum DataPlaneError {
    #[error("snapshot rejected: {reason}")]
    SnapshotRejected { reason: String },

    #[error("stale snapshot: received version {received}, already holding {current}")]
    StaleSnapshot { received: u64, current: u64 },

    #[error("TLS configuration for '{context}' failed: {reason}")]
    Tls { context: String, reason: String },

    #[error("interception certificate for '{host}' could not be created: {reason}")]
    Certificate { host: String, reason: String },

    #[error("control plane request {method} {path} failed: {reason}")]
    Control {
        method: String,
        path: String,
        reason: String,
    },

    #[error("control plane answered {status} to {method} {path}: {body}")]
    ControlStatus {
        method: String,
        path: String,
        status: u16,
        body: String,
    },

    #[error("upstream {host}:{port} failed: {reason}")]
    Upstream {
        host: String,
        port: u16,
        reason: String,
    },

    #[error("I/O error during {operation}: {source}")]
    Io {
        operation: String,
        #[source]
        source: std::io::Error,
    },

    #[error("node identity error: {reason}")]
    Identity { reason: String },

    #[error("binding '{binding_id}' was not created: {reason}")]
    InvalidBinding { binding_id: String, reason: String },

    #[error("binding '{binding_id}' has been revoked; bind the workload again")]
    BindingRevoked { binding_id: String },

    #[error("binding '{binding_id}' was not updated to version {version}: {reason}")]
    InvalidBindingUpdate {
        binding_id: String,
        version: u64,
        reason: String,
    },

    #[error("binding '{binding_id}' is at version {current}, so the update to version {offered} is stale and was refused")]
    StaleBindingUpdate {
        binding_id: String,
        current: u64,
        offered: u64,
    },

    #[error("binding '{binding_id}' already has its {max_connections} connections open")]
    BindingFull {
        binding_id: String,
        max_connections: usize,
    },

    #[error("binding '{binding_id}' is not ready: {}", reason.reason())]
    NotReady {
        binding_id: String,
        reason: crate::status::NotReady,
    },

    #[error("the data plane already has its {max_connections} connections open")]
    ConnectionLimit { max_connections: usize },

    #[error("the data plane is shutting down and accepts no new connections")]
    ShuttingDown,

    #[error(transparent)]
    Core(#[from] CoreError),
}

impl DataPlaneError {
    pub fn tls(context: &str, reason: impl std::fmt::Display) -> Self {
        DataPlaneError::Tls {
            context: context.to_string(),
            reason: reason.to_string(),
        }
    }

    pub fn io(operation: impl Into<String>, source: std::io::Error) -> Self {
        DataPlaneError::Io {
            operation: operation.into(),
            source,
        }
    }

    pub fn identity(reason: impl std::fmt::Display) -> Self {
        DataPlaneError::Identity {
            reason: reason.to_string(),
        }
    }

    pub fn rejected(reason: impl Into<String>) -> Self {
        DataPlaneError::SnapshotRejected {
            reason: reason.into(),
        }
    }
}
