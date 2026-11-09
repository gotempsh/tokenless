// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Renders the headers a credential injects: its secret fields and custom
//! headers, with `{{VARIABLE}}` references filled in. Used for snapshots
//! and for validation requests, so both send exactly the same thing.

use std::collections::HashMap;

use tokenless_core::injection::{InjectedHeaders, SecretFields};
use tokenless_core::substitution::render_substitutions;
use tokenless_core::template::ServiceTemplate;
use tokenless_core::variables::render_custom_headers;
use zeroize::Zeroizing;

use super::policy::credential_aad_for;
use crate::cipher::SecretCipher;
use crate::error::ControlError;
use crate::model::CredentialMeta;
use crate::store::CredentialStore;

pub(crate) fn variable_aad(id: &tokenless_core::ids::VariableId) -> Vec<u8> {
    format!("variable|{id}").into_bytes()
}

pub(crate) struct Rendered {
    pub headers: InjectedHeaders,
    /// Header names removed from the agent's request before injection.
    pub strip: Vec<String>,
}

/// Decrypts the variables named in `keys`. Missing keys are simply absent:
/// substitution reports them with the field or header that uses them.
pub(crate) async fn load_variables(
    credentials: &dyn CredentialStore,
    cipher: &dyn SecretCipher,
    keys: &[String],
) -> Result<HashMap<String, Zeroizing<String>>, ControlError> {
    let mut values = HashMap::new();
    for (variable, ciphertext) in credentials.load_variable_ciphertexts(keys).await? {
        let plaintext = cipher
            .decrypt(&ciphertext, &variable_aad(&variable.id))
            .await?;
        let value = String::from_utf8(plaintext.to_vec()).map_err(|_| {
            ControlError::crypto(
                "variable.decode",
                format!("variable {} ({}) is not UTF-8", variable.key, variable.id),
            )
        })?;
        values.insert(variable.key, Zeroizing::new(value));
    }
    Ok(values)
}

pub(crate) async fn render_credential(
    credentials: &dyn CredentialStore,
    cipher: &dyn SecretCipher,
    template: &ServiceTemplate,
    meta: &CredentialMeta,
) -> Result<Rendered, ControlError> {
    let ciphertext = credentials
        .load_secret_ciphertext(&meta.id)
        .await?
        .ok_or_else(|| ControlError::not_found("credential", meta.id))?;
    let plaintext = cipher
        .decrypt(&ciphertext, &credential_aad_for(meta))
        .await?;
    let fields: SecretFields = serde_json::from_slice(&plaintext)
        .map_err(|e| ControlError::crypto("credential.decode", format!("{}: {e}", meta.id)))?;
    let values = load_variables(credentials, cipher, &meta.variable_refs).await?;
    let lookup = |key: &str| values.get(key).map(|v| v.as_str());
    let resolved = fields.resolve(lookup)?;
    drop(fields);
    let mut headers = template.injection.render(&template.id, &resolved)?;
    headers.substitutions = render_substitutions(&template.id, &meta.substitutions, &resolved)?;
    drop(resolved);
    render_custom_headers(&meta.custom_headers, &mut headers, lookup)?;
    let mut strip = template.injection.strip_set();
    for header in &meta.custom_headers {
        let name = header.name.to_ascii_lowercase();
        if !strip.contains(&name) {
            strip.push(name);
        }
    }
    Ok(Rendered { headers, strip })
}
