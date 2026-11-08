// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `Debug` for types that hold a secret: the secret fields print as `***`,
//! so a `{:?}` in a log line, an error or a panic message never carries
//! one. Serialization is untouched: a type that hands a freshly minted
//! credential to its caller still serializes it, exactly once.

/// Implements `Debug` for a struct, printing each field after the `;` as
/// `***`. Every field must be listed, so a new one is a compile error
/// until someone decides which side it is on.
///
/// ```
/// pub struct Login {
///     pub username: String,
///     pub password: String,
/// }
/// tokenless_core::redacted_debug!(Login { username; password });
///
/// let login = Login { username: "ada".into(), password: "hunter2".into() };
/// assert_eq!(format!("{login:?}"), r#"Login { username: "ada", password: *** }"#);
/// ```
#[macro_export]
macro_rules! redacted_debug {
    ($ty:ident { $($shown:ident),* $(,)? ; $($secret:ident),+ $(,)? }) => {
        impl ::core::fmt::Debug for $ty {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                // Destructuring lists every field: one left out fails to
                // compile.
                let Self { $($shown,)* $($secret,)+ } = self;
                $(let _ = $secret;)+
                f.debug_struct(stringify!($ty))
                    $(.field(stringify!($shown), $shown))*
                    $(.field(stringify!($secret), &$crate::redact::Redacted))+
                    .finish()
            }
        }
    };
}

/// Prints `***`.
pub struct Redacted;

impl core::fmt::Debug for Redacted {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("***")
    }
}
