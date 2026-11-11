// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tripwires: decoy credentials planted on an agent's machine. Nothing
//! legitimate ever sends one, so a request through the proxy that carries
//! it means someone took it from the machine.

use rand::distributions::{Distribution, Uniform};
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::host::HostPattern;

/// The provider a decoy looks like it belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TripwireKind {
    /// An AWS access key pair, as in `~/.aws/credentials`.
    Aws,
    /// A GitHub personal access token.
    Github,
    /// An OpenAI API key.
    Openai,
    /// An API key of no provider in particular.
    Generic,
}

/// A generated decoy: the value the proxy looks for, and for AWS the
/// secret half that goes with it.
#[derive(Clone, PartialEq, Eq)]
pub struct Decoy {
    pub value: String,
    pub secret: Option<String>,
}

impl std::fmt::Debug for Decoy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Decoy").finish_non_exhaustive()
    }
}

const UPPER_DIGITS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const BASE64ISH: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn random(rng: &mut impl Rng, alphabet: &[u8], len: usize) -> String {
    let pick = Uniform::from(0..alphabet.len());
    (0..len)
        .map(|_| char::from(alphabet[pick.sample(rng)]))
        .collect()
}

impl TripwireKind {
    pub const ALL: [TripwireKind; 4] = [
        TripwireKind::Aws,
        TripwireKind::Github,
        TripwireKind::Openai,
        TripwireKind::Generic,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            TripwireKind::Aws => "aws",
            TripwireKind::Github => "github",
            TripwireKind::Openai => "openai",
            TripwireKind::Generic => "generic",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == raw)
    }

    /// A fresh decoy shaped like a real credential of this kind.
    pub fn generate(self) -> Decoy {
        let mut rng = rand::rngs::OsRng;
        match self {
            TripwireKind::Aws => Decoy {
                value: format!("AKIA{}", random(&mut rng, UPPER_DIGITS, 16)),
                secret: Some(random(&mut rng, BASE64ISH, 40)),
            },
            TripwireKind::Github => Decoy {
                value: format!("ghp_{}", random(&mut rng, ALNUM, 36)),
                secret: None,
            },
            TripwireKind::Openai => Decoy {
                value: format!("sk-proj-{}", random(&mut rng, ALNUM, 48)),
                secret: None,
            },
            TripwireKind::Generic => Decoy {
                value: format!("sk-{}", random(&mut rng, ALNUM, 40)),
                secret: None,
            },
        }
    }

    /// Where someone holding the decoy would use it. Under the deny policy
    /// the proxy opens connections to these hosts to look for it, even when
    /// no rule covers them; elsewhere it looks only on hosts it intercepts.
    pub fn hosts(self) -> Vec<HostPattern> {
        let names: &[&str] = match self {
            TripwireKind::Aws => &["sts.amazonaws.com", "iam.amazonaws.com", "s3.amazonaws.com"],
            TripwireKind::Github => &["api.github.com", "github.com"],
            TripwireKind::Openai => &["api.openai.com"],
            TripwireKind::Generic => &[],
        };
        names
            .iter()
            .filter_map(|n| HostPattern::parse(n).ok())
            .collect()
    }

    /// The environment variables a decoy of this kind usually sits in.
    pub fn env_names(self) -> (&'static str, Option<&'static str>) {
        match self {
            TripwireKind::Aws => ("AWS_ACCESS_KEY_ID", Some("AWS_SECRET_ACCESS_KEY")),
            TripwireKind::Github => ("GITHUB_TOKEN", None),
            TripwireKind::Openai => ("OPENAI_API_KEY", None),
            TripwireKind::Generic => ("API_KEY", None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoys_look_like_the_real_thing_and_never_repeat() {
        let aws = TripwireKind::Aws.generate();
        assert!(aws.value.starts_with("AKIA") && aws.value.len() == 20);
        assert!(aws.value[4..].bytes().all(|b| UPPER_DIGITS.contains(&b)));
        assert_eq!(aws.secret.as_deref().map(str::len), Some(40));
        let gh = TripwireKind::Github.generate();
        assert!(gh.value.starts_with("ghp_") && gh.value.len() == 40);
        assert!(TripwireKind::Openai
            .generate()
            .value
            .starts_with("sk-proj-"));
        assert_ne!(
            TripwireKind::Generic.generate().value,
            TripwireKind::Generic.generate().value
        );
        assert!(!format!("{aws:?}").contains(&aws.value), "never in Debug");
    }

    #[test]
    fn kinds_round_trip_and_name_their_hosts() {
        for kind in TripwireKind::ALL {
            assert_eq!(TripwireKind::parse(kind.as_str()), Some(kind));
        }
        assert_eq!(TripwireKind::parse("gcp"), None);
        assert!(TripwireKind::Aws
            .hosts()
            .iter()
            .any(|h| h.matches("sts.amazonaws.com", 443)));
        assert!(TripwireKind::Generic.hosts().is_empty());
    }
}
