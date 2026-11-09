// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Change notification from services to node snapshot streams.

use tokio::sync::watch;

/// Two counters so that minting or revoking a session (frequent) does not
/// invalidate the cached sealed rules (expensive to rebuild).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Generation {
    /// Rules, credentials, templates, settings.
    pub content: u64,
    /// Revocations and request-limited sessions.
    pub sessions: u64,
}

pub struct PolicyNotifier {
    tx: watch::Sender<Generation>,
}

impl PolicyNotifier {
    pub fn new() -> Self {
        let (tx, _) = watch::channel(Generation::default());
        Self { tx }
    }

    pub fn bump_content(&self) {
        self.tx.send_modify(|g| g.content += 1);
    }

    pub fn bump_sessions(&self) {
        self.tx.send_modify(|g| g.sessions += 1);
    }

    pub fn current(&self) -> Generation {
        *self.tx.borrow()
    }

    pub fn subscribe(&self) -> watch::Receiver<Generation> {
        self.tx.subscribe()
    }
}

impl Default for PolicyNotifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn subscribers_see_bumps() {
        let n = PolicyNotifier::new();
        let mut rx = n.subscribe();
        n.bump_sessions();
        rx.changed().await.unwrap();
        assert_eq!(
            *rx.borrow(),
            Generation {
                content: 0,
                sessions: 1
            }
        );
        n.bump_content();
        assert_eq!(n.current().content, 1);
    }
}
