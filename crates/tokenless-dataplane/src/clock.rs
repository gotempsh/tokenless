// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The time expiry is checked against, which setting the wall clock back
//! cannot rewind: the later of the wall clock and the wall clock at the
//! first check plus the monotonic time since. A clock set back by an hour
//! does not give an expired session or grant another hour; one set forward
//! ends them early, which fails closed.
//!
//! Only deadlines use it. A token's `nbf` is still checked against the wall
//! clock, so a correction backwards never refuses freshly minted sessions.

use std::sync::OnceLock;
use std::time::Instant;

use chrono::{DateTime, TimeDelta, Utc};

pub(crate) fn now() -> DateTime<Utc> {
    later_of(Utc::now(), anchor())
}

fn anchor() -> DateTime<Utc> {
    static ANCHOR: OnceLock<(DateTime<Utc>, Instant)> = OnceLock::new();
    let (wall, mono) = ANCHOR.get_or_init(|| (Utc::now(), Instant::now()));
    TimeDelta::from_std(mono.elapsed())
        .ok()
        .and_then(|elapsed| wall.checked_add_signed(elapsed))
        .unwrap_or(DateTime::<Utc>::MAX_UTC)
}

fn later_of(wall: DateTime<Utc>, floor: DateTime<Utc>) -> DateTime<Utc> {
    wall.max(floor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wall_clock_set_back_does_not_rewind_deadlines() {
        let floor = now();
        let set_back = floor - TimeDelta::hours(1);
        assert_eq!(later_of(set_back, floor), floor);
        let set_forward = floor + TimeDelta::hours(1);
        assert_eq!(later_of(set_forward, floor), set_forward);
        assert!(now() >= floor);
    }
}
