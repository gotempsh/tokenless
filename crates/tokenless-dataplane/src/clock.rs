// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The time expiry is checked against: the later of this host's wall clock
//! and the control plane's, as the snapshot in force carries it (its
//! `issued_at`, plus the monotonic time since it was installed). The
//! control plane's clock is the one that minted every deadline, so setting
//! this host's clock back does not give an expired session or grant more
//! time. A host clock that is ahead ends them early, which fails closed,
//! and stops doing so as soon as it is corrected; a control plane clock
//! that was ahead is followed again with its next snapshot.
//!
//! Only deadlines use it. A token's `nbf` is still checked against the wall
//! clock, so a correction backwards never refuses freshly minted sessions.

use chrono::{DateTime, TimeDelta, Utc};

use crate::state::ActiveSnapshot;

pub(crate) fn now(snapshot: &ActiveSnapshot) -> DateTime<Utc> {
    later_of(Utc::now(), control_time(snapshot))
}

/// The control plane's time now, by the snapshot in force.
fn control_time(snapshot: &ActiveSnapshot) -> DateTime<Utc> {
    TimeDelta::from_std(snapshot.installed_at.elapsed())
        .ok()
        .and_then(|elapsed| snapshot.issued_at.checked_add_signed(elapsed))
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
        let floor = Utc::now();
        let set_back = floor - TimeDelta::hours(1);
        assert_eq!(later_of(set_back, floor), floor);
        let set_forward = floor + TimeDelta::hours(1);
        assert_eq!(later_of(set_forward, floor), set_forward);
    }

    /// A control plane clock that ran ahead (a host that booted before its
    /// clock was synced) is followed again from its next snapshot, rather
    /// than held until the data plane restarts.
    #[tokio::test]
    async fn a_control_clock_that_ran_ahead_is_followed_again_with_its_next_snapshot() {
        let r = crate::testing::running("localhost:1", vec![]).await;
        let install = |version, issued_at| {
            let mut body = r.f.snapshot_body(version, vec![]);
            body.issued_at = issued_at;
            r.installer.install(&r.f.sign(&body)).unwrap();
            r.dp.snapshot.load_full().unwrap()
        };
        let ahead = install(2, Utc::now() + TimeDelta::seconds(50));
        assert!(now(&ahead) >= Utc::now() + TimeDelta::seconds(45));
        let corrected = install(3, Utc::now());
        assert!(now(&corrected) < Utc::now() + TimeDelta::seconds(5));
    }
}
