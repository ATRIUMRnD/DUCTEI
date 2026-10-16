//! Kani proof harnesses for DUCTEI's hard invariants.
//!
//!   cargo kani -p ductei-core --features net   # Linux/macOS/CI: proves
//!                                              # every input within bounds
//!   cargo test -p ductei-core proofs           # anywhere: sampled run of
//!                                              # the same harness bodies
//!
//! Kani also flags any arithmetic overflow, out-of-bounds index or panic
//! reachable inside a harness, beyond the explicit assertions.
//!
//! Covered: deny-by-default scopes, bounded sessions, ack-after-persist
//! mapping, blob base64 round-trip. Not covered here: fsync durability
//! itself, the C side of the QSW wire (see ductei-qallow proofs + the
//! conformance job), multi-node ordering.

#[cfg(not(kani))]
#[path = "proof_shim.rs"]
mod kani;

use crate::{permits_with, ChannelError, Scope, SessionBound, SessionBudget};

// ---- Invariant: deny-by-default broadcast scopes -------------------------

const NAMES: [&str; 3] = ["a", "b", "c"];

/// For any envelope with up to 3 scopes and any allow/deny pattern:
/// an empty scope set is denied, one forbidden scope denies the whole
/// envelope, and it is permitted only if every scope is allowed.
#[cfg_attr(kani, kani::proof)]
#[cfg_attr(kani, kani::unwind(5))]
fn scope_policy_is_deny_by_default() {
    let n: usize = kani::any();
    kani::assume(n <= NAMES.len());
    let allowed: [bool; 3] = kani::any();

    let scopes: Vec<Scope> = NAMES[..n].iter().map(|s| Scope((*s).to_string())).collect();
    let lookup = |s: &Scope| NAMES.iter().position(|x| *x == s.0).is_some_and(|i| allowed[i]);
    let permitted = permits_with(&scopes, lookup);

    if n == 0 {
        assert!(!permitted, "an envelope with no scopes must be denied");
    }
    for &ok in &allowed[..n] {
        if !ok {
            assert!(!permitted, "one forbidden scope must poison the envelope");
        }
    }
    if n > 0 && allowed[..n].iter().all(|&a| a) {
        assert!(permitted, "an envelope whose scopes are all allowed must pass");
    }
}

// ---- Invariant: bounded sessions only ------------------------------------

/// From any reachable budget state and any cost: admission implies the
/// send stays within both bounds (checked in u128, so it cannot wrap),
/// and denial closes the budget.
#[cfg_attr(kani, kani::proof)]
fn session_budget_admit_respects_bounds() {
    let max: Option<u32> = kani::any();
    let deadline: Option<u64> = kani::any();
    let Some(bound) = SessionBound::new(max, deadline) else {
        assert!(max.is_none() && deadline.is_none(), "only fully-unbounded is unrepresentable");
        return;
    };
    let sent: u32 = kani::any();
    let spent: u64 = kani::any();
    let cost: u64 = kani::any();
    let mut b = SessionBudget { bound, sent, cost: spent, closed: false };

    match b.admit(cost) {
        Ok(()) => {
            if let Some(m) = max {
                assert!(sent < m, "admitted past the envelope cap");
            }
            if let Some(d) = deadline {
                assert!(spent as u128 + cost as u128 <= d as u128, "admitted past the cost deadline");
            }
        }
        Err(e) => {
            assert_eq!(e, ChannelError::BoundReached);
            assert!(b.closed, "a denial must close the session");
        }
    }
}

const STEPS: usize = 4;

/// Drive a fresh budget exactly the way `Session::send` does (admit, then a
/// channel send that may fail, then commit) for up to 4 sends with
/// arbitrary costs. The true totals, tracked in u128, never exceed the
/// bounds, and once closed a session stays closed.
#[cfg_attr(kani, kani::proof)]
#[cfg_attr(kani, kani::unwind(5))]
fn session_budget_sequence_never_exceeds_bound() {
    let max: Option<u32> = kani::any();
    let deadline: Option<u64> = kani::any();
    let Some(bound) = SessionBound::new(max, deadline) else { return };
    let mut b = SessionBudget::new(bound);
    let (mut true_sent, mut true_cost) = (0u128, 0u128);

    for _ in 0..STEPS {
        let cost: u64 = kani::any();
        let channel_accepts: bool = kani::any();
        let was_closed = b.closed;
        let admitted = b.admit(cost).is_ok();
        if was_closed {
            assert!(!admitted, "a closed session must stay closed");
        }
        if admitted && channel_accepts {
            b.commit(cost);
            true_sent += 1;
            true_cost += cost as u128;
        }
        if let Some(m) = max {
            assert!(true_sent <= m as u128);
        }
        if let Some(d) = deadline {
            assert!(true_cost <= d as u128);
        }
    }
}

// ---- Invariant: persistence-before-ack (wire mapping) --------------------

/// The TCP ack byte is 1 ("applied") exactly when the channel returned
/// Ok(()), which `Channel::send` does only after the fsynced append.
/// Stale deltas get the receipt ack 2; everything else gets 0.
#[cfg(feature = "net")]
#[cfg_attr(kani, kani::proof)]
fn ack_applied_only_after_accept() {
    let pick: u8 = kani::any();
    let result: Result<(), ChannelError> = match pick % 5 {
        0 => Ok(()),
        1 => Err(ChannelError::ScopeDenied(String::new())),
        2 => Err(ChannelError::BoundReached),
        3 => Err(ChannelError::Io(String::new())),
        _ => Err(ChannelError::StaleDelta { key: String::new(), lamport: kani::any() }),
    };
    let ack = crate::transport::ack_code(&result);
    assert_eq!(ack == 1, result.is_ok(), "applied-ack without an accepted send");
    assert!(ack <= 2, "ack outside the tri-state protocol");
    if matches!(result, Err(ChannelError::StaleDelta { .. })) {
        assert_eq!(ack, 2);
    }
}

// ---- Persistence/transport encoding: blob base64 -------------------------

/// Every blob of up to 4 bytes (both padding cases and a multi-chunk case)
/// survives the JSONL/TCP base64 encoding unchanged.
#[cfg_attr(kani, kani::proof)]
#[cfg_attr(kani, kani::unwind(70))]
fn blob_base64_round_trips() {
    let len: usize = kani::any();
    kani::assume(len <= 4);
    let data: [u8; 4] = kani::any();
    let blob = &data[..len];
    let back = crate::b64::dec(&crate::b64::enc(blob));
    assert_eq!(back.as_deref(), Some(blob));
}

// ---- Sampled run of the same harnesses under `cargo test` -----------------

#[cfg(all(test, not(kani)))]
mod sampled {
    use super::*;
    const N: usize = 20_000;

    #[test] fn scope_policy() { kani::run(scope_policy_is_deny_by_default, N) }
    #[test] fn session_admit() { kani::run(session_budget_admit_respects_bounds, N) }
    #[test] fn session_sequence() { kani::run(session_budget_sequence_never_exceeds_bound, N) }
    #[cfg(feature = "net")]
    #[test] fn ack_mapping() { kani::run(ack_applied_only_after_accept, N) }
    #[test] fn base64() { kani::run(blob_base64_round_trips, N) }

    /// Regression for the release-build wrap: a u64::MAX cost on a
    /// deadline-10 session used to be admitted and reset the total to 0.
    #[test]
    fn max_cost_cannot_wrap_past_deadline() {
        let mut b = SessionBudget::new(SessionBound::new(None, Some(10)).unwrap());
        b.admit(1).unwrap();
        b.commit(1);
        assert_eq!(b.admit(u64::MAX), Err(ChannelError::BoundReached));
        assert!(b.closed);
        assert_eq!(b.cost, 1);
    }
}
