//! Kani proof harnesses for the QSW wire codecs: the bytes DUCTEI reads
//! from other machines once network transport (GAP 4) is live.
//!
//!   cargo kani -p ductei-qallow     # proves every input within bounds
//!   cargo test -p ductei-qallow     # sampled run of the same bodies
//!
//! "Never panics" here means Kani found no reachable panic, out-of-bounds
//! slice, or arithmetic overflow for ANY byte string up to the bound.
//! Byte-compatibility with Qallow's C decoder is still the conformance
//! job's responsibility; these harnesses cover the Rust side only.

#[cfg(not(kani))]
#[path = "../../ductei-core/src/proof_shim.rs"]
mod kani;

use ductei_core::{Envelope, Scope};

/// 36-byte v1 header plus up to 8 bytes of key/blob.
const V1_MAX: usize = 44;
/// 30-byte v2 fixed header plus up to 10 bytes of scopes/key/blob.
const V2_MAX: usize = 40;

#[cfg_attr(kani, kani::proof)]
#[cfg_attr(kani, kani::unwind(46))]
fn v1_decoder_never_panics() {
    let len: usize = kani::any();
    kani::assume(len <= V1_MAX);
    let buf: [u8; V1_MAX] = kani::any();
    let _ = crate::decode_envelope_body(&buf[..len]);
}

#[cfg_attr(kani, kani::proof)]
#[cfg_attr(kani, kani::unwind(42))]
fn v2_decoder_never_panics() {
    let len: usize = kani::any();
    kani::assume(len <= V2_MAX);
    let buf: [u8; V2_MAX] = kani::any();
    let _ = crate::v2::decode_envelope_body(&buf[..len]);
}

/// A short ASCII string of symbolic length `<= N`.
fn ascii<const N: usize>() -> String {
    let len: usize = kani::any();
    kani::assume(len <= N);
    let bytes: [u8; N] = kani::any();
    kani::assume(bytes[..len].iter().all(|&b| b < 0x80));
    String::from_utf8(bytes[..len].to_vec()).unwrap()
}

/// Up to 2 scopes of up to 2 ASCII bytes each.
fn scopes() -> Vec<Scope> {
    let n: usize = kani::any();
    kani::assume(n <= 2);
    (0..n).map(|_| Scope(ascii::<2>())).collect()
}

fn small_envelope(scopes: Vec<Scope>) -> Envelope {
    let blob_len: usize = kani::any();
    kani::assume(blob_len <= 3);
    let blob: [u8; 3] = kani::any();
    Envelope {
        node_id: kani::any(),
        lamport: kani::any(),
        schema_ver: kani::any(),
        flags: kani::any(),
        key: ascii::<2>(),
        scopes,
        blob: blob[..blob_len].to_vec(),
    }
}

/// Check the outer frame and return the body.
fn body(frame: &[u8]) -> &[u8] {
    assert_eq!(frame[0], crate::F_ENVELOPE);
    let len = u32::from_le_bytes(frame[1..5].try_into().unwrap()) as usize;
    assert_eq!(len, frame.len() - 5, "frame length prefix disagrees with body");
    &frame[5..]
}

/// v2 is lossless: any small envelope decodes back to itself, with scopes
/// in the encoder's canonical (sorted) order.
#[cfg_attr(kani, kani::proof)]
#[cfg_attr(kani, kani::unwind(8))]
fn v2_round_trips() {
    let mut env = small_envelope(scopes());
    let frame = crate::v2::encode_envelope(&env);
    let back = crate::v2::decode_envelope_body(body(&frame)).expect("own v2 encoding must decode");
    env.scopes.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(back, env);
}

/// v1 round-trips ONLY for scopes that are non-empty and contain neither
/// ',' nor '|', because scopes ride in the "scope0,scope1|key" shim. Those
/// assumptions are the known limits of v1; QSW v2 removes them.
#[cfg_attr(kani, kani::proof)]
#[cfg_attr(kani, kani::unwind(8))]
fn v1_round_trips_within_shim_limits() {
    let sc = scopes();
    for s in &sc {
        kani::assume(!s.0.is_empty() && !s.0.contains(',') && !s.0.contains('|'));
    }
    let mut env = small_envelope(sc);
    let frame = crate::encode_envelope(&env);
    let back = crate::decode_envelope_body(body(&frame)).expect("own v1 encoding must decode");
    env.scopes.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(back, env);
}

#[cfg(all(test, not(kani)))]
mod sampled {
    use super::*;
    const N: usize = 20_000;

    #[test] fn v1_no_panic() { kani::run(v1_decoder_never_panics, N) }
    #[test] fn v2_no_panic() { kani::run(v2_decoder_never_panics, N) }
    #[test] fn v2_round_trip() { kani::run(v2_round_trips, N) }
    #[test] fn v1_round_trip() { kani::run(v1_round_trips_within_shim_limits, N) }

    /// Documents the v1 shim limit the round-trip harness assumes away: a
    /// scope containing ',' comes back as two different scopes.
    #[test]
    fn v1_shim_splits_scope_containing_comma() {
        let env = ductei_core::scoped("k", &["a,b"], [0; 16], 1, b"x");
        let frame = crate::encode_envelope(&env);
        let back = crate::decode_envelope_body(&frame[5..]).unwrap();
        assert_eq!(back.scopes, vec![Scope("a".into()), Scope("b".into())]);
    }
}
