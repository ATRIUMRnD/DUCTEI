//! Persist payload v2: the blob layout Qallow's `ql_persist_merge_blob()`
//! requires since Qallow@2b0009e (ATRIUM Task 4, kernel-level invariants).
//!
//! The wire frame (QSW v1, `encode_envelope`) is unchanged and still
//! passes the conformance oracle. What changes is what rides *inside*
//! `Envelope::blob` when the destination is Qallow's LMDB store: the
//! bounded session that carried the envelope through DUCTEI becomes an
//! on-disk fact (session id + bound), and the scope set becomes a
//! non-zero scope code, so Qallow can refuse -- at the C level, before
//! any write -- anything unbounded or broadcast/open. Invariants I2 and
//! I5 stop being "checked by the relay" and become unrepresentable in
//! the store.
//!
//! Layout inside `env.blob` (all little-endian, mirrors persist_lmdb.c):
//!
//! ```text
//!   u16 persist_ver   == 2
//!   u16 scope_code    != 0   (0 = broadcast/open, rejected by Qallow)
//!   u64 session_id    != 0
//!   u64 session_bound != 0
//!   u32 data_len
//!   u8[data_len] data        (the original envelope blob, untouched)
//! ```
//!
//! `envelope.schema_ver` must be >= 2 for Qallow to look at the payload
//! at all; `for_persist` sets it. Qallow's `ql_persist_get` returns only
//! `data`, so a reader (`qallow get`) sees exactly the bytes the producer
//! put in the envelope.
use ductei_core::{Envelope, Scope};

pub const PERSIST_VER: u16 = 2;
pub const PERSIST_HDR_LEN: usize = 24;
/// Envelope schema version that carries a persist-v2 payload.
pub const PERSIST_SCHEMA_VER: u16 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistPayload<'a> {
    pub scope_code: u16,
    pub session_id: u64,
    pub session_bound: u64,
    pub data: &'a [u8],
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Deterministic 16-bit code for a scope set, non-zero for any non-empty
/// set. An empty set (open/broadcast) yields 0 on purpose: zero is the
/// value Qallow rejects before write, so deny-by-default survives the
/// translation instead of being laundered into a "valid" code.
pub fn scope_code(scopes: &[Scope]) -> u16 {
    if scopes.is_empty() {
        return 0;
    }
    let mut names: Vec<&str> = scopes.iter().map(|s| s.0.as_str()).collect();
    names.sort_unstable();
    let h = fnv1a64(names.join(",").as_bytes());
    let folded = ((h >> 48) ^ (h >> 32) ^ (h >> 16) ^ h) as u16;
    if folded == 0 { 1 } else { folded }
}

/// Non-zero session id derived from the delivery identity
/// (node, key, lamport): stable across a relay restart that re-derives
/// the same delivery, distinct across deliveries.
pub fn session_id_for(node: &[u8; 16], key: &str, lamport: u64) -> u64 {
    let mut buf = Vec::with_capacity(16 + key.len() + 8);
    buf.extend_from_slice(node);
    buf.extend_from_slice(key.as_bytes());
    buf.extend_from_slice(&lamport.to_le_bytes());
    let h = fnv1a64(&buf);
    if h == 0 { 1 } else { h }
}

pub fn encode_persist_payload(scope_code: u16, session_id: u64, session_bound: u64, data: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(PERSIST_HDR_LEN + data.len());
    b.extend_from_slice(&PERSIST_VER.to_le_bytes());
    b.extend_from_slice(&scope_code.to_le_bytes());
    b.extend_from_slice(&session_id.to_le_bytes());
    b.extend_from_slice(&session_bound.to_le_bytes());
    b.extend_from_slice(&(data.len() as u32).to_le_bytes());
    b.extend_from_slice(data);
    b
}

pub fn decode_persist_payload(blob: &[u8]) -> Option<PersistPayload<'_>> {
    if blob.len() < PERSIST_HDR_LEN {
        return None;
    }
    let ver = u16::from_le_bytes(blob[0..2].try_into().ok()?);
    if ver != PERSIST_VER {
        return None;
    }
    let scope_code = u16::from_le_bytes(blob[2..4].try_into().ok()?);
    let session_id = u64::from_le_bytes(blob[4..12].try_into().ok()?);
    let session_bound = u64::from_le_bytes(blob[12..20].try_into().ok()?);
    let data_len = u32::from_le_bytes(blob[20..24].try_into().ok()?) as usize;
    if PERSIST_HDR_LEN + data_len != blob.len() {
        return None;
    }
    Some(PersistPayload { scope_code, session_id, session_bound, data: &blob[PERSIST_HDR_LEN..] })
}

/// Re-frames an already-accepted envelope for Qallow's persist gate:
/// schema_ver 2, blob wrapped in a persist-v2 header carrying the
/// bounded session that delivered it. Key, scopes, node and lamport are
/// untouched, so the causal gate and the wire key shim see the same
/// envelope identity as before.
pub fn for_persist(env: &Envelope, session_id: u64, session_bound: u64) -> Envelope {
    let mut out = env.clone();
    out.schema_ver = PERSIST_SCHEMA_VER;
    out.blob = encode_persist_payload(scope_code(&env.scopes), session_id, session_bound, &env.blob);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ductei_core::scoped;

    #[test]
    fn payload_roundtrips_and_is_layout_exact() {
        let p = encode_persist_payload(7, 123, 456, b"hello");
        assert_eq!(p.len(), PERSIST_HDR_LEN + 5);
        assert_eq!(&p[0..2], &2u16.to_le_bytes());
        assert_eq!(&p[2..4], &7u16.to_le_bytes());
        assert_eq!(&p[4..12], &123u64.to_le_bytes());
        assert_eq!(&p[12..20], &456u64.to_le_bytes());
        assert_eq!(&p[20..24], &5u32.to_le_bytes());
        let d = decode_persist_payload(&p).unwrap();
        assert_eq!(d, PersistPayload { scope_code: 7, session_id: 123, session_bound: 456, data: b"hello" });
    }

    #[test]
    fn length_mismatch_and_wrong_version_are_rejected() {
        let mut p = encode_persist_payload(1, 1, 1, b"ok");
        p.push(0);
        assert!(decode_persist_payload(&p).is_none());
        let mut q = encode_persist_payload(1, 1, 1, b"ok");
        q[0] = 1;
        assert!(decode_persist_payload(&q).is_none());
        assert!(decode_persist_payload(&[0u8; 10]).is_none());
    }

    #[test]
    fn scope_code_is_stable_order_independent_and_zero_only_for_open() {
        let a = scope_code(&[Scope("veyn.rem_event".into()), Scope("x.y".into())]);
        let b = scope_code(&[Scope("x.y".into()), Scope("veyn.rem_event".into())]);
        assert_eq!(a, b);
        assert_ne!(a, 0);
        assert_ne!(a, scope_code(&[Scope("qallow.semantic.cert".into())]));
        assert_eq!(scope_code(&[]), 0);
    }

    #[test]
    fn for_persist_keeps_identity_and_wraps_blob() {
        let env = scoped("limen.cert.j1", &["qallow.semantic.cert"], [9u8; 16], 42, b"{\"job_id\":\"j1\"}");
        let sid = session_id_for(&env.node_id, &env.key, env.lamport);
        assert_ne!(sid, 0);
        let p = for_persist(&env, sid, 1);
        assert_eq!(p.schema_ver, 2);
        assert_eq!(p.key, env.key);
        assert_eq!(p.scopes, env.scopes);
        assert_eq!(p.lamport, 42);
        let d = decode_persist_payload(&p.blob).unwrap();
        assert_eq!(d.session_id, sid);
        assert_eq!(d.session_bound, 1);
        assert_eq!(d.data, env.blob.as_slice());
        let frame = crate::encode_envelope(&p);
        let back = crate::decode_envelope_body(&frame[5..]).unwrap();
        assert_eq!(back.schema_ver, 2);
        assert_eq!(decode_persist_payload(&back.blob).unwrap().data, env.blob.as_slice());
    }
}
