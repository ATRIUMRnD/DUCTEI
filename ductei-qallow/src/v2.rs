//! QSW proto v2: scopes as a native wire field instead of the v1
//! key-prefix shim. Frame layout unchanged (u8 type | u32 body_len | body);
//! only the ENVELOPE body layout changes. Lives alongside v1 unchanged:
//! v1 stays byte-compatible with Qallow's real sync_wire.c and keeps
//! passing the conformance oracle. v2 is opt-in via HELLO proto_ver=2.
//! The C counterpart (`qsw_decode_v2`, `qsw_v2_merge_key`) landed in
//! Qallow#17 (ATRIUM harness-roadmap/05). Merge-key parity rebuilds the
//! v1 "scopes|key" shim so ingest lands under one LMDB key either way.
use ductei_core::{Envelope, Scope};

pub const QSW_PROTO_VER: u16 = 2;

fn put_u16(v: &mut Vec<u8>, x: u16) { v.extend_from_slice(&x.to_le_bytes()); }
fn put_u32(v: &mut Vec<u8>, x: u32) { v.extend_from_slice(&x.to_le_bytes()); }
fn put_u64(v: &mut Vec<u8>, x: u64) { v.extend_from_slice(&x.to_le_bytes()); }

fn frame(t: u8, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(5 + body.len());
    v.push(t);
    put_u32(&mut v, body.len() as u32);
    v.extend_from_slice(body);
    v
}

pub fn encode_hello(t: u8, node_id: &[u8; 16], lamport: u64) -> Vec<u8> {
    let mut b = Vec::new();
    put_u32(&mut b, crate::QSW_MAGIC);
    put_u16(&mut b, QSW_PROTO_VER);
    put_u16(&mut b, 0); // caps
    b.extend_from_slice(node_id);
    put_u64(&mut b, lamport);
    frame(t, &b)
}

/// Envelope -> QSW v2 ENVELOPE frame. Body layout:
/// node_id[16] | u64 lamport | u16 schema_ver | u16 flags |
/// u16 scope_count | (u16 scope_len | scope bytes){scope_count} |
/// u32 key_len | u32 blob_len | key | blob
pub fn encode_envelope(env: &Envelope) -> Vec<u8> {
    let mut scopes: Vec<&str> = env.scopes.iter().map(|s| s.0.as_str()).collect();
    scopes.sort_unstable();
    let mut b = Vec::new();
    b.extend_from_slice(&env.node_id);
    put_u64(&mut b, env.lamport);
    put_u16(&mut b, env.schema_ver);
    put_u16(&mut b, env.flags);
    put_u16(&mut b, scopes.len() as u16);
    for s in &scopes {
        put_u16(&mut b, s.len() as u16);
        b.extend_from_slice(s.as_bytes());
    }
    put_u32(&mut b, env.key.len() as u32);
    put_u32(&mut b, env.blob.len() as u32);
    b.extend_from_slice(env.key.as_bytes());
    b.extend_from_slice(&env.blob);
    frame(crate::F_ENVELOPE, &b)
}

/// QSW v2 ENVELOPE body -> Envelope. Native scope field, no shim parsing.
pub fn decode_envelope_body(b: &[u8]) -> Option<Envelope> {
    if b.len() < 30 { return None; }
    let mut node_id = [0u8; 16];
    node_id.copy_from_slice(&b[0..16]);
    let lamport = u64::from_le_bytes(b[16..24].try_into().ok()?);
    let schema_ver = u16::from_le_bytes(b[24..26].try_into().ok()?);
    let flags = u16::from_le_bytes(b[26..28].try_into().ok()?);
    let scope_count = u16::from_le_bytes(b[28..30].try_into().ok()?) as usize;

    let mut pos = 30;
    let mut scopes = Vec::with_capacity(scope_count);
    for _ in 0..scope_count {
        if b.len() < pos + 2 { return None; }
        let len = u16::from_le_bytes(b[pos..pos + 2].try_into().ok()?) as usize;
        pos += 2;
        if b.len() < pos + len { return None; }
        scopes.push(Scope(std::str::from_utf8(&b[pos..pos + len]).ok()?.into()));
        pos += len;
    }

    if b.len() < pos + 8 { return None; }
    let key_len = u32::from_le_bytes(b[pos..pos + 4].try_into().ok()?) as usize;
    let blob_len = u32::from_le_bytes(b[pos + 4..pos + 8].try_into().ok()?) as usize;
    pos += 8;
    if b.len() != pos + key_len + blob_len { return None; }
    let key = std::str::from_utf8(&b[pos..pos + key_len]).ok()?.into();
    let blob = b[pos + key_len..].to_vec();

    Some(Envelope { node_id, lamport, schema_ver, flags, key, scopes, blob })
}

/// Rebuild the v1 merge key from a v2 envelope: scopes sorted bytewise,
/// joined with ",", then "|" + key. Delegates to `v1_shim_key` so the
/// string is identical to what v1's encoder writes on the wire (the
/// byte-level oracle) and to what Qallow's `qsw_v2_merge_key` produces.
pub fn merge_key(env: &Envelope) -> String {
    crate::v1_shim_key(env)
}
