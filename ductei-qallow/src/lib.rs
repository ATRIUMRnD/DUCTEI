//! Qallow adapter: Envelope <-> QSW proto v1 bytes. Pure Rust, byte-
//! compatible with Qallow's sync_wire.c (hand-rolled LE, length-prefixed).
//! Frame: u8 type | u32 body_len | body.
//! Scopes ride as a key prefix shim ("scope0,scope1|key") until QSW v2
//! makes them a native wire field.
use ductei_core::{Envelope, Scope};

pub mod ingest;
pub mod persist;
pub mod v2;

pub const QSW_MAGIC: u32 = 0x4E595351;
pub const QSW_PROTO_VER: u16 = 1;
pub const F_HELLO: u8 = 1;
pub const F_HELLO_ACK: u8 = 2;
pub const F_ENVELOPE: u8 = 3;
pub const F_BATCH_END: u8 = 4;
pub const F_BYE: u8 = 5;

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
    put_u32(&mut b, QSW_MAGIC);
    put_u16(&mut b, QSW_PROTO_VER);
    put_u16(&mut b, 0); // caps
    b.extend_from_slice(node_id);
    put_u64(&mut b, lamport);
    frame(t, &b)
}

pub fn encode_batch_end(lamport: u64) -> Vec<u8> {
    let mut b = Vec::new();
    put_u64(&mut b, lamport);
    frame(F_BATCH_END, &b)
}

pub fn encode_bye() -> Vec<u8> { frame(F_BYE, &[]) }

/// Envelope -> QSW ENVELOPE frame. Body layout mirrors qsw_envelope:
/// node_id[16] | u64 lamport | u16 schema_ver | u16 flags |
/// u32 key_len | u32 blob_len | key | blob
pub fn encode_envelope(env: &Envelope) -> Vec<u8> {
    let mut scopes: Vec<&str> = env.scopes.iter().map(|s| s.0.as_str()).collect();
    scopes.sort_unstable();
    let key = format!("{}|{}", scopes.join(","), env.key);
    let mut b = Vec::new();
    b.extend_from_slice(&env.node_id);
    put_u64(&mut b, env.lamport);
    put_u16(&mut b, env.schema_ver);
    put_u16(&mut b, env.flags);
    put_u32(&mut b, key.len() as u32);
    put_u32(&mut b, env.blob.len() as u32);
    b.extend_from_slice(key.as_bytes());
    b.extend_from_slice(&env.blob);
    frame(F_ENVELOPE, &b)
}

/// QSW ENVELOPE body -> Envelope (splits the scope shim back out).
pub fn decode_envelope_body(b: &[u8]) -> Option<Envelope> {
    if b.len() < 36 { return None; }
    let mut node_id = [0u8; 16];
    node_id.copy_from_slice(&b[0..16]);
    let lamport = u64::from_le_bytes(b[16..24].try_into().ok()?);
    let schema_ver = u16::from_le_bytes(b[24..26].try_into().ok()?);
    let flags = u16::from_le_bytes(b[26..28].try_into().ok()?);
    let key_len = u32::from_le_bytes(b[28..32].try_into().ok()?) as usize;
    let blob_len = u32::from_le_bytes(b[32..36].try_into().ok()?) as usize;
    if b.len() != 36 + key_len + blob_len { return None; }
    let raw_key = std::str::from_utf8(&b[36..36 + key_len]).ok()?;
    let (scope_part, key) = raw_key.split_once('|')?;
    let scopes = scope_part.split(',').filter(|s| !s.is_empty()).map(|s| Scope(s.into())).collect();
    Some(Envelope {
        node_id, lamport, schema_ver, flags,
        key: key.into(), scopes,
        blob: b[36 + key_len..].to_vec(),
    })
}
