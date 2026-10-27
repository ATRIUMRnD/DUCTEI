//! qsw-inspect: field-level decoder and differ for QSW (Qallow Sync Wire)
//! streams. Walks `u8 type | u32 body_len | body` frames, labels every byte
//! with the field it belongs to, and cross-checks each ENVELOPE body against
//! the real `ductei_qallow` decoder (v1 or v2), so the inspector never
//! becomes a second, drifting source of truth for the layout.
use ductei_qallow::{F_BATCH_END, F_BYE, F_ENVELOPE, F_HELLO, F_HELLO_ACK, QSW_MAGIC};
use serde::Serialize;

pub const HEADER_LEN: usize = 5;
pub const HELLO_BODY_LEN: usize = 32;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Field {
    pub name: String,
    /// Absolute byte offset in the stream.
    pub offset: usize,
    pub len: usize,
    /// Raw bytes as hex (first 64 bytes).
    pub bytes: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Frame {
    pub index: usize,
    pub offset: usize,
    pub ftype: u8,
    pub type_name: &'static str,
    pub body_len: u32,
    /// Proto version used to read this frame (from HELLO or --proto).
    pub proto: u16,
    pub fields: Vec<Field>,
    /// ENVELOPE only: did the real ductei_qallow decoder accept the body?
    pub decoder_accepts: Option<bool>,
    pub problems: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub total_bytes: usize,
    pub frames: Vec<Frame>,
    /// Bytes after the last complete frame that do not form a header.
    pub trailing: Option<String>,
}

impl Report {
    pub fn ok(&self) -> bool {
        self.trailing.is_none() && self.frames.iter().all(|f| f.problems.is_empty())
    }

    /// Field (and its frame) covering absolute byte `off`.
    pub fn locate(&self, off: usize) -> Option<(&Frame, &Field)> {
        self.frames.iter().find_map(|fr| {
            fr.fields
                .iter()
                .find(|f| off >= f.offset && off < f.offset + f.len.max(1))
                .map(|f| (fr, f))
        })
    }
}

pub fn type_name(t: u8) -> &'static str {
    match t {
        F_HELLO => "HELLO",
        F_HELLO_ACK => "HELLO_ACK",
        F_ENVELOPE => "ENVELOPE",
        F_BATCH_END => "BATCH_END",
        F_BYE => "BYE",
        _ => "UNKNOWN",
    }
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(" ")
}

fn hex_capped(b: &[u8], cap: usize) -> String {
    if b.len() <= cap {
        hex(b)
    } else {
        format!("{} .. (+{} bytes)", hex(&b[..cap]), b.len() - cap)
    }
}

/// Printable UTF-8 shows as a quoted string, anything else as hex.
fn show_bytes(b: &[u8]) -> String {
    match std::str::from_utf8(b) {
        Ok(s) if s.chars().all(|c| !c.is_control()) => format!("{s:?}"),
        _ => format!("<binary> {}", hex_capped(b, 32)),
    }
}

struct Cur<'a> {
    b: &'a [u8],
    base: usize,
    pos: usize,
    fields: Vec<Field>,
}

impl<'a> Cur<'a> {
    fn take(&mut self, name: &str, n: usize, fmt: impl Fn(&[u8]) -> String) -> Result<&'a [u8], String> {
        let left = self.b.len() - self.pos;
        if n > left {
            return Err(format!(
                "{name}: needs {n} byte(s) at stream 0x{:X}, only {left} left in body",
                self.base + self.pos
            ));
        }
        let b = self.b;
        let s = &b[self.pos..self.pos + n];
        self.fields.push(Field {
            name: name.into(),
            offset: self.base + self.pos,
            len: n,
            bytes: hex_capped(s, 64),
            value: fmt(s),
        });
        self.pos += n;
        Ok(s)
    }
    fn u16(&mut self, name: &str) -> Result<u16, String> {
        let s = self.take(name, 2, |s| u16::from_le_bytes([s[0], s[1]]).to_string())?;
        Ok(u16::from_le_bytes([s[0], s[1]]))
    }
    fn u16_hex(&mut self, name: &str) -> Result<u16, String> {
        let s = self.take(name, 2, |s| format!("0x{:04X}", u16::from_le_bytes([s[0], s[1]])))?;
        Ok(u16::from_le_bytes([s[0], s[1]]))
    }
    fn u32(&mut self, name: &str) -> Result<u32, String> {
        let s = self.take(name, 4, |s| u32::from_le_bytes(s.try_into().unwrap()).to_string())?;
        Ok(u32::from_le_bytes(s.try_into().unwrap()))
    }
    fn u64(&mut self, name: &str) -> Result<u64, String> {
        let s = self.take(name, 8, |s| u64::from_le_bytes(s.try_into().unwrap()).to_string())?;
        Ok(u64::from_le_bytes(s.try_into().unwrap()))
    }
    fn node_id(&mut self) -> Result<(), String> {
        self.take("node_id", 16, |s| s.iter().map(|x| format!("{x:02x}")).collect())
            .map(|_| ())
    }
    fn left(&self) -> usize {
        self.b.len() - self.pos
    }
}

fn parse_hello(c: &mut Cur, proto: &mut u16, pinned: bool, problems: &mut Vec<String>) -> Result<(), String> {
    let magic = {
        let s = c.take("magic", 4, |s| {
            let v = u32::from_le_bytes(s.try_into().unwrap());
            let ascii: String = s.iter().map(|&x| if x.is_ascii_graphic() { x as char } else { '.' }).collect();
            format!("0x{v:08X} \"{ascii}\"")
        })?;
        u32::from_le_bytes(s.try_into().unwrap())
    };
    if magic != QSW_MAGIC {
        problems.push(format!("bad magic 0x{magic:08X}, expected 0x{QSW_MAGIC:08X} \"QSYN\""));
    }
    let ver = c.u16("proto_ver")?;
    match ver {
        1 | 2 if !pinned => *proto = ver,
        1 | 2 => {
            if ver != *proto {
                problems.push(format!("HELLO says proto v{ver} but --proto pinned v{}", *proto));
            }
        }
        _ => problems.push(format!("unknown proto_ver {ver} (known: 1, 2)")),
    }
    c.u16_hex("caps")?;
    c.node_id()?;
    c.u64("lamport")?;
    Ok(())
}

fn parse_envelope(c: &mut Cur, proto: u16, problems: &mut Vec<String>) -> Result<(), String> {
    c.node_id()?;
    c.u64("lamport")?;
    c.u16("schema_ver")?;
    c.u16_hex("flags")?;
    if proto == 2 {
        let n = c.u16("scope_count")?;
        for i in 0..n {
            let len = c.u16(&format!("scope[{i}].len"))? as usize;
            c.take(&format!("scope[{i}]"), len, show_bytes)?;
        }
    }
    let key_len = c.u32("key_len")? as usize;
    let blob_len = c.u32("blob_len")? as usize;
    let left = c.left();
    if key_len + blob_len != left {
        problems.push(format!(
            "length mismatch: key_len {key_len} + blob_len {blob_len} = {}, body has {left} byte(s) left",
            key_len + blob_len
        ));
    }
    let key = c.take("key", key_len, |s| {
        let shown = show_bytes(s);
        if proto == 1 {
            if let Ok(k) = std::str::from_utf8(s) {
                if let Some((sc, key)) = k.split_once('|') {
                    return format!("{shown}  (shim: scopes=[{sc}] key={key:?})");
                }
            }
        }
        shown
    })?;
    if proto == 1 {
        match std::str::from_utf8(key) {
            Err(_) => problems.push("v1 key is not valid UTF-8".into()),
            Ok(k) if !k.contains('|') => {
                problems.push("v1 key has no scope shim separator '|' (\"scopes|key\")".into())
            }
            _ => {}
        }
    }
    c.take("blob", blob_len, show_bytes)?;
    Ok(())
}

/// Decode a whole stream. `proto_pin` forces v1/v2 for ENVELOPE bodies;
/// otherwise the proto follows the latest HELLO/HELLO_ACK (default v1).
pub fn inspect(buf: &[u8], proto_pin: Option<u16>) -> Report {
    let mut frames = Vec::new();
    let mut proto = proto_pin.unwrap_or(1);
    let mut off = 0usize;
    let mut trailing = None;

    while off < buf.len() {
        let rem = buf.len() - off;
        if rem < HEADER_LEN {
            trailing = Some(format!(
                "{rem} byte(s) at 0x{off:X} [{}] are too short for a 5-byte frame header (truncated capture?)",
                hex(&buf[off..])
            ));
            break;
        }
        let t = buf[off];
        let body_len = u32::from_le_bytes(buf[off + 1..off + 5].try_into().unwrap());
        let mut fields = vec![
            Field { name: "type".into(), offset: off, len: 1, bytes: hex(&buf[off..off + 1]), value: format!("{t} ({})", type_name(t)) },
            Field { name: "body_len".into(), offset: off + 1, len: 4, bytes: hex(&buf[off + 1..off + 5]), value: body_len.to_string() },
        ];
        let mut problems = Vec::new();
        let body_start = off + HEADER_LEN;
        let avail = rem - HEADER_LEN;
        if body_len as usize > avail {
            problems.push(format!(
                "truncated: body_len {body_len} but only {avail} byte(s) remain ({} missing)",
                body_len as usize - avail
            ));
            if avail > 0 {
                fields.push(Field { name: "partial_body".into(), offset: body_start, len: avail, bytes: hex_capped(&buf[body_start..], 64), value: String::new() });
            }
            frames.push(Frame { index: frames.len(), offset: off, ftype: t, type_name: type_name(t), body_len, proto, fields, decoder_accepts: None, problems });
            break;
        }
        let body = &buf[body_start..body_start + body_len as usize];
        let mut c = Cur { b: body, base: body_start, pos: 0, fields: Vec::new() };
        let mut decoder_accepts = None;
        let parsed = match t {
            F_HELLO | F_HELLO_ACK => {
                if body.len() != HELLO_BODY_LEN {
                    problems.push(format!("HELLO body is {} byte(s), expected {HELLO_BODY_LEN}", body.len()));
                }
                parse_hello(&mut c, &mut proto, proto_pin.is_some(), &mut problems)
            }
            F_ENVELOPE => {
                let r = parse_envelope(&mut c, proto, &mut problems);
                if let Err(e) = &r {
                    problems.push(e.clone());
                }
                let accepted = if proto == 2 {
                    ductei_qallow::v2::decode_envelope_body(body).is_some()
                } else {
                    ductei_qallow::decode_envelope_body(body).is_some()
                };
                decoder_accepts = Some(accepted);
                let clean = r.is_ok() && problems.is_empty();
                if !accepted {
                    problems.push(format!("ductei_qallow v{proto} decoder REJECTS this body"));
                } else if !clean {
                    problems.push("inspector found problems the decoder accepted (inspector/decoder disagree)".into());
                }
                Ok(())
            }
            F_BATCH_END => c.u64("lamport").map(|_| ()),
            F_BYE => Ok(()),
            _ => {
                problems.push(format!("unknown frame type {t} (known: 1-5)"));
                c.take("body", body.len(), |s| hex_capped(s, 32)).map(|_| ())
            }
        };
        if let Err(e) = parsed {
            problems.push(e);
        }
        if c.left() > 0 {
            let n = c.left();
            problems.push(format!("{n} unparsed byte(s) at end of body"));
            let _ = c.take("unparsed", n, |s| hex_capped(s, 32));
        }
        fields.extend(c.fields);
        frames.push(Frame { index: frames.len(), offset: off, ftype: t, type_name: type_name(t), body_len, proto, fields, decoder_accepts, problems });
        off = body_start + body_len as usize;
    }

    Report { total_bytes: buf.len(), frames, trailing }
}

#[derive(Debug, Clone, Serialize)]
pub struct Side {
    pub frame: Option<usize>,
    pub frame_type: Option<&'static str>,
    pub field: Option<String>,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiffResult {
    pub identical: bool,
    pub len_a: usize,
    pub len_b: usize,
    pub frames_a: usize,
    pub frames_b: usize,
    /// First differing absolute byte offset (or the shorter length).
    pub first_diff: Option<usize>,
    /// Differing bytes over the common prefix length.
    pub differing_bytes: usize,
    pub a: Option<Side>,
    pub b: Option<Side>,
}

fn side(r: &Report, off: usize) -> Side {
    match r.locate(off) {
        Some((fr, f)) => Side { frame: Some(fr.index), frame_type: Some(fr.type_name), field: Some(f.name.clone()), value: Some(f.value.clone()) },
        None => Side { frame: None, frame_type: None, field: None, value: None },
    }
}

pub fn diff(a: &[u8], b: &[u8], proto_pin: Option<u16>) -> (DiffResult, Report, Report) {
    let ra = inspect(a, proto_pin);
    let rb = inspect(b, proto_pin);
    let common = a.len().min(b.len());
    let differing_bytes = (0..common).filter(|&i| a[i] != b[i]).count();
    let first_diff = (0..common).find(|&i| a[i] != b[i]).or(if a.len() != b.len() { Some(common) } else { None });
    let identical = first_diff.is_none();
    let res = DiffResult {
        identical,
        len_a: a.len(),
        len_b: b.len(),
        frames_a: ra.frames.len(),
        frames_b: rb.frames.len(),
        first_diff,
        differing_bytes,
        a: first_diff.map(|d| side(&ra, d)),
        b: first_diff.map(|d| side(&rb, d)),
    };
    (res, ra, rb)
}

/// Input text formats. `Auto` sniffs file contents: only 0/1 (plus
/// separators) -> bits, only hex digits -> hex, anything else -> raw.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Fmt {
    Auto,
    Raw,
    Hex,
    Bits,
}

fn is_sep(c: char) -> bool {
    c.is_whitespace() || c == ',' || c == '_' || c == ':' || c == '-'
}

fn strip_prefixes(s: &str, p: &str) -> String {
    s.split(|c: char| c.is_whitespace() || c == ',')
        .map(|tok| tok.strip_prefix(p).or_else(|| tok.strip_prefix(&p.to_uppercase())).unwrap_or(tok))
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn parse_bits(s: &str) -> Result<Vec<u8>, String> {
    let s = strip_prefixes(s, "0b");
    let mut bits = Vec::new();
    for c in s.chars() {
        match c {
            '0' => bits.push(0u8),
            '1' => bits.push(1u8),
            c if is_sep(c) => {}
            c => return Err(format!("bits input: unexpected character {c:?}")),
        }
    }
    if !bits.len().is_multiple_of(8) {
        return Err(format!("bits input: {} bits is not a multiple of 8 ({} extra)", bits.len(), bits.len() % 8));
    }
    Ok(bits.chunks(8).map(|ch| ch.iter().fold(0u8, |acc, &b| (acc << 1) | b)).collect())
}

pub fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = strip_prefixes(s, "0x");
    let digits: Vec<char> = s.chars().filter(|c| !is_sep(*c)).collect();
    if let Some(bad) = digits.iter().find(|c| !c.is_ascii_hexdigit()) {
        return Err(format!("hex input: unexpected character {bad:?}"));
    }
    if !digits.len().is_multiple_of(2) {
        return Err(format!("hex input: odd number of hex digits ({})", digits.len()));
    }
    Ok(digits
        .chunks(2)
        .map(|p| u8::from_str_radix(&p.iter().collect::<String>(), 16).unwrap())
        .collect())
}

/// Turn raw file/stdin/--str bytes into stream bytes. Returns the format used.
pub fn load(data: &[u8], fmt: Fmt) -> Result<(Vec<u8>, Fmt), String> {
    let text = || std::str::from_utf8(data).map_err(|_| "input is not text; use --format raw".to_string());
    match fmt {
        Fmt::Raw => Ok((data.to_vec(), Fmt::Raw)),
        Fmt::Bits => Ok((parse_bits(text()?)?, Fmt::Bits)),
        Fmt::Hex => Ok((parse_hex(text()?)?, Fmt::Hex)),
        Fmt::Auto => {
            let Ok(t) = std::str::from_utf8(data) else { return Ok((data.to_vec(), Fmt::Raw)) };
            if t.trim().is_empty() {
                return Ok((data.to_vec(), Fmt::Raw));
            }
            if let Ok(v) = parse_bits(t) {
                return Ok((v, Fmt::Bits));
            }
            if let Ok(v) = parse_hex(t) {
                return Ok((v, Fmt::Hex));
            }
            Ok((data.to_vec(), Fmt::Raw))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ductei_core::scoped;

    const NODE: [u8; 16] = [7u8; 16];

    /// Same stream the conformance emitter writes (conformance/emitter).
    fn stream(v2: bool) -> Vec<u8> {
        let mut out = Vec::new();
        if v2 {
            let env = scoped("limen.cert.j1", &["qallow.semantic.cert", "veyn,x"], NODE, 42, br#"{"tier":2}"#);
            out.extend(ductei_qallow::v2::encode_hello(F_HELLO, &NODE, 41));
            out.extend(ductei_qallow::v2::encode_hello(F_HELLO_ACK, &NODE, 41));
            out.extend(ductei_qallow::v2::encode_envelope(&env));
        } else {
            let env = scoped("limen.cert.j1", &["qallow.semantic.cert"], NODE, 42, br#"{"tier":2}"#);
            out.extend(ductei_qallow::encode_hello(F_HELLO, &NODE, 41));
            out.extend(ductei_qallow::encode_hello(F_HELLO_ACK, &NODE, 41));
            out.extend(ductei_qallow::encode_envelope(&env));
        }
        out.extend(ductei_qallow::encode_batch_end(43));
        out.extend(ductei_qallow::encode_bye());
        out
    }

    fn val<'a>(fr: &'a Frame, name: &str) -> &'a str {
        &fr.fields.iter().find(|f| f.name == name).unwrap().value
    }

    #[test]
    fn v1_stream_decodes_clean_and_decoder_agrees() {
        let r = inspect(&stream(false), None);
        assert!(r.ok(), "{r:#?}");
        let types: Vec<_> = r.frames.iter().map(|f| f.type_name).collect();
        assert_eq!(types, ["HELLO", "HELLO_ACK", "ENVELOPE", "BATCH_END", "BYE"]);
        let env = &r.frames[2];
        assert_eq!(env.decoder_accepts, Some(true));
        assert_eq!(val(env, "lamport"), "42");
        assert!(val(env, "key").contains("key=\"limen.cert.j1\""));
        assert!(val(&r.frames[0], "magic").contains("QSYN"));
        // every byte is covered by exactly one field
        let covered: usize = r.frames.iter().flat_map(|f| &f.fields).map(|f| f.len).sum();
        assert_eq!(covered, r.total_bytes);
    }

    #[test]
    fn v2_follows_hello_and_reads_native_scopes() {
        let r = inspect(&stream(true), None);
        assert!(r.ok(), "{r:#?}");
        let env = &r.frames[2];
        assert_eq!(env.proto, 2);
        assert_eq!(env.decoder_accepts, Some(true));
        assert_eq!(val(env, "scope_count"), "2");
        assert_eq!(val(env, "scope[1]"), "\"veyn,x\"");
    }

    #[test]
    fn wrong_proto_pin_is_flagged() {
        let r = inspect(&stream(true), Some(1));
        assert!(!r.ok());
        assert!(r.frames[2].problems.iter().any(|p| p.contains("REJECTS")));
    }

    #[test]
    fn truncation_is_reported_not_panicked() {
        let s = stream(false);
        for cut in 0..s.len() {
            let r = inspect(&s[..cut], None);
            if cut > 0 && cut < s.len() {
                let _ = r.ok(); // must not panic at any cut point
            }
        }
        let r = inspect(&s[..s.len() - 7], None); // drop BYE (5) + 2 bytes of BATCH_END body
        assert!(!r.ok());
        assert!(r.frames.last().unwrap().problems[0].starts_with("truncated"));
        let r = inspect(&s[..2], None);
        assert!(r.trailing.is_some());
    }

    #[test]
    fn corrupt_length_is_caught() {
        let mut s = stream(false);
        let env_off = inspect(&s, None).frames[2].offset;
        // key_len lives at body+28 in v1
        s[env_off + HEADER_LEN + 28] += 1;
        let r = inspect(&s, None);
        let env = &r.frames[2];
        assert_eq!(env.decoder_accepts, Some(false));
        assert!(env.problems.iter().any(|p| p.contains("length mismatch")));
    }

    #[test]
    fn diff_names_the_field() {
        let a = stream(false);
        let mut b = a.clone();
        let r = inspect(&a, None);
        let lam = r.frames[2].fields.iter().find(|f| f.name == "lamport").unwrap().offset;
        b[lam] = 43;
        let (d, _, _) = diff(&a, &b, None);
        assert!(!d.identical);
        assert_eq!(d.first_diff, Some(lam));
        assert_eq!(d.differing_bytes, 1);
        let sa = d.a.unwrap();
        assert_eq!(sa.frame_type, Some("ENVELOPE"));
        assert_eq!(sa.field.as_deref(), Some("lamport"));
        assert_eq!(d.b.unwrap().value.as_deref(), Some("43"));
        assert!(diff(&a, &a, None).0.identical);
    }

    #[test]
    fn diff_v1_vs_v2_points_at_proto_ver() {
        let (d, _, _) = diff(&stream(false), &stream(true), None);
        assert_eq!(d.a.unwrap().field.as_deref(), Some("proto_ver"));
    }

    #[test]
    fn bits_and_hex_inputs_roundtrip() {
        let s = stream(false);
        let bits: String = s.iter().map(|b| format!("{b:08b} ")).collect();
        let hexs = hex(&s);
        assert_eq!(load(bits.as_bytes(), Fmt::Auto).unwrap(), (s.clone(), Fmt::Bits));
        assert_eq!(load(hexs.as_bytes(), Fmt::Auto).unwrap(), (s.clone(), Fmt::Hex));
        assert_eq!(load(&s, Fmt::Auto).unwrap().1, Fmt::Raw);
        assert_eq!(parse_bits("0b01001000, 0b01101001").unwrap(), b"Hi");
        assert_eq!(parse_hex("0x51 0x53").unwrap(), [0x51, 0x53]);
        assert!(parse_bits("0100100").is_err());
        assert!(parse_hex("abc").is_err());
    }
}
