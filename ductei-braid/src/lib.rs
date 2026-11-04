//! ductei-braid: three hash-chained, cross-anchored ledgers.
//!
//!   limen  : envelopes scoped or keyed "limen*"
//!   oneiro : envelopes scoped or keyed "oneiro*"
//!   atrium : everything else
//!
//! Hard invariants (checked by `verify`):
//! 1. Append-only: heights run 0,1,2,... and each block links `prev` to the
//!    BLAKE3 hash of the block before it.
//! 2. Every block's stored hash equals its recomputed digest.
//! 3. Every block anchors the current heads of the other two chains; an
//!    anchor must point at a block that still exists with that exact hash,
//!    and anchor heights never go backwards. Rewriting one chain therefore
//!    breaks the other two.
//! 4. No raw payload is stored: only BLAKE3(blob). Øneiro content never
//!    lands in the braid.
//!
//! Not covered (yet): signatures (QFLTL ML-DSA, next step) and truncation of
//! a chain's newest, not-yet-anchored tail (needs an external timestamp
//! anchor of the combined head).

/// Post-accept hook that feeds a `Channel` into the braid.
pub mod hook;

use ductei_core::Envelope;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

pub type Hash = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChainId {
    Limen,
    Oneiro,
    Atrium,
}

impl ChainId {
    pub const ALL: [ChainId; 3] = [ChainId::Limen, ChainId::Oneiro, ChainId::Atrium];

    fn tag(self) -> u8 {
        match self {
            ChainId::Limen => 0,
            ChainId::Oneiro => 1,
            ChainId::Atrium => 2,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            ChainId::Limen => "limen",
            ChainId::Oneiro => "oneiro",
            ChainId::Atrium => "atrium",
        }
    }

    pub fn others(self) -> [ChainId; 2] {
        match self {
            ChainId::Limen => [ChainId::Oneiro, ChainId::Atrium],
            ChainId::Oneiro => [ChainId::Limen, ChainId::Atrium],
            ChainId::Atrium => [ChainId::Limen, ChainId::Oneiro],
        }
    }

    /// Route an envelope by its scopes first, then its key.
    pub fn route(env: &Envelope) -> ChainId {
        let hit = |p: &str| {
            env.scopes.iter().any(|s| s.0.to_ascii_lowercase().starts_with(p))
                || env.key.to_ascii_lowercase().starts_with(p)
        };
        if hit("limen") {
            ChainId::Limen
        } else if hit("oneiro") || hit("øneiro") {
            ChainId::Oneiro
        } else {
            ChainId::Atrium
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Anchor {
    pub chain: ChainId,
    pub height: u64,
    #[serde(with = "hex32")]
    pub hash: Hash,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Block {
    pub chain: ChainId,
    pub height: u64,
    #[serde(with = "hex32")]
    pub prev: Hash,
    /// Heads of `chain.others()` at append time, in that order.
    pub anchors: [Option<Anchor>; 2],
    /// BLAKE3 of the envelope blob; the blob itself is never stored.
    #[serde(with = "hex32")]
    pub payload: Hash,
    pub lamport: u64,
    pub key: String,
    #[serde(with = "hex32")]
    pub hash: Hash,
}

/// Domain-separated digest of every field except `hash`.
fn digest(b: &Block) -> Hash {
    let mut h = blake3::Hasher::new();
    h.update(b"atrium-braid/v1");
    h.update(&[b.chain.tag()]);
    h.update(&b.height.to_le_bytes());
    h.update(&b.prev);
    for a in &b.anchors {
        match a {
            None => {
                h.update(&[0]);
            }
            Some(a) => {
                h.update(&[1, a.chain.tag()]);
                h.update(&a.height.to_le_bytes());
                h.update(&a.hash);
            }
        }
    }
    h.update(&b.payload);
    h.update(&b.lamport.to_le_bytes());
    h.update(&(b.key.len() as u64).to_le_bytes());
    h.update(b.key.as_bytes());
    *h.finalize().as_bytes()
}

#[derive(Debug, PartialEq)]
pub enum BraidError {
    Io(String),
    Corrupt { chain: ChainId, line: usize, why: String },
    Broken { chain: ChainId, height: u64, why: &'static str },
}

impl std::fmt::Display for BraidError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BraidError::Io(e) => write!(f, "io: {e}"),
            BraidError::Corrupt { chain, line, why } => {
                write!(f, "{} line {}: unreadable block ({why})", chain.name(), line + 1)
            }
            BraidError::Broken { chain, height, why } => {
                write!(f, "{} height {height}: {why}", chain.name())
            }
        }
    }
}

impl From<std::io::Error> for BraidError {
    fn from(e: std::io::Error) -> Self {
        BraidError::Io(e.to_string())
    }
}

pub fn chain_path(dir: &Path, c: ChainId) -> PathBuf {
    dir.join(format!("braid-{}.jsonl", c.name()))
}

/// Append-only braid over three fsynced JSONL files in one directory.
pub struct Braid {
    files: HashMap<ChainId, File>,
    heads: HashMap<ChainId, Anchor>,
}

impl Braid {
    /// Opens (or creates) the braid. Refuses to open a braid that fails
    /// `verify`, so a tampered history is never extended.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, BraidError> {
        let dir = dir.as_ref();
        std::fs::create_dir_all(dir)?;
        let heads = verify(dir)?;
        let mut files = HashMap::new();
        for c in ChainId::ALL {
            let f = OpenOptions::new().create(true).append(true).open(chain_path(dir, c))?;
            files.insert(c, f);
        }
        Ok(Self { files, heads })
    }

    /// Record an accepted DUCTEI envelope on its routed chain.
    pub fn record(&mut self, env: &Envelope) -> Result<Block, BraidError> {
        let chain = ChainId::route(env);
        self.append(chain, *blake3::hash(&env.blob).as_bytes(), env.lamport, &env.key)
    }

    pub fn append(
        &mut self,
        chain: ChainId,
        payload: Hash,
        lamport: u64,
        key: &str,
    ) -> Result<Block, BraidError> {
        let (height, prev) = match self.heads.get(&chain) {
            Some(a) => (a.height + 1, a.hash),
            None => (0, [0u8; 32]),
        };
        let o = chain.others();
        let mut b = Block {
            chain,
            height,
            prev,
            anchors: [self.heads.get(&o[0]).copied(), self.heads.get(&o[1]).copied()],
            payload,
            lamport,
            key: key.to_string(),
            hash: [0u8; 32],
        };
        b.hash = digest(&b);
        let line = serde_json::to_string(&b).map_err(|e| BraidError::Io(e.to_string()))?;
        let f = self.files.get_mut(&chain).expect("all three chains opened");
        writeln!(f, "{line}")?;
        f.sync_data()?;
        self.heads.insert(chain, Anchor { chain, height, hash: b.hash });
        Ok(b)
    }

    pub fn head(&self, c: ChainId) -> Option<Anchor> {
        self.heads.get(&c).copied()
    }

    /// One hash committing to all three heads: the value to timestamp
    /// externally (OpenTimestamps) for outside trust later.
    pub fn braid_root(&self) -> Hash {
        let mut h = blake3::Hasher::new();
        h.update(b"atrium-braid-root/v1");
        for c in ChainId::ALL {
            match self.heads.get(&c) {
                None => {
                    h.update(&[0]);
                }
                Some(a) => {
                    h.update(&[1]);
                    h.update(&a.height.to_le_bytes());
                    h.update(&a.hash);
                }
            }
        }
        *h.finalize().as_bytes()
    }
}

fn load(dir: &Path, c: ChainId) -> Result<Vec<Block>, BraidError> {
    let p = chain_path(dir, c);
    let mut v = Vec::new();
    if !p.exists() {
        return Ok(v);
    }
    for (i, line) in BufReader::new(File::open(p)?).lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let b: Block = serde_json::from_str(&line)
            .map_err(|e| BraidError::Corrupt { chain: c, line: i, why: e.to_string() })?;
        v.push(b);
    }
    Ok(v)
}

/// Walk all three chains and check every invariant. Returns the heads.
pub fn verify(dir: impl AsRef<Path>) -> Result<HashMap<ChainId, Anchor>, BraidError> {
    let dir = dir.as_ref();
    let mut chains = HashMap::new();
    for c in ChainId::ALL {
        chains.insert(c, load(dir, c)?);
    }
    let mut heads = HashMap::new();
    for c in ChainId::ALL {
        let mut prev = [0u8; 32];
        let mut last_anchor: [Option<u64>; 2] = [None, None];
        for (i, b) in chains[&c].iter().enumerate() {
            let h = i as u64;
            let broken = |why| BraidError::Broken { chain: c, height: h, why };
            if b.chain != c || b.height != h {
                return Err(broken("height or chain mismatch"));
            }
            if b.prev != prev {
                return Err(broken("prev link does not match previous block"));
            }
            if digest(b) != b.hash {
                return Err(broken("stored hash does not match contents"));
            }
            for (k, a) in b.anchors.iter().enumerate() {
                let want = c.others()[k];
                match a {
                    None if last_anchor[k].is_some() => return Err(broken("anchor dropped")),
                    None => {}
                    Some(a) => {
                        if a.chain != want {
                            return Err(broken("anchor names the wrong chain"));
                        }
                        match chains[&want].get(a.height as usize) {
                            Some(t) if t.hash == a.hash => {}
                            _ => return Err(broken("anchor points at a missing or rewritten block")),
                        }
                        if last_anchor[k].is_some_and(|p| a.height < p) {
                            return Err(broken("anchor went backwards"));
                        }
                        last_anchor[k] = Some(a.height);
                    }
                }
            }
            prev = b.hash;
        }
        if let Some(b) = chains[&c].last() {
            heads.insert(c, Anchor { chain: c, height: b.height, hash: b.hash });
        }
    }
    Ok(heads)
}

pub fn to_hex(h: &Hash) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}

mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(h: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&super::to_hex(h))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        if s.len() != 64 {
            return Err(serde::de::Error::custom("hash must be 64 hex chars"));
        }
        let mut o = [0u8; 32];
        for (i, b) in o.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(serde::de::Error::custom)?;
        }
        Ok(o)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ductei_core::scoped;

    fn tmp(tag: &str) -> PathBuf {
        let n = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let d = std::env::temp_dir().join(format!("braid-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn env(key: &str, scope: &str, l: u64) -> Envelope {
        scoped(key, &[scope], [0; 16], l, key.as_bytes())
    }

    #[test]
    fn routes_by_scope_and_key() {
        assert_eq!(ChainId::route(&env("x", "limen.compile", 1)), ChainId::Limen);
        assert_eq!(ChainId::route(&env("oneiro/rem", "dream", 1)), ChainId::Oneiro);
        assert_eq!(ChainId::route(&env("qallow.sync", "qallow", 1)), ChainId::Atrium);
    }

    #[test]
    fn appends_verify_and_survive_reopen() {
        let d = tmp("reopen");
        {
            let mut b = Braid::open(&d).unwrap();
            b.record(&env("a", "limen", 1)).unwrap();
            b.record(&env("b", "oneiro", 2)).unwrap();
            let blk = b.record(&env("c", "atrium", 3)).unwrap();
            assert!(blk.anchors.iter().all(|a| a.is_some()));
        }
        let mut b = Braid::open(&d).unwrap();
        let blk = b.record(&env("d", "limen", 4)).unwrap();
        assert_eq!(blk.height, 1);
        assert_eq!(verify(&d).unwrap().len(), 3);
    }

    #[test]
    fn edited_block_is_caught() {
        let d = tmp("edit");
        let mut b = Braid::open(&d).unwrap();
        b.record(&env("a", "limen", 1)).unwrap();
        drop(b);
        let p = chain_path(&d, ChainId::Limen);
        let s = std::fs::read_to_string(&p).unwrap().replace("\"lamport\":1", "\"lamport\":9");
        std::fs::write(&p, s).unwrap();
        assert!(matches!(verify(&d), Err(BraidError::Broken { chain: ChainId::Limen, .. })));
        assert!(Braid::open(&d).is_err(), "must refuse to extend tampered history");
    }

    #[test]
    fn consistent_rewrite_is_caught_by_other_chain() {
        let d = tmp("rewrite");
        let mut b = Braid::open(&d).unwrap();
        b.record(&env("a", "limen", 1)).unwrap();
        b.record(&env("b", "atrium", 2)).unwrap(); // anchors limen #0
        drop(b);
        // Forge limen #0 with a valid self-hash: limen alone looks fine.
        let p = chain_path(&d, ChainId::Limen);
        let mut blk: Block = serde_json::from_str(std::fs::read_to_string(&p).unwrap().trim()).unwrap();
        blk.payload = [7; 32];
        blk.hash = digest(&blk);
        std::fs::write(&p, format!("{}\n", serde_json::to_string(&blk).unwrap())).unwrap();
        assert_eq!(
            verify(&d),
            Err(BraidError::Broken { chain: ChainId::Atrium, height: 0, why: "anchor points at a missing or rewritten block" })
        );
    }

    #[test]
    fn hash_round_trips_through_json() {
        let d = tmp("json");
        let mut b = Braid::open(&d).unwrap();
        let blk = b.record(&env("a", "limen", 1)).unwrap();
        let back: Block = serde_json::from_str(&serde_json::to_string(&blk).unwrap()).unwrap();
        assert_eq!(back, blk);
        assert_eq!(digest(&back), back.hash);
    }
}
