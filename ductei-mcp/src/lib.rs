//! ductei-mcp: put a DUCTEI channel between an MCP client and an MCP server.
//!
//! Every `tools/call` becomes a scoped Envelope (`mcp:{server}:{tool}`) that
//! must pass the deny-by-default ScopePolicy and land in the fsynced channel
//! log *before* it is forwarded; every result lands the same way *before* it
//! is returned. Each call/result pair then gets a hash-chained receipt
//! (optionally ML-DSA signed) in receipts.jsonl. Denied calls never reach
//! the server and are recorded in denied.jsonl plus a receipt with
//! verdict = "denied", so the timeline records refusals too.
//!
//! `tools/list` answers are filtered to the allowlist, so the client never
//! sees a tool it cannot call (and cannot burn the session budget on it).
//!
//! Receipt format v1: `v`, `kid` (SHA-256 of the signing public key, "" when
//! unsigned) and a domain-separated signature over the raw hash bytes. The
//! verifier takes its public key from the caller (pinned), not from the log
//! directory, so whoever can write the log directory cannot re-key history.
//!
//! Invariants carried over from ductei-core: deny-by-default scopes,
//! persistence-before-ack, bounded sessions, no credentials in envelopes
//! (the gate never sees the server's keys; it only relays JSON-RPC lines).
use ductei_core::{scoped, Channel, ChannelError, Envelope, LogStore, ScopePolicy};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------- config

#[derive(Debug, Deserialize)]
pub struct Config {
    pub server: ServerCfg,
    pub policy: PolicyCfg,
    #[serde(default)]
    pub log: LogCfg,
    #[serde(default)]
    pub sign: SignCfg,
    #[serde(default)]
    pub anchor: AnchorCfg,
}

/// Chain-head anchoring: every N receipts the gate signs `(seq, head)` and
/// pushes it to DUCTEI peers over TCP. A peer that holds a later anchor than
/// the local receipts.jsonl shows is proof the local file was truncated.
#[derive(Debug, Deserialize, Clone)]
pub struct AnchorCfg {
    /// Anchor every N receipts. 0 = off.
    #[serde(default)]
    pub every: u64,
    /// DUCTEI TCP peers (host:port). Each must allow scope `mcp:{server}:anchor`.
    #[serde(default)]
    pub peers: Vec<String>,
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
}
fn default_connect_timeout_ms() -> u64 { 2000 }
impl Default for AnchorCfg {
    fn default() -> Self { Self { every: 0, peers: vec![], connect_timeout_ms: default_connect_timeout_ms() } }
}

#[derive(Debug, Deserialize)]
pub struct ServerCfg {
    /// Short name used in scopes and keys, e.g. "gev" or "video-watch".
    pub name: String,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct PolicyCfg {
    /// Tool names allowed through. Deny-by-default: an empty list blocks every call.
    #[serde(default)]
    pub allow: Vec<String>,
    /// Bounded session: calls (accepted or denied) per gate process lifetime.
    pub max_calls_per_session: u32,
}

#[derive(Debug, Deserialize, Default)]
pub struct LogCfg {
    /// Directory for channel.jsonl, denied.jsonl, rejected.jsonl, receipts.jsonl,
    /// gate-node-id and the signing key. Default: ./ductei next to the config.
    pub dir: Option<PathBuf>,
}

#[derive(Debug, Deserialize, Default, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    #[default]
    #[serde(rename = "none")]
    None,
    #[serde(rename = "ml-dsa-65")]
    MlDsa65,
    /// CNSA 2.0 parameter set.
    #[serde(rename = "ml-dsa-87")]
    MlDsa87,
}

impl Scheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::None => "none",
            Scheme::MlDsa65 => "ml-dsa-65",
            Scheme::MlDsa87 => "ml-dsa-87",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "none" => Some(Scheme::None),
            "ml-dsa-65" => Some(Scheme::MlDsa65),
            "ml-dsa-87" => Some(Scheme::MlDsa87),
            _ => None,
        }
    }
}

/// Where the secret key lives at rest.
#[derive(Debug, Deserialize, Default, Clone, Copy, PartialEq, Eq)]
pub enum KeyStore {
    /// DPAPI on Windows; plaintext elsewhere (and only with `insecure_plaintext_key = true`).
    #[default]
    #[serde(rename = "auto")]
    Auto,
    #[serde(rename = "dpapi")]
    Dpapi,
    #[serde(rename = "plaintext")]
    Plaintext,
}

#[derive(Debug, Deserialize, Default)]
pub struct SignCfg {
    #[serde(default)]
    pub scheme: Scheme,
    #[serde(default)]
    pub key_store: KeyStore,
    /// SHA-256 hex of the public key this gate must sign with. If set and the
    /// key on disk does not match, the gate refuses to start.
    #[serde(default)]
    pub pubkey_fingerprint: Option<String>,
    /// Must be true to store the secret key as a plaintext file.
    #[serde(default)]
    pub insecure_plaintext_key: bool,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        toml::from_str(&text).map_err(|e| format!("parse {}: {e}", path.display()))
    }
    pub fn log_dir(&self, config_path: &Path) -> PathBuf {
        self.log.dir.clone().unwrap_or_else(|| {
            config_path.parent().unwrap_or(Path::new(".")).join("ductei")
        })
    }
}

pub fn scope_for(server: &str, tool: &str) -> String {
    format!("mcp:{server}:{tool}")
}

// ---------------------------------------------------------------- hex / hash

pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 { return None; }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

pub fn sha256_hex(data: &[u8]) -> String {
    to_hex(&Sha256::digest(data))
}

// ---------------------------------------------------------------- node id

/// Same persisted-identity rule as ductei-limen-relay: one id per install,
/// so the causal gate sees one producer across restarts.
pub fn load_or_create_node_id(dir: &Path) -> std::io::Result<[u8; 16]> {
    let path = dir.join("gate-node-id");
    if let Ok(s) = fs::read_to_string(&path) {
        if let Some(v) = from_hex(s.trim()) {
            if v.len() == 16 {
                let mut id = [0u8; 16];
                id.copy_from_slice(&v);
                return Ok(id);
            }
        }
    }
    let mut id = [0u8; 16];
    getrandom::getrandom(&mut id).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    fs::write(&path, to_hex(&id))?;
    Ok(id)
}

// ---------------------------------------------------------------- receipts

pub const RECEIPT_VERSION: u32 = 1;
/// Domain separator prepended to the raw hash bytes before signing, so a
/// receipt signature can never be replayed as a signature over some other
/// DUCTEI object that happens to share the hash.
pub const SIGN_DOMAIN: &[u8] = b"ductei-mcp-receipt-v1\0";

/// The fields that are hashed and signed, in this exact order.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReceiptBody {
    pub v: u32,
    pub seq: u64,
    pub prev: String,
    /// SHA-256 hex of the signing public key; "" when scheme = none.
    pub kid: String,
    pub key: String,
    pub scope: String,
    pub verdict: String,
    pub lamport_call: u64,
    pub lamport_result: u64,
    pub call_sha256: String,
    pub result_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    #[serde(flatten)]
    pub body: ReceiptBody,
    pub hash: String,
    pub scheme: String,
    pub sig: Option<String>,
}

impl ReceiptBody {
    /// Unfilled template: `seq`, `prev`, `kid` and `v` are set by `ReceiptLog::record`.
    pub fn new(key: String, scope: String, verdict: &str, lamport_call: u64, lamport_result: u64, call_sha256: String, result_sha256: String) -> Self {
        Self { v: RECEIPT_VERSION, seq: 0, prev: String::new(), kid: String::new(), key, scope, verdict: verdict.into(), lamport_call, lamport_result, call_sha256, result_sha256 }
    }
    pub fn hash(&self) -> String {
        // serde_json preserves struct field order, so this is canonical for us.
        sha256_hex(serde_json::to_string(self).expect("receipt body serializes").as_bytes())
    }
}

/// What actually gets signed: domain || raw 32-byte hash.
pub fn signing_message(hash_hex: &str) -> Vec<u8> {
    let mut m = SIGN_DOMAIN.to_vec();
    m.extend(from_hex(hash_hex).unwrap_or_default());
    m
}

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Append-only receipts.jsonl with an in-memory chain head.
pub struct ReceiptLog {
    file: File,
    pub seq: u64,
    pub head: String,
    pub signer: Signer,
}

impl ReceiptLog {
    pub fn open(dir: &Path, sign: &SignCfg) -> Result<Self, String> {
        let path = dir.join("receipts.jsonl");
        let (seq, head) = match File::open(&path) {
            Ok(f) => {
                let mut seq = 0u64;
                let mut head = GENESIS.to_string();
                for line in BufReader::new(f).lines() {
                    let line = line.map_err(|e| e.to_string())?;
                    if let Ok(r) = serde_json::from_str::<Receipt>(&line) {
                        seq = r.body.seq + 1;
                        head = r.hash;
                    }
                }
                (seq, head)
            }
            Err(_) => (0, GENESIS.to_string()),
        };
        let file = OpenOptions::new().create(true).append(true).open(&path).map_err(|e| e.to_string())?;
        let signer = Signer::load_or_create(dir, sign)?;
        Ok(Self { file, seq, head, signer })
    }

    pub fn record(&mut self, mut body: ReceiptBody) -> std::io::Result<Receipt> {
        body.v = RECEIPT_VERSION;
        body.seq = self.seq;
        body.prev = self.head.clone();
        body.kid = self.signer.kid.clone();
        let hash = body.hash();
        let sig = self.signer.sign(&signing_message(&hash));
        let r = Receipt { body, hash: hash.clone(), scheme: self.signer.scheme.as_str().into(), sig };
        writeln!(self.file, "{}", serde_json::to_string(&r)?)?;
        self.file.sync_data()?;
        self.seq += 1;
        self.head = hash;
        Ok(r)
    }
}

// ---------------------------------------------------------------- anchors

pub const ANCHOR_DOMAIN: &[u8] = b"ductei-mcp-anchor-v1\0";

/// A signed statement "receipt `seq` has hash `head`". Lives outside the
/// log dir (on a peer) so a shortened receipts.jsonl can be caught.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Anchor {
    pub v: u32,
    pub kid: String,
    pub seq: u64,
    pub head: String,
    pub scheme: String,
    pub sig: Option<String>,
}

pub fn anchor_message(seq: u64, head: &str) -> Vec<u8> {
    let mut m = ANCHOR_DOMAIN.to_vec();
    m.extend(seq.to_le_bytes());
    m.extend(from_hex(head).unwrap_or_default());
    m
}

pub fn anchor_scope(server: &str) -> String { format!("mcp:{server}:anchor") }

impl ReceiptLog {
    /// Anchor for the last receipt written. None if nothing was written yet.
    pub fn anchor(&self) -> Option<Anchor> {
        if self.seq == 0 { return None; }
        let seq = self.seq - 1;
        let sig = self.signer.sign(&anchor_message(seq, &self.head));
        Some(Anchor { v: RECEIPT_VERSION, kid: self.signer.kid.clone(), seq, head: self.head.clone(), scheme: self.signer.scheme.as_str().into(), sig })
    }
}

impl Anchor {
    /// Signature check against a trusted key. Unsigned anchors (scheme none)
    /// are accepted only when `pk` is None, i.e. the log is unsigned too.
    pub fn verify(&self, pk: Option<&(Scheme, Vec<u8>)>) -> bool {
        match (pk, &self.sig) {
            (Some((scheme, pkb)), Some(sig)) => scheme.as_str() == self.scheme && self.kid == sha256_hex(pkb) && Signer::verify(*scheme, pkb, &anchor_message(self.seq, &self.head), sig),
            (None, None) => self.scheme == "none",
            _ => false,
        }
    }
}

/// Push one envelope to a DUCTEI TCP peer with timeouts and record intent and
/// ack in an outbox. Same frame format as ductei-core transport
/// (u32 LE length + JSON, 1 ack byte: 1 applied, 2 stale, 0 rejected).
pub fn push_envelope(peer: &str, env: &Envelope, timeout: std::time::Duration, outbox: &Path) -> Result<u8, String> {
    use std::io::Read;
    use std::net::{TcpStream, ToSocketAddrs};
    let addr = peer.to_socket_addrs().map_err(|e| format!("{peer}: {e}"))?.next().ok_or_else(|| format!("{peer}: no address"))?;
    let mut ob = ductei_core::outbox::Outbox::open(outbox).map_err(|e| e.to_string())?;
    ob.record_intent(env).map_err(|e| e.to_string())?;
    let mut s = TcpStream::connect_timeout(&addr, timeout).map_err(|e| format!("{peer}: connect: {e}"))?;
    s.set_read_timeout(Some(timeout)).ok();
    s.set_write_timeout(Some(timeout)).ok();
    let body = serde_json::to_vec(env).map_err(|e| e.to_string())?;
    s.write_all(&(body.len() as u32).to_le_bytes()).and_then(|_| s.write_all(&body)).and_then(|_| s.flush()).map_err(|e| format!("{peer}: write: {e}"))?;
    let mut ack = [0u8; 1];
    if let Err(e) = s.read_exact(&mut ack) {
        let _ = ob.record_receipt(&env.key, env.lamport, &env.node_id, 0xFF);
        return Err(format!("{peer}: no ack: {e}"));
    }
    ob.record_receipt(&env.key, env.lamport, &env.node_id, ack[0]).map_err(|e| e.to_string())?;
    Ok(ack[0])
}

/// Anchors found in a peer's exported log (channel.jsonl) or a local
/// anchors.jsonl: every envelope whose blob parses as an Anchor.
pub fn anchors_in(path: &Path) -> Result<Vec<Anchor>, String> {
    let store = LogStore::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let (envs, _) = store.replay(0).map_err(|e| e.to_string())?;
    Ok(envs.iter().filter_map(|e| serde_json::from_slice::<Anchor>(&e.blob).ok()).collect())
}

// ---------------------------------------------------------------- verify

/// What the verifier is told to trust. Nothing in the log directory is
/// trusted by default: a writer there could have re-keyed the whole chain.
#[derive(Debug, Default)]
pub struct VerifyTrust {
    /// Raw public key bytes supplied out-of-band (`--pubkey <file>`).
    pub pubkey: Option<Vec<u8>>,
    /// SHA-256 hex the public key must match (`--fingerprint <hex>`).
    pub fingerprint: Option<String>,
    /// Accept the `.pk` found in the log dir with no pin. Verification then
    /// proves integrity and ordering, not authorship.
    pub allow_unpinned: bool,
    /// Anchors obtained from outside the log dir (a peer's channel.jsonl
    /// export, or `seq:hash` typed by hand). The highest valid one must be
    /// present in receipts.jsonl, which catches tail truncation.
    pub anchors: Vec<Anchor>,
}

#[derive(Debug, Default)]
pub struct VerifyReport {
    pub receipts: u64,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    /// Fingerprint of the key the receipts were checked against, if any.
    pub kid: Option<String>,
}

impl VerifyReport {
    pub fn ok(&self) -> bool { self.errors.is_empty() }
}

fn blob_hashes(path: &Path, flags: u16) -> HashSet<String> {
    let mut set = HashSet::new();
    if let Ok(store) = LogStore::open(path) {
        if let Ok((envs, _)) = store.replay(0) {
            for e in envs.iter().filter(|e| e.flags == flags) { set.insert(sha256_hex(&e.blob)); }
        }
    }
    set
}

/// Recompute the chain, every signature, the key pin, and cross-check each
/// receipt's hashes against the channel / denied logs.
pub fn verify_receipts(dir: &Path, trust: &VerifyTrust) -> Result<VerifyReport, String> {
    let path = dir.join("receipts.jsonl");
    let f = File::open(&path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let mut rep = VerifyReport::default();

    // Resolve the public key: caller-supplied wins; the log dir is a fallback
    // that is only accepted when explicitly allowed.
    let mut pk: Option<(Scheme, Vec<u8>)> = None;
    if let Some(bytes) = &trust.pubkey {
        let scheme = Signer::scheme_for_pubkey_len(bytes.len()).ok_or("--pubkey: not an ML-DSA-65/87 public key")?;
        pk = Some((scheme, bytes.clone()));
    } else if let Some(found) = Signer::load_public(dir)? {
        if trust.fingerprint.is_none() && !trust.allow_unpinned {
            rep.errors.push("public key taken from the log dir and not pinned: pass --pubkey <file> or --fingerprint <hex> (or --allow-unpinned to check integrity only)".into());
        }
        pk = Some(found);
    }
    if let (Some((_, bytes)), Some(want)) = (&pk, &trust.fingerprint) {
        if sha256_hex(bytes) != want.to_lowercase() {
            rep.errors.push(format!("public key fingerprint {} does not match pinned {}", sha256_hex(bytes), want));
        }
    }
    let kid = pk.as_ref().map(|(_, b)| sha256_hex(b));
    rep.kid = kid.clone();

    let calls = blob_hashes(&dir.join("channel.jsonl"), 0);
    let results = blob_hashes(&dir.join("channel.jsonl"), 1);
    let denied = blob_hashes(&dir.join("denied.jsonl"), 0);

    let mut expect_seq = 0u64;
    let mut prev = GENESIS.to_string();
    let mut hashes: HashMap<u64, String> = HashMap::new();
    for (i, line) in BufReader::new(f).lines().enumerate() {
        let line = line.map_err(|e| e.to_string())?;
        let r: Receipt = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => { rep.errors.push(format!("line {}: unparsable: {e}", i + 1)); continue; }
        };
        rep.receipts += 1;
        let s = r.body.seq;
        if r.body.v != RECEIPT_VERSION { rep.errors.push(format!("seq {s}: receipt version {} (expected {RECEIPT_VERSION})", r.body.v)); }
        if s != expect_seq { rep.errors.push(format!("seq {s}: expected seq {expect_seq}")); }
        if r.body.prev != prev { rep.errors.push(format!("seq {s}: prev hash mismatch")); }
        if r.body.hash() != r.hash { rep.errors.push(format!("seq {s}: body hash mismatch")); }
        if r.scheme != "none" {
            match (&pk, &r.sig) {
                (Some((scheme, pkb)), Some(sig)) if scheme.as_str() == r.scheme => {
                    if Some(&r.body.kid) != kid.as_ref() { rep.errors.push(format!("seq {s}: kid {} is not the trusted key", r.body.kid)); }
                    if !Signer::verify(*scheme, pkb, &signing_message(&r.hash), sig) {
                        rep.errors.push(format!("seq {s}: signature invalid"));
                    }
                }
                _ => rep.errors.push(format!("seq {s}: signed with {} but no matching public key / sig", r.scheme)),
            }
        } else if !r.body.kid.is_empty() {
            rep.errors.push(format!("seq {s}: unsigned receipt carries kid"));
        }
        match r.body.verdict.as_str() {
            "accepted" => {
                if !calls.contains(&r.body.call_sha256) { rep.errors.push(format!("seq {s}: call not found in channel.jsonl")); }
                if !results.contains(&r.body.result_sha256) { rep.errors.push(format!("seq {s}: result not found in channel.jsonl")); }
            }
            "denied" => {
                if !denied.contains(&r.body.call_sha256) { rep.errors.push(format!("seq {s}: denied call not found in denied.jsonl")); }
            }
            v => rep.errors.push(format!("seq {s}: unknown verdict {v}")),
        }
        expect_seq = s + 1;
        hashes.insert(s, r.hash.clone());
        prev = r.hash;
    }
    if rep.receipts > 0 && pk.is_none() {
        rep.warnings.push("no public key: only unsigned receipts can be accepted".into());
    }
    if trust.allow_unpinned && trust.pubkey.is_none() && trust.fingerprint.is_none() {
        rep.warnings.push("unpinned key: integrity and order verified, authorship not".into());
    }

    // Anchors: the highest one that verifies against the trusted key must be
    // present in the file with the same hash. A valid anchor beyond the end
    // of the file is proof of truncation.
    let valid: Vec<&Anchor> = trust.anchors.iter().filter(|a| a.v == RECEIPT_VERSION && a.verify(pk.as_ref())).collect();
    let rejected = trust.anchors.len() - valid.len();
    if rejected > 0 { rep.warnings.push(format!("{rejected} anchor(s) ignored: not signed by the trusted key")); }
    if let Some(a) = valid.iter().max_by_key(|a| a.seq) {
        match hashes.get(&a.seq) {
            Some(h) if *h == a.head => rep.warnings.push(format!("anchor seq {} matches; receipts after it ({}) are not covered by an anchor", a.seq, rep.receipts.saturating_sub(a.seq + 1))),
            Some(_) => rep.errors.push(format!("seq {}: hash differs from anchor (history rewritten)", a.seq)),
            None => rep.errors.push(format!("TRUNCATED: anchor proves receipt seq {} existed (head {}), file ends at seq {}", a.seq, &a.head[..16], expect_seq.saturating_sub(1))),
        }
    } else {
        rep.warnings.push("no anchor: tail truncation is not detectable; pass --anchor seq:hash or --anchor-file <peer channel.jsonl>".into());
    }
    Ok(rep)
}

// ---------------------------------------------------------------- signer

#[cfg(feature = "sign")]
type Secret = zeroize::Zeroizing<Vec<u8>>;

pub struct Signer {
    pub scheme: Scheme,
    /// SHA-256 hex of the public key; "" when unsigned.
    pub kid: String,
    pub public: Option<Vec<u8>>,
    /// True when the key was minted by this call (print the fingerprint).
    pub created: bool,
    #[cfg(feature = "sign")]
    secret: Option<Secret>,
}

impl Signer {
    fn pk_path(dir: &Path, scheme: Scheme) -> PathBuf { dir.join(format!("gate-{}.pk", scheme.as_str())) }
    fn sk_plain_path(dir: &Path, scheme: Scheme) -> PathBuf { dir.join(format!("gate-{}.sk", scheme.as_str())) }
    fn sk_dpapi_path(dir: &Path, scheme: Scheme) -> PathBuf { dir.join(format!("gate-{}.sk.dpapi", scheme.as_str())) }

    pub fn scheme_for_pubkey_len(len: usize) -> Option<Scheme> {
        match len { 1952 => Some(Scheme::MlDsa65), 2592 => Some(Scheme::MlDsa87), _ => None }
    }

    fn effective_store(cfg: &SignCfg) -> Result<KeyStore, String> {
        let store = match cfg.key_store {
            KeyStore::Auto => if cfg!(windows) { KeyStore::Dpapi } else { KeyStore::Plaintext },
            s => s,
        };
        if store == KeyStore::Plaintext && !cfg.insecure_plaintext_key {
            return Err("sign.key_store = plaintext requires sign.insecure_plaintext_key = true (or use dpapi on Windows)".into());
        }
        if store == KeyStore::Dpapi && !cfg!(windows) {
            return Err("sign.key_store = dpapi is Windows-only".into());
        }
        Ok(store)
    }

    pub fn load_or_create(dir: &Path, cfg: &SignCfg) -> Result<Self, String> {
        let scheme = cfg.scheme;
        #[cfg(not(feature = "sign"))]
        {
            let _ = dir;
            if scheme != Scheme::None {
                return Err(format!("sign.scheme = {} requires building with --features sign", scheme.as_str()));
            }
            Ok(Self { scheme, kid: String::new(), public: None, created: false })
        }
        #[cfg(feature = "sign")]
        {
            if scheme == Scheme::None { return Ok(Self { scheme, kid: String::new(), public: None, created: false, secret: None }); }
            let store = Self::effective_store(cfg)?;
            let pk_path = Self::pk_path(dir, scheme);
            let plain = Self::sk_plain_path(dir, scheme);
            let wrapped = Self::sk_dpapi_path(dir, scheme);

            let mut created = false;
            let secret: Secret = if let Ok(w) = fs::read(&wrapped) {
                Secret::new(keystore::unwrap(&w)?)
            } else if let Ok(p) = fs::read(&plain) {
                let s = Secret::new(p);
                if store == KeyStore::Dpapi {
                    // Migrate: wrap, then try to remove the plaintext copy.
                    fs::write(&wrapped, keystore::wrap(&s)?).map_err(|e| e.to_string())?;
                    if fs::remove_file(&plain).is_err() {
                        eprintln!("ductei-mcp-gate: WARNING plaintext key {} could not be removed after DPAPI migration; delete it by hand", plain.display());
                    }
                }
                s
            } else {
                let (pk, sk) = pq::keypair(scheme);
                let s = Secret::new(sk);
                fs::write(&pk_path, &pk).map_err(|e| e.to_string())?;
                match store {
                    KeyStore::Dpapi => fs::write(&wrapped, keystore::wrap(&s)?).map_err(|e| e.to_string())?,
                    _ => fs::write(&plain, &*s).map_err(|e| e.to_string())?,
                }
                created = true;
                s
            };
            let public = fs::read(&pk_path).map_err(|e| format!("read {}: {e}", pk_path.display()))?;
            if Self::scheme_for_pubkey_len(public.len()) != Some(scheme) {
                return Err(format!("{} is not a {} public key", pk_path.display(), scheme.as_str()));
            }
            let kid = sha256_hex(&public);
            if let Some(want) = &cfg.pubkey_fingerprint {
                if kid != want.to_lowercase() {
                    return Err(format!("signing key fingerprint {kid} does not match sign.pubkey_fingerprint {want}; refusing to start"));
                }
            }
            Ok(Self { scheme, kid, public: Some(public), created, secret: Some(secret) })
        }
    }

    pub fn sign(&self, msg: &[u8]) -> Option<String> {
        #[cfg(feature = "sign")]
        {
            let sk = self.secret.as_ref()?;
            return Some(to_hex(&pq::sign(self.scheme, sk, msg)));
        }
        #[cfg(not(feature = "sign"))]
        { let _ = msg; None }
    }

    /// Public key on disk, if any scheme has one. Untrusted unless pinned.
    pub fn load_public(dir: &Path) -> Result<Option<(Scheme, Vec<u8>)>, String> {
        for scheme in [Scheme::MlDsa87, Scheme::MlDsa65] {
            let p = Self::pk_path(dir, scheme);
            if let Ok(pk) = fs::read(&p) { return Ok(Some((scheme, pk))); }
        }
        Ok(None)
    }

    pub fn verify(scheme: Scheme, pk: &[u8], msg: &[u8], sig_hex: &str) -> bool {
        #[cfg(feature = "sign")]
        {
            match from_hex(sig_hex) {
                Some(sig) => pq::verify(scheme, pk, msg, &sig),
                None => false,
            }
        }
        #[cfg(not(feature = "sign"))]
        { let _ = (scheme, pk, msg, sig_hex); false }
    }
}

/// Secret key at rest. DPAPI user scope on Windows: only this Windows user
/// on this machine can unwrap it. Not a defence against that user, or against
/// anyone running as them; it is a defence against the file being copied.
#[cfg(all(feature = "sign", windows))]
mod keystore {
    use windows_sys::Win32::Security::Cryptography::{CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN};
    use windows_sys::Win32::Foundation::LocalFree;

    fn take(out: CRYPT_INTEGER_BLOB) -> Vec<u8> {
        let v = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec() };
        unsafe { LocalFree(out.pbData as _); }
        v
    }

    pub fn wrap(secret: &[u8]) -> Result<Vec<u8>, String> {
        let input = CRYPT_INTEGER_BLOB { cbData: secret.len() as u32, pbData: secret.as_ptr() as *mut u8 };
        let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
        let desc: Vec<u16> = "ductei-mcp-gate signing key\0".encode_utf16().collect();
        let ok = unsafe { CryptProtectData(&input, desc.as_ptr(), std::ptr::null(), std::ptr::null(), std::ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut out) };
        if ok == 0 { return Err("CryptProtectData failed".into()); }
        Ok(take(out))
    }

    pub fn unwrap(wrapped: &[u8]) -> Result<Vec<u8>, String> {
        let input = CRYPT_INTEGER_BLOB { cbData: wrapped.len() as u32, pbData: wrapped.as_ptr() as *mut u8 };
        let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
        let ok = unsafe { CryptUnprotectData(&input, std::ptr::null_mut(), std::ptr::null(), std::ptr::null(), std::ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut out) };
        if ok == 0 { return Err("CryptUnprotectData failed (key wrapped by another user or machine?)".into()); }
        Ok(take(out))
    }
}

#[cfg(all(feature = "sign", not(windows)))]
mod keystore {
    pub fn wrap(_: &[u8]) -> Result<Vec<u8>, String> { Err("DPAPI key store is Windows-only".into()) }
    pub fn unwrap(_: &[u8]) -> Result<Vec<u8>, String> { Err("DPAPI key store is Windows-only".into()) }
}

#[cfg(feature = "sign")]
mod pq {
    use super::Scheme;
    use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};

    macro_rules! with_scheme {
        ($scheme:expr, $m:ident, $body:block) => {
            match $scheme {
                Scheme::MlDsa65 => { use pqcrypto_mldsa::mldsa65 as $m; $body }
                Scheme::MlDsa87 => { use pqcrypto_mldsa::mldsa87 as $m; $body }
                Scheme::None => unreachable!("no pq scheme"),
            }
        };
    }

    pub fn keypair(scheme: Scheme) -> (Vec<u8>, Vec<u8>) {
        with_scheme!(scheme, m, {
            let (pk, sk) = m::keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        })
    }
    pub fn sign(scheme: Scheme, sk: &[u8], msg: &[u8]) -> Vec<u8> {
        with_scheme!(scheme, m, {
            let sk = m::SecretKey::from_bytes(sk).expect("stored secret key is well-formed");
            m::detached_sign(msg, &sk).as_bytes().to_vec()
        })
    }
    pub fn verify(scheme: Scheme, pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        with_scheme!(scheme, m, {
            let (Ok(pk), Ok(sig)) = (m::PublicKey::from_bytes(pk), m::DetachedSignature::from_bytes(sig)) else { return false };
            m::verify_detached_signature(&sig, msg, &pk).is_ok()
        })
    }
}

// ---------------------------------------------------------------- gate state

/// What we remember between forwarding a call and seeing its result.
#[derive(Debug, Clone)]
pub struct PendingCall {
    pub key: String,
    pub scope: String,
    pub lamport_call: u64,
    pub call_sha256: String,
}

/// Everything the two relay threads share. Lives behind one Mutex.
pub struct Gate {
    pub server: String,
    pub node: [u8; 16],
    pub lamport: u64,
    pub channel: Channel,
    pub denied: LogStore,
    pub receipts: ReceiptLog,
    pub pending: HashMap<String, PendingCall>,
    /// `tools/list` request ids awaiting a server answer to filter.
    pub pending_lists: HashSet<String>,
    pub allow: HashSet<String>,
    pub max_calls: u32,
    pub calls: u32,
    pub closed: bool,
    /// Anchor every N receipts (0 = off). Anchors also go to anchors.jsonl locally.
    pub anchor_every: u64,
    pub anchors: LogStore,
    /// Where anchor envelopes go to be pushed to peers (gate binary owns the thread).
    pub anchor_tx: Option<std::sync::mpsc::Sender<Envelope>>,
}

#[derive(Debug, PartialEq)]
pub enum Decision {
    /// Forward the line to the server unchanged.
    Forward,
    /// Do not forward; send this JSON-RPC error line back to the client instead.
    Reply(String),
}

impl Gate {
    pub fn open(cfg: &Config, dir: &Path) -> Result<Self, String> {
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let mut policy = ScopePolicy::new();
        for t in &cfg.policy.allow { policy = policy.allow(&scope_for(&cfg.server.name, t)); }
        let channel = Channel::open(policy, dir.join("channel.jsonl"), dir.join("rejected.jsonl"))
            .map_err(|e| e.to_string())?;
        let node = load_or_create_node_id(dir).map_err(|e| e.to_string())?;
        // Resume our lamport clock from what this node already persisted.
        let (past, _) = channel.replay(0).map_err(|e| e.to_string())?;
        let lamport = past.iter().filter(|e| e.node_id == node).map(|e| e.lamport).max().map_or(0, |l| l + 1);
        Ok(Self {
            server: cfg.server.name.clone(),
            node,
            lamport,
            channel,
            denied: LogStore::open(dir.join("denied.jsonl")).map_err(|e| e.to_string())?,
            receipts: ReceiptLog::open(dir, &cfg.sign)?,
            pending: HashMap::new(),
            pending_lists: HashSet::new(),
            allow: cfg.policy.allow.iter().cloned().collect(),
            max_calls: cfg.policy.max_calls_per_session,
            calls: 0,
            closed: false,
            anchor_every: cfg.anchor.every,
            anchors: LogStore::open(dir.join("anchors.jsonl")).map_err(|e| e.to_string())?,
            anchor_tx: None,
        })
    }

    fn next_lamport(&mut self) -> u64 { let l = self.lamport; self.lamport += 1; l }

    /// After a receipt: every N receipts, sign the chain head, append it to
    /// anchors.jsonl and hand it to the pusher. Local write first, so an
    /// anchor is never in flight without a record of it.
    fn maybe_anchor(&mut self) {
        if self.anchor_every == 0 || self.receipts.seq % self.anchor_every != 0 { return; }
        let Some(a) = self.receipts.anchor() else { return };
        let blob = serde_json::to_vec(&a).unwrap_or_default();
        let key = format!("mcp/{}/anchor/{}", self.server, a.seq);
        let lamport = self.next_lamport();
        let env = scoped(&key, &[&anchor_scope(&self.server)], self.node, lamport, &blob);
        if let Err(e) = self.anchors.append(&env) { eprintln!("ductei-mcp-gate: anchors.jsonl append failed: {e}"); return; }
        if let Some(tx) = &self.anchor_tx { let _ = tx.send(env); }
    }

    /// Build an anchor envelope by hand (used by the binary on exit).
    pub fn anchor_now(&mut self) -> Option<Envelope> {
        let a = self.receipts.anchor()?;
        let blob = serde_json::to_vec(&a).unwrap_or_default();
        let key = format!("mcp/{}/anchor/{}", self.server, a.seq);
        let lamport = self.next_lamport();
        Some(scoped(&key, &[&anchor_scope(&self.server)], self.node, lamport, &blob))
    }

    /// Mirrors ductei_core::SessionBudget (which is private and borrows the
    /// channel for its lifetime, so it can't be shared across relay threads).
    fn admit_call(&mut self) -> Result<(), ChannelError> {
        if self.closed { return Err(ChannelError::BoundReached); }
        if self.calls >= self.max_calls { self.closed = true; return Err(ChannelError::BoundReached); }
        self.calls += 1;
        Ok(())
    }

    /// A line from the client. `tools/call` is gated, `tools/list` is noted
    /// so its answer can be filtered, everything else is forwarded.
    pub fn on_client_line(&mut self, line: &str) -> Decision {
        let Ok(msg) = serde_json::from_str::<serde_json::Value>(line) else { return Decision::Forward };
        let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("");
        if method == "tools/list" {
            if let Some(id) = msg.get("id") { self.pending_lists.insert(id.to_string()); }
            return Decision::Forward;
        }
        if method != "tools/call" { return Decision::Forward; }
        let id = msg.get("id").cloned().unwrap_or(serde_json::Value::Null);
        let tool = msg.pointer("/params/name").and_then(|t| t.as_str()).unwrap_or("").to_string();
        let scope = scope_for(&self.server, &tool);
        let id_str = id.to_string();
        let key = format!("mcp/{}/{}/{}", self.server, tool, id_str.trim_matches('"'));
        let params = msg.get("params").cloned().unwrap_or(serde_json::Value::Null);
        let blob = serde_json::to_vec(&params).unwrap_or_default();
        let call_sha256 = sha256_hex(&blob);
        let lamport_call = self.next_lamport();
        let env = scoped(&key, &[&scope], self.node, lamport_call, &blob);

        let outcome = self.admit_call().and_then(|_| self.channel.send(env.clone()));
        match outcome {
            Ok(()) => {
                self.pending.insert(id_str, PendingCall { key, scope, lamport_call, call_sha256 });
                Decision::Forward
            }
            Err(e) => {
                let (code, text) = match &e {
                    ChannelError::ScopeDenied(_) => (-32001, format!("ductei: scope {scope} denied by policy")),
                    ChannelError::BoundReached => (-32002, "ductei: session bound reached".to_string()),
                    ChannelError::StaleDelta { .. } => (-32003, "ductei: stale delta rejected".to_string()),
                    ChannelError::Io(m) => (-32004, format!("ductei: persistence failed: {m}")),
                };
                let reply = serde_json::json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":text}}).to_string();
                let _ = self.denied.append(&env);
                let lamport_result = self.next_lamport();
                let _ = self.receipts.record(ReceiptBody::new(key, scope, "denied", lamport_call, lamport_result, call_sha256, sha256_hex(reply.as_bytes())));
                self.maybe_anchor();
                Decision::Reply(reply)
            }
        }
    }

    /// A line from the server. If it answers a gated call, persist the result
    /// and write the receipt *before* the caller forwards it to the client.
    /// Returns `Some(line)` when the line to forward differs from the input
    /// (a filtered `tools/list` answer), `None` to forward it unchanged.
    pub fn on_server_line(&mut self, line: &str) -> Result<Option<String>, ChannelError> {
        let Ok(mut msg) = serde_json::from_str::<serde_json::Value>(line) else { return Ok(None) };
        let Some(id) = msg.get("id").cloned() else { return Ok(None) };
        let id_str = id.to_string();

        if self.pending_lists.remove(&id_str) {
            let allow = self.allow.clone();
            let Some(tools) = msg.pointer_mut("/result/tools").and_then(|t| t.as_array_mut()) else { return Ok(None) };
            let before = tools.len();
            let hidden: Vec<String> = tools.iter()
                .filter_map(|t| t.get("name").and_then(|n| n.as_str()))
                .filter(|n| !allow.contains(*n)).map(String::from).collect();
            tools.retain(|t| t.get("name").and_then(|n| n.as_str()).map_or(false, |n| allow.contains(n)));
            if tools.len() != before {
                eprintln!("ductei-mcp-gate: tools/list filtered {} -> {} (hidden: {})", before, tools.len(), hidden.join(", "));
            }
            return Ok(Some(msg.to_string()));
        }

        let Some(p) = self.pending.remove(&id_str) else { return Ok(None) };
        let body = msg.get("result").or_else(|| msg.get("error")).cloned().unwrap_or(serde_json::Value::Null);
        let blob = serde_json::to_vec(&body).unwrap_or_default();
        let lamport_result = self.next_lamport();
        let mut env = scoped(&p.key, &[&p.scope], self.node, lamport_result, &blob);
        env.flags = 1; // response
        self.channel.send(env)?;
        self.receipts.record(ReceiptBody::new(p.key, p.scope, "accepted", p.lamport_call, lamport_result, p.call_sha256, sha256_hex(&blob)))
            .map_err(|e| ChannelError::Io(e.to_string()))?;
        self.maybe_anchor();
        Ok(None)
    }
}

// ---------------------------------------------------------------- launch nonce

/// Environment the gate gives the server it spawns. A server built to be
/// gate-only refuses to serve stdio unless `DUCTEI_GATE_NONCE` is present
/// and its SHA-256 equals the `nonce_sha256` in `gate-launch.json` next to
/// the logs (which the server can also check is owned by a live gate pid).
/// This stops accidental bypass (a client configured straight at the
/// server); it does not stop someone running as the same user on purpose.
pub const GATE_NONCE_ENV: &str = "DUCTEI_GATE_NONCE";
pub const GATE_LAUNCH_FILE: &str = "gate-launch.json";

#[derive(Debug, Serialize, Deserialize)]
pub struct LaunchRecord {
    pub v: u32,
    pub gate_pid: u32,
    pub node_id: String,
    pub nonce_sha256: String,
    pub server: String,
}

/// Returns (nonce hex for the child's env, record written to the log dir).
pub fn new_launch(dir: &Path, server: &str, node: [u8; 16]) -> std::io::Result<(String, LaunchRecord)> {
    let mut nonce = [0u8; 32];
    getrandom::getrandom(&mut nonce).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    let nonce_hex = to_hex(&nonce);
    let rec = LaunchRecord { v: 1, gate_pid: std::process::id(), node_id: to_hex(&node), nonce_sha256: sha256_hex(nonce_hex.as_bytes()), server: server.into() };
    fs::write(dir.join(GATE_LAUNCH_FILE), serde_json::to_string(&rec)?)?;
    Ok((nonce_hex, rec))
}

/// Re-exported so the binary and tests share one Envelope type.
pub type Env = Envelope;

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(allow: &[&str], max: u32) -> Config {
        Config {
            server: ServerCfg { name: "t".into(), command: "true".into(), args: vec![] },
            policy: PolicyCfg { allow: allow.iter().map(|s| s.to_string()).collect(), max_calls_per_session: max },
            log: LogCfg::default(),
            sign: SignCfg::default(),
            anchor: AnchorCfg::default(),
        }
    }

    /// A DUCTEI peer on localhost that accepts anchor envelopes for server "t",
    /// serving connections until the listener is dropped. Returns (addr, dir).
    fn anchor_peer() -> (String, PathBuf) {
        let d = tmp();
        let policy = ScopePolicy::new().allow(&anchor_scope("t"));
        let mut ch = Channel::open(policy, d.join("channel.jsonl"), d.join("rejected.jsonl")).unwrap();
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            for s in l.incoming() {
                let Ok(s) = s else { break };
                let _ = ductei_core::transport::serve_connection(s, &mut ch);
            }
        });
        (addr, d)
    }

    #[test]
    fn anchors_are_written_pushed_and_catch_truncation() {
        let (peer, peer_dir) = anchor_peer();
        let d = tmp();
        let mut c = cfg(&["echo"], 10);
        c.anchor = AnchorCfg { every: 1, peers: vec![peer.clone()], connect_timeout_ms: 2000 };
        let (tx, rx) = std::sync::mpsc::channel();
        let mut g = Gate::open(&c, &d).unwrap();
        g.anchor_tx = Some(tx);
        for id in 1..=3 {
            g.on_client_line(&call(id, "echo"));
            g.on_server_line(&format!(r#"{{"jsonrpc":"2.0","id":{id},"result":{id}}}"#)).unwrap();
        }
        // Local anchors.jsonl has one per receipt, and the pusher gets the same envelopes.
        assert_eq!(g.anchors.replay(0).unwrap().0.len(), 3);
        let outbox = d.join("outbox.jsonl");
        let mut pushed = 0;
        while let Ok(env) = rx.try_recv() {
            assert_eq!(push_envelope(&peer, &env, std::time::Duration::from_secs(2), &outbox).unwrap(), 1);
            pushed += 1;
        }
        assert_eq!(pushed, 3);
        // The peer's log is the external anchor source.
        let anchors = anchors_in(&peer_dir.join("channel.jsonl")).unwrap();
        assert_eq!(anchors.len(), 3);
        assert_eq!(anchors.iter().map(|a| a.seq).max(), Some(2));
        let trust = VerifyTrust { allow_unpinned: true, anchors: anchors.clone(), ..Default::default() };
        let rep = verify_receipts(&d, &trust).unwrap();
        assert!(rep.ok(), "{:?}", rep.errors);
        // Drop the last receipt: chain still intact, anchor says it's missing.
        let p = d.join("receipts.jsonl");
        let keep: Vec<String> = fs::read_to_string(&p).unwrap().lines().take(2).map(String::from).collect();
        fs::write(&p, keep.join("\n") + "\n").unwrap();
        assert!(verify_receipts(&d, &unpinned()).unwrap().ok(), "chain alone cannot see truncation");
        let rep = verify_receipts(&d, &trust).unwrap();
        assert!(rep.errors.iter().any(|e| e.starts_with("TRUNCATED")), "{:?}", rep.errors);
    }

    #[test]
    fn unreachable_peer_does_not_block_or_lose_the_local_anchor() {
        let d = tmp();
        let mut c = cfg(&["echo"], 10);
        c.anchor = AnchorCfg { every: 1, peers: vec!["127.0.0.1:9".into()], connect_timeout_ms: 300 };
        let mut g = Gate::open(&c, &d).unwrap();
        g.on_client_line(&call(1, "echo"));
        g.on_server_line(r#"{"jsonrpc":"2.0","id":1,"result":1}"#).unwrap();
        let env = g.anchor_now().unwrap();
        let t = std::time::Instant::now();
        assert!(push_envelope("127.0.0.1:9", &env, std::time::Duration::from_millis(300), &d.join("outbox.jsonl")).is_err());
        assert!(t.elapsed() < std::time::Duration::from_secs(5));
        assert_eq!(g.anchors.replay(0).unwrap().0.len(), 1);
    }

    #[test]
    fn launch_record_matches_nonce() {
        let d = tmp();
        let (nonce, rec) = new_launch(&d, "t", [7u8; 16]).unwrap();
        assert_eq!(sha256_hex(nonce.as_bytes()), rec.nonce_sha256);
        let on_disk: LaunchRecord = serde_json::from_str(&fs::read_to_string(d.join(GATE_LAUNCH_FILE)).unwrap()).unwrap();
        assert_eq!(on_disk.nonce_sha256, rec.nonce_sha256);
        assert_eq!(on_disk.gate_pid, std::process::id());
    }

    fn tmp() -> PathBuf {
        let d = std::env::temp_dir().join(format!("ductei-mcp-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn unpinned() -> VerifyTrust { VerifyTrust { allow_unpinned: true, ..Default::default() } }

    fn call(id: u32, tool: &str) -> String {
        format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"{tool}","arguments":{{"x":{id}}}}}}}"#)
    }

    #[test]
    fn allowed_tool_is_forwarded_then_receipted() {
        let d = tmp();
        let mut g = Gate::open(&cfg(&["echo"], 10), &d).unwrap();
        assert_eq!(g.on_client_line(&call(1, "echo")), Decision::Forward);
        assert_eq!(g.pending.len(), 1);
        assert_eq!(g.on_server_line(r#"{"jsonrpc":"2.0","id":1,"result":{"content":[]}}"#).unwrap(), None);
        assert!(g.pending.is_empty());
        let (log, _) = g.channel.replay(0).unwrap();
        assert_eq!(log.len(), 2);
        assert_eq!(log[1].flags, 1);
        let rep = verify_receipts(&d, &unpinned()).unwrap();
        assert_eq!((rep.receipts, rep.errors.as_slice()), (1, &[][..]));
    }

    #[test]
    fn denied_tool_never_forwards_and_is_receipted() {
        let d = tmp();
        let mut g = Gate::open(&cfg(&["echo"], 10), &d).unwrap();
        match g.on_client_line(&call(7, "rm_rf")) {
            Decision::Reply(r) => assert!(r.contains("-32001") && r.contains("\"id\":7")),
            Decision::Forward => panic!("denied call was forwarded"),
        }
        assert!(g.pending.is_empty());
        assert_eq!(g.channel.replay(0).unwrap().0.len(), 0, "denied call must not enter channel log");
        assert_eq!(g.denied.replay(0).unwrap().0.len(), 1);
        let rep = verify_receipts(&d, &unpinned()).unwrap();
        assert_eq!(rep.receipts, 1);
        assert!(rep.errors.is_empty(), "{:?}", rep.errors);
    }

    #[test]
    fn session_bound_closes_for_good() {
        let d = tmp();
        let mut g = Gate::open(&cfg(&["echo"], 1), &d).unwrap();
        assert_eq!(g.on_client_line(&call(1, "echo")), Decision::Forward);
        assert!(matches!(g.on_client_line(&call(2, "echo")), Decision::Reply(r) if r.contains("-32002")));
        assert!(matches!(g.on_client_line(&call(3, "echo")), Decision::Reply(r) if r.contains("-32002")));
    }

    #[test]
    fn non_call_methods_pass_through() {
        let d = tmp();
        let mut g = Gate::open(&cfg(&[], 10), &d).unwrap();
        assert_eq!(g.on_client_line(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#), Decision::Forward);
        assert_eq!(g.on_client_line("not json"), Decision::Forward);
    }

    #[test]
    fn tools_list_is_filtered_to_allowlist() {
        let d = tmp();
        let mut g = Gate::open(&cfg(&["latest_frame", "events"], 10), &d).unwrap();
        assert_eq!(g.on_client_line(r#"{"jsonrpc":"2.0","id":5,"method":"tools/list"}"#), Decision::Forward);
        let answer = r#"{"jsonrpc":"2.0","id":5,"result":{"tools":[{"name":"latest_frame"},{"name":"delete_all"},{"name":"events"}],"nextCursor":null}}"#;
        let out = g.on_server_line(answer).unwrap().expect("list answer is rewritten");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        let names: Vec<&str> = v["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["latest_frame", "events"]);
        assert!(v["result"].get("nextCursor").is_some(), "other result fields are kept");
        // A second answer with the same id is not a list answer any more.
        assert_eq!(g.on_server_line(answer).unwrap(), None);
    }

    #[test]
    fn tampered_receipt_fails_verify() {
        let d = tmp();
        let mut g = Gate::open(&cfg(&["echo"], 10), &d).unwrap();
        g.on_client_line(&call(1, "echo"));
        g.on_server_line(r#"{"jsonrpc":"2.0","id":1,"result":1}"#).unwrap();
        g.on_client_line(&call(2, "echo"));
        g.on_server_line(r#"{"jsonrpc":"2.0","id":2,"result":2}"#).unwrap();
        let p = d.join("receipts.jsonl");
        let text = fs::read_to_string(&p).unwrap().replace("\"verdict\":\"accepted\"", "\"verdict\":\"denied\"");
        fs::write(&p, text).unwrap();
        assert!(!verify_receipts(&d, &unpinned()).unwrap().ok());
    }

    #[test]
    fn receipt_without_matching_channel_entry_fails_verify() {
        let d = tmp();
        let mut g = Gate::open(&cfg(&["echo"], 10), &d).unwrap();
        g.on_client_line(&call(1, "echo"));
        g.on_server_line(r#"{"jsonrpc":"2.0","id":1,"result":1}"#).unwrap();
        assert!(verify_receipts(&d, &unpinned()).unwrap().ok());
        // Someone rewrites the channel log out from under the receipts.
        fs::write(d.join("channel.jsonl"), "").unwrap();
        let rep = verify_receipts(&d, &unpinned()).unwrap();
        assert!(rep.errors.iter().any(|e| e.contains("not found in channel.jsonl")), "{:?}", rep.errors);
    }

    #[test]
    fn lamport_resumes_across_restart() {
        let d = tmp();
        let l1 = {
            let mut g = Gate::open(&cfg(&["echo"], 10), &d).unwrap();
            g.on_client_line(&call(1, "echo"));
            g.on_server_line(r#"{"jsonrpc":"2.0","id":1,"result":1}"#).unwrap();
            g.lamport
        };
        let g2 = Gate::open(&cfg(&["echo"], 10), &d).unwrap();
        assert_eq!(g2.lamport, l1);
        assert_eq!(g2.receipts.seq, 1);
    }

    #[test]
    fn plaintext_key_store_needs_explicit_opt_in() {
        let c = SignCfg { scheme: Scheme::MlDsa65, key_store: KeyStore::Plaintext, pubkey_fingerprint: None, insecure_plaintext_key: false };
        assert!(Signer::effective_store(&c).is_err());
        let c = SignCfg { insecure_plaintext_key: true, ..c };
        assert_eq!(Signer::effective_store(&c).unwrap(), KeyStore::Plaintext);
    }

    #[cfg(feature = "sign")]
    mod signed {
        use super::*;

        fn signed_cfg(fp: Option<String>) -> Config {
            let mut c = cfg(&["echo"], 10);
            c.sign = SignCfg { scheme: Scheme::MlDsa65, key_store: KeyStore::Plaintext, pubkey_fingerprint: fp, insecure_plaintext_key: true };
            c
        }

        #[test]
        fn signed_receipts_verify_only_against_pinned_key() {
            let d = tmp();
            let kid = {
                let mut g = Gate::open(&signed_cfg(None), &d).unwrap();
                g.on_client_line(&call(1, "echo"));
                g.on_server_line(r#"{"jsonrpc":"2.0","id":1,"result":1}"#).unwrap();
                g.on_client_line(&call(2, "nope"));
                g.receipts.signer.kid.clone()
            };
            // Unpinned, not allowed: error.
            assert!(!verify_receipts(&d, &VerifyTrust::default()).unwrap().ok());
            // Pinned by fingerprint: ok.
            let rep = verify_receipts(&d, &VerifyTrust { fingerprint: Some(kid.clone()), ..Default::default() }).unwrap();
            assert!(rep.ok(), "{:?}", rep.errors);
            assert_eq!(rep.receipts, 2);
            // Pinned by pubkey file: ok.
            let pk = fs::read(d.join("gate-ml-dsa-65.pk")).unwrap();
            assert!(verify_receipts(&d, &VerifyTrust { pubkey: Some(pk), ..Default::default() }).unwrap().ok());
            // Wrong fingerprint: fail.
            assert!(!verify_receipts(&d, &VerifyTrust { fingerprint: Some("00".repeat(32)), ..Default::default() }).unwrap().ok());
            // Attacker re-keys: delete the pair, run the gate again (new key), verify against the old pin fails.
            fs::remove_file(d.join("gate-ml-dsa-65.pk")).unwrap();
            fs::remove_file(d.join("gate-ml-dsa-65.sk")).unwrap();
            let mut g = Gate::open(&signed_cfg(None), &d).unwrap();
            g.on_client_line(&call(3, "echo"));
            g.on_server_line(r#"{"jsonrpc":"2.0","id":3,"result":3}"#).unwrap();
            let rep = verify_receipts(&d, &VerifyTrust { fingerprint: Some(kid), ..Default::default() }).unwrap();
            assert!(rep.errors.iter().any(|e| e.contains("not the trusted key") || e.contains("does not match pinned")), "{:?}", rep.errors);
        }

        #[test]
        fn gate_refuses_to_start_with_wrong_pinned_key() {
            let d = tmp();
            drop(Gate::open(&signed_cfg(None), &d).unwrap());
            assert!(Gate::open(&signed_cfg(Some("ff".repeat(32))), &d).is_err());
        }

        #[test]
        fn signature_is_domain_separated() {
            let d = tmp();
            let mut g = Gate::open(&signed_cfg(None), &d).unwrap();
            g.on_client_line(&call(1, "echo"));
            g.on_server_line(r#"{"jsonrpc":"2.0","id":1,"result":1}"#).unwrap();
            let line = fs::read_to_string(d.join("receipts.jsonl")).unwrap();
            let r: Receipt = serde_json::from_str(line.lines().next().unwrap()).unwrap();
            let pk = g.receipts.signer.public.clone().unwrap();
            assert!(Signer::verify(Scheme::MlDsa65, &pk, &signing_message(&r.hash), r.sig.as_ref().unwrap()));
            assert!(!Signer::verify(Scheme::MlDsa65, &pk, r.hash.as_bytes(), r.sig.as_ref().unwrap()), "bare hash must not verify");
        }
    }
}
