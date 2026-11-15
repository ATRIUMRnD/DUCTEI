// Copyright (C) 2026 xingxerx
// Licensed under the Elastic License 2.0. See the LICENSE file in this crate.

//! atrium-os: the one job door of the ATRIUM control plane.
//!
//! This crate adds no new machinery. It wires rooms that already exist, each
//! keeping its one job, and returns one receipt for the whole trip:
//!
//! 0. Door: the request is a closed, flat `JobRequest` (atrium_os spec). The
//!    job id must be a plain file stem, because the spool names files after it.
//! 1. QHR (ductei-qhr): CANON gate, tier, ABA pre-flight, deadline, and a
//!    hash-chained, signed receipt written before anything is returned.
//! 2. LIMEN: `qpu.run` goes to limend through the spool contract (QHR's QPU lane).
//! 3. DUCTEI: the job receipt goes through a bounded one-envelope session on
//!    this crate's own channel (scope `atrium.os.receipt`), fsynced.
//! 4. Qallow: `ductei-qallow-relay --once` hands that envelope to `qallow
//!    ingest`; the receipt is then read back with `qallow get`, byte for byte.
//!
//! N5 (nothing fails silently): a receipt always says how far it got
//! (`persist_state` plus a reason), and `verify_receipt` re-derives every
//! outcome field from the signed chain entry instead of trusting the receipt.
#![forbid(unsafe_code)]

#[path = "../../atrium-spec/generated/atrium_os_spec.rs"]
pub mod spec;
/// The base ATRIUM contract (health states, N5 health report).
#[path = "../../atrium-spec/generated/atrium_spec.rs"]
pub mod base;

pub use spec::{JobReceipt, JobRequest};

use ductei_core::{scoped, Channel, LogStore, ScopePolicy, SessionBound};
use ductei_mcp::{sha256_hex, Durability, Receipt, Scheme, SignCfg, Signer, VerifyTrust};
use ductei_qhr::lanes::{CpuLane, LlmLane};
use ductei_qhr::qpu::{safe_job_id, QpuConfig, QpuLane};
use ductei_qhr::{Assurance, Job, Lane, LaneId, Qhr, Report, Status};
use ductei_router::{brain::Ollama, sha256_json, Canon, Effect, Kind, Task, Tier, Verdict};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

// ---------------------------------------------------------------- config

fn default_weighter() -> String { "uniform".into() }

/// The `[os]` table of an atrium.toml. Other tables in that file belong to
/// other rooms and are ignored here. Inside `[os]` an unknown key is an
/// error, so a typo cannot silently drop a setting.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OsConfig {
    /// QHR state dir: sign.toml, canon.toml (optional), the signing key and
    /// the two receipt chains (`verified/`, `fast/`).
    pub state: PathBuf,
    /// limend spool. Absent: no QPU lane, so `qpu.*` jobs are refused in pre-flight.
    #[serde(default)]
    pub spool: Option<PathBuf>,
    /// Where receipts are persisted. Absent: they stay in the QHR chain only.
    #[serde(default)]
    pub persist: Option<PersistCfg>,
    /// SHA-256 hex of the key receipts must be signed with. `open` refuses any
    /// other key (or no key), and `receipt` checks pin to it.
    #[serde(default)]
    pub pubkey_fingerprint: Option<String>,
    /// Register the local LLM lane (Ollama on this machine).
    #[serde(default)]
    pub llm: bool,
    /// Lane weighter: uniform or evidence.
    #[serde(default = "default_weighter")]
    pub weighter: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistCfg {
    /// This crate's own DUCTEI channel dir (accepted.jsonl, rejected.jsonl, node id).
    pub channel: PathBuf,
    /// ductei-qallow-relay binary. With `qallow_cli` and `store` also set,
    /// every receipt is handed to Qallow before `submit` returns.
    #[serde(default)]
    pub qallow_relay: Option<PathBuf>,
    #[serde(default)]
    pub qallow_cli: Option<PathBuf>,
    /// Qallow's LMDB store dir.
    #[serde(default)]
    pub store: Option<PathBuf>,
    /// The relay's working tree. Default: `qallow-out` next to `channel`.
    #[serde(default)]
    pub out: Option<PathBuf>,
}

#[derive(Deserialize)]
struct OsFile { os: OsConfig }

fn no_bom(text: &str) -> &str { text.trim_start_matches('\u{feff}') }

impl OsConfig {
    pub fn parse(text: &str) -> Result<Self, String> {
        toml::from_str::<OsFile>(no_bom(text)).map(|f| f.os).map_err(|e| format!("[os] table: {e}"))
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Self::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// Every directory this config writes to must pass CANON (never on C:).
    /// The binary calls this before anything is opened.
    pub fn canon_paths(&self) -> Result<(), String> {
        let mut dirs: Vec<(&str, &Path)> = vec![("state", self.state.as_path())];
        if let Some(s) = &self.spool { dirs.push(("spool", s.as_path())); }
        if let Some(p) = &self.persist {
            dirs.push(("persist.channel", p.channel.as_path()));
            if let Some(s) = &p.store { dirs.push(("persist.store", s.as_path())); }
            if let Some(o) = &p.out { dirs.push(("persist.out", o.as_path())); }
        }
        for (what, dir) in dirs {
            let probe = Task { id: what.into(), intent: "atrium-os config path".into(), kind: Kind::Chat, criticality: 0, private: true, effects: vec![Effect::Write(dir.to_path_buf())] };
            if let Verdict::Deny(r) = Canon::default().check(&probe, &[]) { return Err(format!("[os] {what} refused: {r}")); }
        }
        Ok(())
    }
}

fn load_sign(state: &Path) -> Result<SignCfg, String> {
    let p = state.join("sign.toml");
    match fs::read_to_string(&p) {
        Ok(t) => toml::from_str(no_bom(&t)).map_err(|e| format!("{}: {e}", p.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(SignCfg::default()),
        // Unreadable is not absent: running unsigned here would be a silent downgrade.
        Err(e) => Err(format!("{}: {e}", p.display())),
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// A serde unit variant from its tag ("t0_local" -> Tier::T0Local), and back.
fn untag<T: DeserializeOwned>(s: &str) -> Result<T, String> {
    serde_json::from_value(serde_json::Value::String(s.to_string())).map_err(|e| e.to_string())
}
fn tag<T: Serialize>(v: &T) -> String {
    serde_json::to_value(v).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default()
}

// ---------------------------------------------------------------- request

const REQUEST_KEYS: [&str; 10] = ["id", "intent", "op", "payload", "budget_ms", "kind", "private", "assurance", "effects_json", "effects"];

/// Read a job file. Two conveniences over the bare `JobRequest` shape, both
/// turned into the canonical string fields before anything is hashed:
/// `payload` may be a JSON object, and `effects` may be a JSON list.
/// Unknown keys are refused, so a typo cannot silently drop a constraint.
pub fn parse_request(text: &str) -> Result<JobRequest, String> {
    let mut v: serde_json::Value = serde_json::from_str(no_bom(text)).map_err(|e| format!("job is not JSON: {e}"))?;
    let obj = v.as_object_mut().ok_or("job must be a JSON object")?;
    if let Some(k) = obj.keys().find(|k| !REQUEST_KEYS.contains(&k.as_str())) {
        return Err(format!("unknown job field {k:?}"));
    }
    if let Some(p) = obj.get("payload").filter(|p| !p.is_string()).cloned() {
        obj.insert("payload".into(), serde_json::Value::String(p.to_string()));
    }
    if let Some(e) = obj.remove("effects") {
        if obj.contains_key("effects_json") { return Err("give effects or effects_json, not both".into()); }
        obj.insert("effects_json".into(), serde_json::Value::String(e.to_string()));
    }
    serde_json::from_value(v).map_err(|e| format!("job: {e}"))
}

/// The QHR job a request stands for. Refuses a request the door must not pass on.
pub fn to_job(req: &JobRequest) -> Result<Job, String> {
    safe_job_id(&req.id)?;
    if req.op.is_empty() { return Err("op is empty".into()); }
    let kind: Kind = untag(req.kind.as_deref().unwrap_or("code"))
        .map_err(|_| format!("unknown kind {:?}: use classify, chat, code, research or quantum", req.kind.as_deref().unwrap_or("")))?;
    let assurance: Assurance = untag(req.assurance.as_deref().unwrap_or("verified"))
        .map_err(|_| format!("unknown assurance {:?}: use verified or fast", req.assurance.as_deref().unwrap_or("")))?;
    let effects: Vec<Effect> = match req.effects_json.as_deref() {
        None | Some("") => Vec::new(),
        Some(t) => serde_json::from_str(t).map_err(|e| format!("effects_json is not a list of router effects: {e}"))?,
    };
    Ok(Job {
        task: Task { id: req.id.clone(), intent: req.intent.clone(), kind, criticality: 0, private: req.private.unwrap_or(true), effects },
        op: req.op.clone(),
        payload: req.payload.clone(),
        budget_ms: req.budget_ms,
        assurance,
    })
}

/// Exit code of `atrium submit` for a receipt.
pub fn exit_code(rc: &JobReceipt) -> u8 {
    match rc.verdict.as_str() {
        "done" => spec::OS_EXIT_DONE,
        "needs_approval" => spec::OS_EXIT_NEEDS_APPROVAL,
        "denied" | "refused" => spec::OS_EXIT_REFUSED,
        _ => spec::OS_EXIT_FAILED,
    }
}

// ---------------------------------------------------------------- receipt

/// The fields of a receipt that are a reading of the status, not new facts.
#[derive(Debug, Default, PartialEq)]
struct Summary {
    reason: Option<String>,
    backend: Option<String>,
    success_probability: Option<f64>,
    target_met: Option<bool>,
}

fn summarize(status: &Status) -> Summary {
    match status {
        Status::Done(out) => {
            let v: serde_json::Value = serde_json::from_str(out).unwrap_or(serde_json::Value::Null);
            Summary {
                reason: None,
                backend: v.get("backend").and_then(|x| x.as_str()).map(String::from),
                success_probability: v.get("success_probability").and_then(|x| x.as_f64()),
                target_met: v.get("target_met").and_then(|x| x.as_bool()),
            }
        }
        Status::Denied(why) | Status::Refused(why) | Status::LaneError(why) => Summary { reason: Some(why.clone()), ..Default::default() },
        Status::NeedsApproval(need) => Summary { reason: Some(format!("needs approval: {}", need.join(", "))), ..Default::default() },
        Status::DeadlineMissed { budget_ms } => Summary { reason: Some(format!("deadline missed: the budget was {budget_ms} ms")), ..Default::default() },
    }
}

fn receipt_from(job: &Job, r: &Report, scheme: &str, fingerprint: Option<String>) -> Result<JobReceipt, String> {
    let s = summarize(&r.status);
    Ok(JobReceipt {
        contract_ver: spec::OS_CONTRACT_VER,
        job_id: job.task.id.clone(),
        verdict: r.status.label().into(),
        reason: s.reason,
        tier: tag(&r.tier),
        lane: r.lane.map(|l| l.as_str().to_string()),
        backend: s.backend,
        success_probability: s.success_probability,
        target_met: s.target_met,
        status_json: serde_json::to_string(&r.status).map_err(|e| e.to_string())?,
        pick_why: r.pick_why.clone(),
        job_sha256: sha256_json(job),
        // Must stay the exact tuple Qhr::submit hashes into the chain entry;
        // `verify_receipt` compares the two, and the tests submit then verify.
        result_sha256: sha256_json(&(&job.task.id, r.tier, r.lane, &r.status, &r.pick_why)),
        chain: tag(&job.assurance),
        qhr_receipt: r.receipt.clone(),
        sig_scheme: scheme.into(),
        signer_fingerprint: fingerprint,
        persist_state: spec::OS_PERSIST_NONE,
        persist_key: None,
        persist_reason: None,
        issued_ms: now_ms(),
        elapsed_us: r.elapsed_us,
    })
}

/// The bytes that get persisted: the receipt as issued, before the persist
/// fields are filled in (a record cannot hold the proof of its own storage).
pub fn issued_bytes(rc: &JobReceipt) -> Result<Vec<u8>, String> {
    let mut c = rc.clone();
    c.persist_state = spec::OS_PERSIST_NONE;
    c.persist_key = None;
    c.persist_reason = None;
    serde_json::to_vec(&c).map_err(|e| e.to_string())
}

fn persist_key(job_id: &str) -> String { format!("{}{job_id}", spec::OS_RECEIPT_KEY_PREFIX) }

// ---------------------------------------------------------------- the door

pub struct Os {
    cfg: OsConfig,
    qhr: Qhr,
    channel: Option<(Channel, [u8; 16])>,
    scheme: &'static str,
    fingerprint: Option<String>,
}

impl Os {
    pub fn open(cfg: OsConfig) -> Result<Self, String> {
        let sign = load_sign(&cfg.state)?;
        let scheme = sign.scheme;
        if cfg.pubkey_fingerprint.is_some() && scheme == Scheme::None {
            return Err(format!("[os] pins a signing key but {} sets no scheme: refusing to run unsigned", cfg.state.join("sign.toml").display()));
        }
        let mut qhr = Qhr::open(&cfg.state, &sign, Durability { sync_every: 100, sync_max_ms: 10, background: true })?;
        // J-lens stays out until the jspace-lab readout validation passes (same rule as the qhr CLI).
        match cfg.weighter.as_str() {
            "uniform" => {}
            "evidence" => qhr.set_weighter(Box::new(ductei_qhr::weight::EvidenceWeighter)),
            w => return Err(format!("[os] weighter {w:?}: use uniform or evidence")),
        }
        qhr.register(Arc::new(CpuLane));
        if cfg.llm { qhr.register(Arc::new(LlmLane::ollama(Ollama::default()))); }
        if let Some(spool) = &cfg.spool { qhr.register(Arc::new(QpuLane::new(QpuConfig::new(spool.clone())))); }

        let fingerprint = if scheme == Scheme::None { None } else { Signer::load_public(&cfg.state)?.map(|(_, pk)| sha256_hex(&pk)) };
        if let Some(want) = &cfg.pubkey_fingerprint {
            if fingerprint.as_deref() != Some(want.to_lowercase().as_str()) {
                return Err(format!("signing key {} is not the key [os] pins ({want})", fingerprint.as_deref().unwrap_or("(none)")));
            }
        }

        let channel = match &cfg.persist {
            None => None,
            Some(p) => {
                let at = |e: std::io::Error| format!("{}: {e}", p.channel.display());
                fs::create_dir_all(&p.channel).map_err(at)?;
                let node = ductei_mcp::load_or_create_node_id(&p.channel).map_err(at)?;
                let ch = Channel::open(ScopePolicy::new().allow(spec::OS_RECEIPT_SCOPE), p.channel.join("accepted.jsonl"), p.channel.join("rejected.jsonl")).map_err(at)?;
                Some((ch, node))
            }
        };
        Ok(Self { cfg, qhr, channel, scheme: scheme.as_str(), fingerprint })
    }

    /// Signature scheme and key fingerprint this door signs with.
    pub fn signer(&self) -> (&'static str, Option<&str>) { (self.scheme, self.fingerprint.as_deref()) }

    /// One job, start to finish. `Err` means the door itself could not take
    /// the job (bad request, or the chain entry could not be written, in
    /// which case the result is withheld). Everything else, including a
    /// refusal, is a receipt.
    pub fn submit(&mut self, req: &JobRequest, approvals: &[String]) -> Result<JobReceipt, String> {
        let job = to_job(req)?;
        let report = self.qhr.submit(&job, approvals)?;
        self.qhr.flush().map_err(|e| format!("receipt flush failed, result withheld: {e}"))?;
        let mut rc = receipt_from(&job, &report, self.scheme, self.fingerprint.clone())?;
        self.persist(&mut rc);
        Ok(rc)
    }

    fn persist(&mut self, rc: &mut JobReceipt) {
        let (Some(p), Some((ch, node))) = (self.cfg.persist.as_ref(), self.channel.as_mut()) else {
            rc.persist_reason = Some("no [os.persist] table: the receipt lives in the QHR chain only".into());
            return;
        };
        let key = persist_key(&rc.job_id);
        let blob = match issued_bytes(rc) {
            Ok(b) => b,
            Err(e) => { rc.persist_reason = Some(format!("the receipt did not serialize: {e}")); return; }
        };
        let env = scoped(&key, &[spec::OS_RECEIPT_SCOPE], *node, rc.issued_ms, &blob);
        let mut session = ch.session(SessionBound::new(Some(1), None).expect("one envelope is a valid bound"));
        let sent = session.send(env, 1);
        session.close();
        if let Err(e) = sent {
            rc.persist_reason = Some(format!("the DUCTEI channel refused the receipt: {e:?}"));
            return;
        }
        rc.persist_state = spec::OS_PERSIST_CHANNEL;
        rc.persist_key = Some(key.clone());
        match qallow_hop(p, &key, &blob) {
            Ok(true) => rc.persist_state = spec::OS_PERSIST_QALLOW,
            Ok(false) => rc.persist_reason = Some("no Qallow hop configured (qallow_relay, qallow_cli, store): the receipt is in the DUCTEI channel log only".into()),
            Err(e) => rc.persist_reason = Some(format!("Qallow did not confirm: {e}")),
        }
    }
}

/// Run the existing relay once over this crate's channel, then read the
/// receipt back out of Qallow. `Ok(true)` only when the store returns the
/// exact bytes that were sent.
fn qallow_hop(p: &PersistCfg, key: &str, blob: &[u8]) -> Result<bool, String> {
    let (Some(relay), Some(cli), Some(store)) = (&p.qallow_relay, &p.qallow_cli, &p.store) else { return Ok(false) };
    let out = p.out.clone().unwrap_or_else(|| p.channel.with_file_name("qallow-out"));
    let run = Command::new(relay).arg(&p.channel).arg(&out).arg("--once").arg("--qallow-cli").arg(cli).arg("--store-dir").arg(store)
        .output().map_err(|e| format!("{} did not start: {e}", relay.display()))?;
    if !run.status.success() {
        return Err(format!("{} exited {:?}: {}", relay.display(), run.status.code(), String::from_utf8_lossy(&run.stderr).trim()));
    }
    match qallow_get(cli, store, key)? {
        Some(v) if v.as_bytes() == blob => Ok(true),
        Some(_) => Err("Qallow holds a different value under this key".into()),
        None => Err(format!("the relay ran but Qallow has nothing under this key; see {}", out.join("failed").display())),
    }
}

fn qallow_get(cli: &Path, store: &Path, key: &str) -> Result<Option<String>, String> {
    // Qallow's store key is the sorted scope set, then "|", then the envelope key.
    let store_key = format!("{}|{key}", spec::OS_RECEIPT_SCOPE);
    let o = Command::new(cli).arg("get").arg(store).arg(&store_key).output().map_err(|e| format!("{} did not start: {e}", cli.display()))?;
    if !o.status.success() {
        return Err(format!("qallow get exited {:?}: {}", o.status.code(), String::from_utf8_lossy(&o.stderr).trim()));
    }
    let text = String::from_utf8_lossy(&o.stdout);
    let text = text.trim();
    if text == "NOT_FOUND" { return Ok(None); }
    match text.strip_prefix("FOUND:") {
        Some(v) => Ok(Some(v.to_string())),
        None => Err(format!("qallow get printed something unexpected: {:?}", text.chars().take(80).collect::<String>())),
    }
}

// ---------------------------------------------------------------- verify

/// What a successful receipt check established.
#[derive(Debug, Default)]
pub struct Checked {
    /// Position of the entry in its chain.
    pub seq: u64,
    pub chain_receipts: u64,
    /// Fingerprint of the key the chain was checked against, if any.
    pub kid: Option<String>,
    pub warnings: Vec<String>,
}

fn same(errs: &mut Vec<String>, what: &str, got: &str, want: &str) {
    if got != want { errs.push(format!("{what}: the receipt says {got:?}, the chain entry says {want:?}")); }
}

fn find_entry(chain_dir: &Path, hash: &str) -> Result<Option<Receipt>, String> {
    let p = chain_dir.join("receipts.jsonl");
    let f = fs::File::open(&p).map_err(|e| format!("{}: {e}", p.display()))?;
    for line in BufReader::new(f).lines() {
        let line = line.map_err(|e| format!("{}: {e}", p.display()))?;
        if let Ok(r) = serde_json::from_str::<Receipt>(&line) {
            if r.hash == hash { return Ok(Some(r)); }
        }
    }
    Ok(None)
}

/// Check a receipt against the signed chain it points into. Nothing in the
/// receipt is taken on trust:
///
/// 0. the whole chain verifies (hash links, signatures, key pin);
/// 1. the entry it names exists, and agrees on job id, verdict, lane, both
///    hashes, scheme and signing key;
/// 2. its outcome fields hash to the entry's signed result hash, and its
///    summary fields are exactly what that outcome says;
/// 3. the job, if supplied, hashes to the entry's signed job hash;
/// 4. the persisted copy, where one is claimed, is byte-identical.
///
/// A pinned key means "signed by this key": an unsigned chain or entry fails
/// under a pin here (the shared chain verifier reports that as a warning).
pub fn verify_receipt(cfg: &OsConfig, rc: &JobReceipt, request: Option<&JobRequest>, trust: &VerifyTrust) -> Result<Checked, Vec<String>> {
    let mut errs: Vec<String> = Vec::new();
    let mut out = Checked::default();
    if rc.contract_ver != spec::OS_CONTRACT_VER {
        errs.push(format!("contract version {} (this build reads {})", rc.contract_ver, spec::OS_CONTRACT_VER));
    }
    // Also keeps a hostile chain name from being joined onto the state path.
    if rc.chain != "verified" && rc.chain != "fast" { return Err(vec![format!("unknown chain {:?}", rc.chain)]); }

    match ductei_qhr::verify_state(&cfg.state, &rc.chain, trust) {
        Err(e) => return Err(vec![format!("the chain check could not run: {e}")]),
        Ok(rep) => {
            errs.extend(rep.errors);
            out.warnings = rep.warnings;
            out.chain_receipts = rep.receipts;
            out.kid = rep.kid;
        }
    }
    let pinned = trust.fingerprint.as_ref().map(|f| f.to_lowercase()).or_else(|| trust.pubkey.as_ref().map(|pk| sha256_hex(pk)));
    if let Some(want) = &pinned {
        if out.kid.as_deref() != Some(want.as_str()) { errs.push(format!("the chain is not signed by the pinned key {want}")); }
    }

    let entry = match find_entry(&cfg.state.join(&rc.chain), &rc.qhr_receipt) {
        Ok(Some(r)) => r,
        Ok(None) => {
            errs.push(format!("no entry with hash {} in the {} chain", rc.qhr_receipt.get(..16).unwrap_or(&rc.qhr_receipt), rc.chain));
            return Err(errs);
        }
        Err(e) => { errs.push(e); return Err(errs); }
    };
    out.seq = entry.body.seq;
    let b = &entry.body;
    same(&mut errs, "job id", &rc.job_id, &b.key);
    same(&mut errs, "verdict", &rc.verdict, &b.verdict);
    same(&mut errs, "job hash", &rc.job_sha256, &b.call_sha256);
    same(&mut errs, "result hash", &rc.result_sha256, &b.result_sha256);
    same(&mut errs, "lane", &format!("qhr:{}", rc.lane.as_deref().unwrap_or("none")), &b.scope);
    same(&mut errs, "signature scheme", &rc.sig_scheme, &entry.scheme);
    if entry.scheme != "none" {
        same(&mut errs, "signing key", rc.signer_fingerprint.as_deref().unwrap_or(""), &b.kid);
    } else if rc.signer_fingerprint.is_some() {
        errs.push("the receipt names a signing key but the chain entry is unsigned".into());
    }
    if pinned.is_some() && (entry.scheme == "none" || entry.sig.is_none()) {
        errs.push("a key is pinned but this chain entry is unsigned".into());
    }

    let parsed = (
        serde_json::from_str::<Status>(&rc.status_json),
        untag::<Tier>(&rc.tier),
        rc.lane.as_deref().map(untag::<LaneId>).transpose(),
    );
    match parsed {
        (Ok(status), Ok(tier), Ok(lane)) => {
            if sha256_json(&(&rc.job_id, tier, lane, &status, &rc.pick_why)) != rc.result_sha256 {
                errs.push("the outcome fields (status, tier, lane, pick) do not hash to the signed result hash".into());
            }
            if status.label() != rc.verdict { errs.push(format!("verdict {:?} is not what the status says ({})", rc.verdict, status.label())); }
            let mine = Summary { reason: rc.reason.clone(), backend: rc.backend.clone(), success_probability: rc.success_probability, target_met: rc.target_met };
            if summarize(&status) != mine {
                errs.push("summary fields (reason, backend, success_probability, target_met) are not what the signed status says".into());
            }
        }
        _ => errs.push("status_json, tier or lane does not parse".into()),
    }

    if let Some(req) = request {
        match to_job(req) {
            Ok(job) => if sha256_json(&job) != rc.job_sha256 { errs.push("the job file is not the job this receipt was issued for".into()); },
            Err(e) => errs.push(format!("job file: {e}")),
        }
    }

    check_persist(cfg, rc, &mut errs, &mut out.warnings);
    if errs.is_empty() { Ok(out) } else { Err(errs) }
}

fn check_persist(cfg: &OsConfig, rc: &JobReceipt, errs: &mut Vec<String>, warns: &mut Vec<String>) {
    if rc.persist_state == spec::OS_PERSIST_NONE {
        if rc.persist_key.is_some() { errs.push("persist_state is NONE but a persist key is set".into()); }
        return;
    }
    if rc.persist_state != spec::OS_PERSIST_CHANNEL && rc.persist_state != spec::OS_PERSIST_QALLOW {
        errs.push(format!("unknown persist_state {}", rc.persist_state));
        return;
    }
    let key = persist_key(&rc.job_id);
    if rc.persist_key.as_deref() != Some(key.as_str()) {
        errs.push(format!("the persist key should be {key:?}"));
        return;
    }
    let Some(p) = &cfg.persist else {
        warns.push("persistence not checked: this config has no [os.persist] table".into());
        return;
    };
    let blob = match issued_bytes(rc) {
        Ok(b) => b,
        Err(e) => { errs.push(e); return; }
    };
    let log = p.channel.join("accepted.jsonl");
    let in_channel = log.exists()
        && LogStore::open(&log).and_then(|l| l.replay(0)).map(|(envs, _)| envs.iter().any(|e| e.key == key && e.blob == blob)).unwrap_or(false);
    if !in_channel { errs.push(format!("the receipt is not in the DUCTEI channel log {}", log.display())); }
    if rc.persist_state == spec::OS_PERSIST_QALLOW {
        match (&p.qallow_cli, &p.store) {
            (Some(cli), Some(store)) => match qallow_get(cli, store, &key) {
                Ok(Some(v)) if v.as_bytes() == blob.as_slice() => {}
                Ok(Some(_)) => errs.push("Qallow holds a different value under this key (a later receipt for the same job id replaces an earlier one)".into()),
                Ok(None) => errs.push("Qallow does not hold this receipt".into()),
                Err(e) => errs.push(format!("Qallow could not be read: {e}")),
            },
            _ => warns.push("Qallow copy not checked: qallow_cli and store are not configured".into()),
        }
    }
}

// ---------------------------------------------------------------- health (N5)

/// One N5 health report per room on the job path. Read-only: it never
/// creates a key, a dir or a log, so it is safe to run at any time.
pub fn health(cfg: &OsConfig) -> Vec<base::Health> {
    let now = now_ms();
    let mk = |room: &str, state: u8, reason: Option<String>| base::Health { room: room.into(), state, reason, checked_ms: now };
    let mut out = Vec::with_capacity(3);

    out.push(match state_health(cfg) {
        Ok(None) => mk("os.state", base::HEALTH_OK, None),
        Ok(Some(why)) => mk("os.state", base::HEALTH_DEGRADED, Some(why)),
        Err(why) => mk("os.state", base::HEALTH_DOWN, Some(why)),
    });

    // The QHR lane's own health check, in the one shape every room reports in.
    out.push(match &cfg.spool {
        None => mk("os.limen", base::HEALTH_DEGRADED, Some("no spool configured: qpu.* jobs are refused in pre-flight".into())),
        Some(s) => match QpuLane::new(QpuConfig::new(s.clone())).health() {
            ductei_qhr::Health::Ready => mk("os.limen", base::HEALTH_OK, None),
            ductei_qhr::Health::Unavailable(why) => mk("os.limen", base::HEALTH_DOWN, Some(why)),
        },
    });

    out.push(match &cfg.persist {
        None => mk("os.persist", base::HEALTH_DEGRADED, Some("no [os.persist] table: receipts stay in the QHR chain only".into())),
        Some(p) => match (&p.qallow_relay, &p.qallow_cli, &p.store) {
            (Some(relay), Some(cli), Some(_)) => {
                let missing: Vec<String> = [relay, cli].iter().filter(|f| !f.is_file()).map(|f| f.display().to_string()).collect();
                if missing.is_empty() { mk("os.persist", base::HEALTH_OK, None) }
                else { mk("os.persist", base::HEALTH_DOWN, Some(format!("missing: {}", missing.join(", ")))) }
            }
            _ => mk("os.persist", base::HEALTH_DEGRADED, Some("no Qallow hop configured (qallow_relay, qallow_cli, store): receipts stop at the DUCTEI channel log".into())),
        },
    });
    out
}

/// `Ok(None)` healthy, `Ok(Some(why))` working but worth knowing, `Err(why)` not usable.
fn state_health(cfg: &OsConfig) -> Result<Option<String>, String> {
    if !cfg.state.is_dir() { return Ok(Some(format!("{} does not exist yet; the first submit creates it", cfg.state.display()))); }
    let sign = load_sign(&cfg.state)?;
    if sign.scheme == Scheme::None {
        if cfg.pubkey_fingerprint.is_some() { return Err("[os] pins a signing key but sign.toml sets no scheme".into()); }
        return Ok(Some("receipts are hash-chained but unsigned (sign.toml sets no scheme)".into()));
    }
    let Some((_, pk)) = Signer::load_public(&cfg.state)? else {
        return Ok(Some("signing is configured but no key exists yet; the first submit mints one".into()));
    };
    let fp = sha256_hex(&pk);
    match &cfg.pubkey_fingerprint {
        Some(want) if want.to_lowercase() != fp => Err(format!("signing key {fp} is not the key [os] pins ({want})")),
        Some(_) => Ok(None),
        None => Ok(Some(format!("signing key {fp} is not pinned in [os] pubkey_fingerprint"))),
    }
}
