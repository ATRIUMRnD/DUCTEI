//! Hash-chained, fsynced receipt ledger. Every verdict is recorded; a broken
//! chain refuses to open, which rejects everything until a human looks.

use crate::{History, Verdict};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

const DOMAIN: &[u8] = b"ductei-verify/receipt/v1\0";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub seq: u64,
    pub ts: u64,
    pub task_id: String,
    pub accepted: bool,
    pub train_eligible: bool,
    pub reasons: Vec<String>,
    pub candidate_sha256: String,
    pub prev: String,
    pub hash: String,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn sha256_hex(b: &[u8]) -> String {
    hex(&Sha256::digest(b))
}

fn genesis() -> String {
    "0".repeat(64)
}

fn body_hash(r: &Receipt) -> Result<String, String> {
    let mut c = r.clone();
    c.hash = String::new();
    let j = serde_json::to_string(&c).map_err(|e| e.to_string())?;
    Ok(hex(&Sha256::new().chain_update(DOMAIN).chain_update(j.as_bytes()).finalize()))
}

#[derive(Debug)]
pub struct Ledger {
    path: PathBuf,
    receipts: Vec<Receipt>,
}

impl Ledger {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref().to_path_buf();
        let text = match fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(format!("ledger: {e}")),
        };
        let mut receipts: Vec<Receipt> = Vec::new();
        for (i, line) in text.lines().filter(|l| !l.trim().is_empty()).enumerate() {
            let r: Receipt = serde_json::from_str(line).map_err(|e| format!("ledger corrupt at line {}: {e}", i + 1))?;
            let prev = receipts.last().map(|p| p.hash.clone()).unwrap_or_else(genesis);
            if r.seq != i as u64 || r.prev != prev || r.hash != body_hash(&r)? {
                return Err(format!("ledger tampered at seq {i}"));
            }
            receipts.push(r);
        }
        Ok(Self { path, receipts })
    }

    pub fn len(&self) -> usize {
        self.receipts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.receipts.is_empty()
    }

    pub fn history(&self, task_id: &str, now: u64) -> History {
        let day = now / 86_400;
        History {
            attempts_for_task: self.receipts.iter().filter(|r| r.task_id == task_id).count() as u32,
            accepts_today: self.receipts.iter().filter(|r| r.accepted && r.ts / 86_400 == day).count() as u32,
        }
    }

    pub fn append(&mut self, v: &Verdict, candidate_sha256: &str, now: u64) -> Result<Receipt, String> {
        let mut r = Receipt {
            seq: self.receipts.len() as u64,
            ts: now,
            task_id: v.task_id.clone(),
            accepted: v.accepted,
            train_eligible: v.train_eligible,
            reasons: v.reasons.clone(),
            candidate_sha256: candidate_sha256.into(),
            prev: self.receipts.last().map(|p| p.hash.clone()).unwrap_or_else(genesis),
            hash: String::new(),
        };
        r.hash = body_hash(&r)?;
        let line = serde_json::to_string(&r).map_err(|e| e.to_string())?;
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir).map_err(|e| format!("ledger dir: {e}"))?;
        }
        let mut f = OpenOptions::new().create(true).append(true).open(&self.path).map_err(|e| format!("ledger: {e}"))?;
        writeln!(f, "{line}").map_err(|e| format!("ledger: {e}"))?;
        f.sync_all().map_err(|e| format!("ledger fsync: {e}"))?;
        self.receipts.push(r.clone());
        Ok(r)
    }
}
