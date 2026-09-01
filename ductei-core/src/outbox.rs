use crate::{Envelope};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind")]
enum OutboundRecord {
    Intent { env: Envelope },
    Receipt { key: String, lamport: u64, node_id: [u8; 16], ack: u8 },
}

/// Durable append-only log of outbound send intents and receipts.
/// Separate from the Channel's accepted log; never part of Channel replay
/// or any Qallow ingestion path. Fsynced on every write.
pub struct Outbox {
    path: PathBuf,
    file: File,
}

impl Outbox {
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self { path, file })
    }

    /// Record the intent to send this envelope. Must be called before any network I/O.
    pub fn record_intent(&mut self, env: &Envelope) -> std::io::Result<()> {
        let rec = OutboundRecord::Intent { env: env.clone() };
        let line = serde_json::to_string(&rec).map_err(std::io::Error::other)?;
        writeln!(self.file, "{line}")?;
        self.file.sync_data()
    }

    /// Record a receipt outcome (ack code). 1=applied, 2=stale/already-present, 0=rejected.
    pub fn record_receipt(&mut self, key: &str, lamport: u64, node_id: &[u8; 16], ack: u8) -> std::io::Result<()> {
        let rec = OutboundRecord::Receipt {
            key: key.to_string(),
            lamport,
            node_id: *node_id,
            ack,
        };
        let line = serde_json::to_string(&rec).map_err(std::io::Error::other)?;
        writeln!(self.file, "{line}")?;
        self.file.sync_data()
    }

    /// Compute envelopes that were intended but have no successful receipt yet (ack 1 or 2).
    pub fn pending(&self) -> std::io::Result<Vec<Envelope>> {
        let f = File::open(&self.path)?;
        let mut last_intent: HashMap<(String, u64, [u8; 16]), Envelope> = HashMap::new();
        let mut resolved: HashMap<(String, u64, [u8; 16]), bool> = HashMap::new();
        for line in BufReader::new(f).lines() {
            let line = line?;
            let Ok(rec) = serde_json::from_str::<OutboundRecord>(&line) else { continue };
            match rec {
                OutboundRecord::Intent { env } => {
                    last_intent.insert((env.key.clone(), env.lamport, env.node_id), env);
                }
                OutboundRecord::Receipt { key, lamport, node_id, ack } => {
                    // Any receipt resolves the intent for retry purposes:
                    // 1/2 are successful receipts; 0 is a definitive rejection.
                    let _ = ack;
                    resolved.insert((key, lamport, node_id), true);
                }
            }
        }
        let mut out = Vec::new();
        for (triple, env) in last_intent {
            if !resolved.contains_key(&triple) {
                out.push(env);
            }
        }
        Ok(out)
    }
}

