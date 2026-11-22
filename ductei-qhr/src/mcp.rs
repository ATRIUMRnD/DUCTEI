//! QHR tools for the router's MCP server: `qhr_submit` and `qhr_verify`.
//! `qhr serve` runs ductei-router's server with these added, so one stdio
//! server exposes decide / classify / outcome / qhr_submit / qhr_verify.
//! Input is data; a Job goes through the same CANON gate and router as any
//! other task, and the state dir must itself pass CANON.

use crate::{verify_state, Job, Qhr};
use ductei_mcp::VerifyTrust;
use ductei_router::mcp::ToolExt;
use serde_json::{json, Value};
use std::path::PathBuf;

pub struct QhrExt {
    pub state: PathBuf,
    pub qhr: Qhr,
}

impl ToolExt for QhrExt {
    fn tools(&self) -> Vec<Value> {
        vec![
            json!({ "name": "qhr_submit", "description": "Submit one job to the Quantum Hybrid Runtime: CANON gate, router, ABA pre-flight, lane pick (uniform|evidence weighter), run within budget_ms, hash-chained receipt. Lanes: cpu, llm (local Ollama), qpu (when a LIMEN spool is configured). Returns the Report; status is done | denied | needs_approval | refused | lane_error | deadline_missed.",
              "inputSchema": { "type": "object", "required": ["job"], "properties": {
                  "job": { "type": "object", "description": "Job: task (same shape as decide's task), op (cpu.sha256 | llm.complete | qpu.run | unprefixed = any lane), payload string, budget_ms, assurance (verified|fast)" },
                  "approvals": { "type": "array", "items": { "type": "string" }, "description": "Approval tokens granted in chat" } } } }),
            json!({ "name": "qhr_verify", "description": "Cold-verify a QHR receipt chain (verified or fast) in the server's state dir against the pinned signing key. Returns receipts, errors, warnings, key id.",
              "inputSchema": { "type": "object", "properties": {
                  "chain": { "type": "string", "enum": ["verified", "fast"], "default": "verified" },
                  "fingerprint": { "type": "string", "description": "Expected sha256 of the signing public key (from `qhr fingerprint`). Required unless allow_unpinned; an unpinned check only proves chain integrity, not who signed." },
                  "allow_unpinned": { "type": "boolean", "default": false } } } }),
        ]
    }

    fn call(&mut self, name: &str, args: &Value) -> Option<Result<Value, String>> {
        match name {
            "qhr_submit" => Some((|| {
                let job: Job = serde_json::from_value(args.get("job").cloned().unwrap_or(Value::Null)).map_err(|e| format!("bad job: {e}"))?;
                let approvals: Vec<String> = serde_json::from_value(args.get("approvals").cloned().unwrap_or(json!([]))).map_err(|e| format!("bad approvals: {e}"))?;
                let report = self.qhr.submit(&job, &approvals)?;
                self.qhr.flush().map_err(|e| e.to_string())?;
                serde_json::to_value(report).map_err(|e| e.to_string())
            })()),
            "qhr_verify" => Some((|| {
                let chain = args.get("chain").and_then(Value::as_str).unwrap_or("verified");
                if chain != "verified" && chain != "fast" { return Err(format!("chain must be verified or fast, got {chain:?}")); }
                let trust = VerifyTrust {
                    fingerprint: args.get("fingerprint").and_then(Value::as_str).map(String::from),
                    allow_unpinned: args.get("allow_unpinned").and_then(Value::as_bool).unwrap_or(false),
                    ..VerifyTrust::default()
                };
                if !self.state.join(chain).join("receipts.jsonl").exists() {
                    return Ok(json!({ "chain": chain, "receipts": 0, "errors": [], "warnings": ["no receipts yet"], "ok": true }));
                }
                let rep = verify_state(&self.state, chain, &trust)?;
                Ok(json!({ "chain": chain, "receipts": rep.receipts, "errors": rep.errors, "warnings": rep.warnings, "kid": rep.kid, "ok": rep.ok() }))
            })()),
            _ => None,
        }
    }
}
