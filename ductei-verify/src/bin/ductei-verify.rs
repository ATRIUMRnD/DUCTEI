#[path = "../gitdiff.rs"]
mod gitdiff;

use ductei_verify::{adapter_gate, sha256_hex, verify, Candidate, Ledger, Policy, Source, SystemRunner};
use gitdiff::candidate_from_git;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

const USAGE: &str = "usage:
  ductei-verify check-git --policy FILE --worktree DIR --task ID [--jlens SCORE] [--commands FILE] [--sources FILE]
      builds the candidate from git itself (preferred)
  ductei-verify check --policy FILE --candidate FILE
  ductei-verify eval  --policy FILE --old SCORE --new SCORE
  ductei-verify audit --ledger FILE
exit codes: 0 accept, 1 reject, 2 error";

fn main() -> ExitCode {
    match run() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ductei-verify: {e}");
            ExitCode::from(2)
        }
    }
}

fn opt(args: &[String], k: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == k).map(|w| w[1].clone())
}

fn arg(args: &[String], k: &str) -> Result<String, String> {
    opt(args, k).ok_or_else(|| format!("missing {k}\n{USAGE}"))
}

fn num(args: &[String], k: &str) -> Result<f64, String> {
    arg(args, k)?.parse().map_err(|e| format!("{k}: {e}"))
}

fn json_file<T: serde::de::DeserializeOwned + Default>(args: &[String], k: &str) -> Result<T, String> {
    match opt(args, k) {
        None => Ok(T::default()),
        Some(p) => {
            let raw = std::fs::read(&p).map_err(|e| format!("{p}: {e}"))?;
            serde_json::from_slice(&raw).map_err(|e| format!("{p}: {e}"))
        }
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn decide(policy: &Policy, cand: &Candidate, raw: &[u8]) -> Result<ExitCode, String> {
    let mut ledger = Ledger::open(&policy.ledger)?;
    let t = now();
    let v = verify(policy, cand, &ledger.history(&cand.task_id, t), &mut SystemRunner);
    ledger.append(&v, &sha256_hex(raw), t)?;
    println!("{}", serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?);
    Ok(if v.accepted { ExitCode::SUCCESS } else { ExitCode::from(1) })
}

fn run() -> Result<ExitCode, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("check-git") => {
            let policy = Policy::load(&arg(&args, "--policy")?)?;
            let jlens = match opt(&args, "--jlens") {
                Some(s) => Some(s.parse::<f64>().map_err(|e| format!("--jlens: {e}"))?),
                None => None,
            };
            let commands: Vec<String> = json_file(&args, "--commands")?;
            let sources: Vec<Source> = json_file(&args, "--sources")?;
            let cand = candidate_from_git(&arg(&args, "--worktree")?, &arg(&args, "--task")?, jlens, commands, sources)?;
            let raw = serde_json::to_vec(&cand).map_err(|e| e.to_string())?;
            decide(&policy, &cand, &raw)
        }
        Some("check") => {
            let policy = Policy::load(&arg(&args, "--policy")?)?;
            let raw = std::fs::read(arg(&args, "--candidate")?).map_err(|e| format!("candidate: {e}"))?;
            let cand: Candidate = serde_json::from_slice(&raw).map_err(|e| format!("candidate: {e}"))?;
            decide(&policy, &cand, &raw)
        }
        Some("eval") => {
            let policy = Policy::load(&arg(&args, "--policy")?)?;
            match adapter_gate(&policy, num(&args, "--old")?, num(&args, "--new")?) {
                Ok(()) => {
                    println!("keep new adapter");
                    Ok(ExitCode::SUCCESS)
                }
                Err(e) => {
                    println!("{e}");
                    Ok(ExitCode::from(1))
                }
            }
        }
        Some("audit") => {
            let l = Ledger::open(arg(&args, "--ledger")?)?;
            println!("ledger ok: {} receipts, chain intact", l.len());
            Ok(ExitCode::SUCCESS)
        }
        _ => Err(USAGE.into()),
    }
}
