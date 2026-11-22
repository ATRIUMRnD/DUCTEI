// Copyright (C) 2026 xingxerx
// Licensed under the Elastic License 2.0. See the LICENSE file in this crate.

//! atrium-os: the job door.
//!
//!   atrium-os submit  <config.toml> <job.json> [--approve a,b] [--out <receipt.json>]
//!       One job through QHR pre-flight, LIMEN, the signed chain and Qallow.
//!       Prints the receipt as JSON. Exit 0 done, 2 needs approval,
//!       3 denied or refused, 4 lane error or missed deadline, 1 not submitted.
//!   atrium-os receipt <config.toml> <receipt.json> [--job <job.json>]
//!                     [--fingerprint <hex> | --pubkey <file> | --allow-unpinned] [--anchor-file <peer accepted.jsonl>]
//!       Check a receipt against the signed chain and the persisted copy.
//!       The pin defaults to [os] pubkey_fingerprint. Exit 0 valid, 1 not.
//!   atrium-os health  <config.toml>
//!       One N5 health report per room on the job path, as JSON lines.
//!       Exit 0 all ok, 2 something degraded or down.
//!   atrium-os fingerprint <config.toml>
//!
//! <config.toml> is any TOML file with an [os] table (atrium.toml in production).
//! The front door forwards here: `atrium submit|receipt|os-health <config.toml> ...`.
#![forbid(unsafe_code)]

use atrium_os::{base, exit_code, health, parse_request, spec, verify_receipt, JobReceipt, Os, OsConfig};
use ductei_mcp::VerifyTrust;
use std::path::Path;

const USAGE: &str = "usage: atrium-os submit <config.toml> <job.json> [--approve a,b] [--out <receipt.json>]\n       atrium-os receipt <config.toml> <receipt.json> [--job <job.json>] [--fingerprint <hex> | --pubkey <file> | --allow-unpinned]\n       atrium-os health <config.toml>\n       atrium-os fingerprint <config.toml>";

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn read(path: &str) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))
}

fn config(args: &[String]) -> Result<OsConfig, String> {
    let path = args.get(2).filter(|a| !a.starts_with("--")).ok_or(USAGE)?;
    let cfg = OsConfig::load(Path::new(path))?;
    cfg.canon_paths()?;
    Ok(cfg)
}

fn cmd_submit(args: &[String]) -> Result<i32, String> {
    let cfg = config(args)?;
    let job_path = args.get(3).filter(|a| !a.starts_with("--")).ok_or(USAGE)?;
    let req = parse_request(&read(job_path)?).map_err(|e| format!("{job_path}: {e}"))?;
    let approvals: Vec<String> = arg(args, "--approve").map(|a| a.split(',').map(String::from).collect()).unwrap_or_default();
    let rc = Os::open(cfg)?.submit(&req, &approvals)?;
    let text = serde_json::to_string_pretty(&rc).map_err(|e| e.to_string())?;
    if let Some(out) = arg(args, "--out") {
        std::fs::write(&out, &text).map_err(|e| format!("{out}: {e}"))?;
    }
    println!("{text}");
    Ok(exit_code(&rc) as i32)
}

fn cmd_receipt(args: &[String]) -> Result<i32, String> {
    let cfg = config(args)?;
    let rc_path = args.get(3).filter(|a| !a.starts_with("--")).ok_or(USAGE)?;
    let rc: JobReceipt = serde_json::from_str(read(rc_path)?.trim_start_matches('\u{feff}')).map_err(|e| format!("{rc_path}: {e}"))?;
    let req = match arg(args, "--job") {
        Some(p) => Some(parse_request(&read(&p)?).map_err(|e| format!("{p}: {e}"))?),
        None => None,
    };
    let mut trust = VerifyTrust { fingerprint: arg(args, "--fingerprint").or_else(|| cfg.pubkey_fingerprint.clone()), unsigned_through: cfg.unsigned_through, ..Default::default() };
    if let Some(p) = arg(args, "--pubkey") { trust.pubkey = Some(std::fs::read(&p).map_err(|e| format!("--pubkey {p}: {e}"))?); }
    trust.allow_unpinned = args.iter().any(|a| a == "--allow-unpinned");
    // A peer's export of what it accepted: proves the chain tail was not cut on this machine.
    if let Some(f) = arg(args, "--anchor-file") { trust.anchors.extend(ductei_mcp::anchors_in(Path::new(&f))?); }

    match verify_receipt(&cfg, &rc, req.as_ref(), &trust) {
        Ok(c) => {
            let signed = match (&rc.signer_fingerprint, rc.sig_scheme.as_str()) {
                (Some(fp), scheme) if scheme != "none" => format!("signed {scheme} by {}", fp.get(..16).unwrap_or(fp)),
                _ => "UNSIGNED (integrity and order only)".to_string(),
            };
            let stored = match rc.persist_state {
                s if s == spec::OS_PERSIST_QALLOW => "in Qallow",
                s if s == spec::OS_PERSIST_CHANNEL => "in the DUCTEI channel log",
                _ => "in the QHR chain only",
            };
            let anchored = match (rc.anchor_seq, &rc.anchor_peers) {
                (Some(_), Some(peers)) => format!("anchored on {peers}"),
                (Some(_), None) => "anchored on this machine only".to_string(),
                (None, _) => "not anchored".to_string(),
            };
            println!("VALID  job {} verdict {} | {} chain seq {} of {} | {signed} | stored {stored} | {anchored}", rc.job_id, rc.verdict, rc.chain, c.seq, c.chain_receipts);
            for w in &c.warnings { println!("  warn  {w}"); }
            Ok(0)
        }
        Err(errs) => {
            println!("INVALID  job {}", rc.job_id);
            for e in &errs { println!("  ERROR {e}"); }
            Ok(spec::OS_EXIT_ERROR as i32)
        }
    }
}

fn cmd_health(args: &[String]) -> Result<i32, String> {
    let cfg = config(args)?;
    let reports = health(&cfg);
    for h in &reports { println!("{}", serde_json::to_string(h).map_err(|e| e.to_string())?); }
    Ok(if reports.iter().all(|h| h.state == base::HEALTH_OK) { 0 } else { 2 })
}

fn cmd_fingerprint(args: &[String]) -> Result<i32, String> {
    let cfg = config(args)?;
    match ductei_mcp::Signer::load_public(&cfg.state)? {
        Some((scheme, pk)) => println!("{} {}", scheme.as_str(), ductei_mcp::sha256_hex(&pk)),
        None => println!("unsigned"),
    }
    Ok(0)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let r = match args.get(1).map(String::as_str) {
        Some("submit") => cmd_submit(&args),
        Some("receipt") => cmd_receipt(&args),
        Some("health") => cmd_health(&args),
        Some("fingerprint") => cmd_fingerprint(&args),
        Some("--version" | "-V") => { println!("atrium-os {} (contract v{})", env!("CARGO_PKG_VERSION"), spec::OS_CONTRACT_VER); Ok(0) }
        _ => { eprintln!("{USAGE}"); Ok(64) }
    };
    match r {
        Ok(code) => std::process::exit(code),
        Err(e) => { eprintln!("atrium-os: {e}"); std::process::exit(spec::OS_EXIT_ERROR as i32) }
    }
}
