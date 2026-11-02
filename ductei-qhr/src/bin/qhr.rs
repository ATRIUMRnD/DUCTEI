//! qhr: verify a QHR state dir from a cold start, or submit one job.
//!
//!   qhr verify <state> [--pubkey <file> | --fingerprint <hex> | --allow-unpinned]
//!                      [--anchor <seq>:<hash>] [--anchor-file <peer channel.jsonl>]
//!       Checks both chains (verified/, fast/). Exit 0 only if both are clean.
//!   qhr submit <state> --job <job.json> [--spool <limen spool>] [--approve a,b] [--weighter uniform|evidence]
//!       Lanes: cpu, llm (local Ollama), qpu (when --spool is given). Prints the report
//!       as JSON. Exit 0 done, 2 needs approval, 3 denied/refused, 4 lane error/miss.
//!   qhr fingerprint <state>
//!   qhr prefetch --spool <limen spool> --request <limend request.json>
//!       Spools an offline request ahead of the clock and returns at once; the
//!       next qpu.run of the same request is served from the result. Prints the
//!       spooled id (or the cache key if already cached). Hardware requests refused.
//!   qhr serve <state> [--spool <dir>] [--weighter uniform|evidence] [--router-state <dir>]
//!       MCP stdio server: decide, classify, outcome, qhr_submit, qhr_verify.
//!       Router chain: --router-state, else DUCTEI_ROUTER_STATE, else <state>\router.
//!
//! State dir: the argument, else DUCTEI_QHR_STATE, else D:\dev\ductei-qhr-state.
//! The state dir itself must pass CANON (never on C:).

use ductei_mcp::{anchors_in, sha256_hex, Durability, SignCfg, Signer, VerifyTrust};
use ductei_qhr::lanes::{CpuLane, LlmLane};
use ductei_qhr::qpu::{QpuConfig, QpuLane};
use ductei_qhr::{verify_state, Job, Qhr, Status};
use ductei_router::{brain::Ollama, Canon, Effect, Kind, Task, Verdict};
use std::path::{Path, PathBuf};
use std::sync::Arc;

const DEFAULT_STATE: &str = r"D:\dev\ductei-qhr-state";
const USAGE: &str = "usage: qhr verify <state> [--pubkey <file> | --fingerprint <hex> | --allow-unpinned] [--anchor <seq>:<hash>] [--anchor-file <file>]\n       qhr submit <state> --job <job.json> [--spool <dir>] [--approve a,b] [--weighter uniform|evidence]\n       qhr fingerprint <state>\n       qhr prefetch --spool <dir> --request <request.json>";

fn cmd_prefetch(args: &[String]) -> Result<i32, String> {
    let spool = arg(args, "--spool").ok_or(USAGE)?;
    let req = arg(args, "--request").ok_or(USAGE)?;
    let probe = Task { id: "spool".into(), intent: "spool".into(), kind: Kind::Chat, criticality: 0, private: true, effects: vec![Effect::Write(PathBuf::from(&spool))] };
    if let Verdict::Deny(r) = Canon::default().check(&probe, &[]) { return Err(format!("spool refused: {r}")); }
    let payload = std::fs::read_to_string(&req).map_err(|e| format!("{req}: {e}"))?;
    println!("{}", QpuLane::new(QpuConfig::new(spool)).prefetch(&payload)?);
    Ok(0)
}

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn state_dir(args: &[String]) -> Result<PathBuf, String> {
    let s = args.get(2).filter(|a| !a.starts_with("--")).cloned()
        .or_else(|| std::env::var("DUCTEI_QHR_STATE").ok()).unwrap_or_else(|| DEFAULT_STATE.into());
    let p = PathBuf::from(s);
    let probe = Task { id: "state".into(), intent: "state".into(), kind: Kind::Chat, criticality: 0, private: true, effects: vec![Effect::Write(p.clone())] };
    if let Verdict::Deny(r) = Canon::default().check(&probe, &[]) { return Err(format!("state dir refused: {r}")); }
    Ok(p)
}

fn trust_from(args: &[String]) -> Result<VerifyTrust, String> {
    let mut t = VerifyTrust::default();
    if let Some(p) = arg(args, "--pubkey") { t.pubkey = Some(std::fs::read(&p).map_err(|e| format!("--pubkey {p}: {e}"))?); }
    if let Some(f) = arg(args, "--fingerprint") { t.fingerprint = Some(f); }
    if args.iter().any(|a| a == "--allow-unpinned") { t.allow_unpinned = true; }
    if let Some(a) = arg(args, "--anchor") {
        let (s, h) = a.split_once(':').ok_or("--anchor wants <seq>:<hash>")?;
        t.pinned_head = Some((s.parse().map_err(|_| "--anchor: bad seq")?, h.to_string()));
    }
    if let Some(f) = arg(args, "--anchor-file") { t.anchors.extend(anchors_in(Path::new(&f))?); }
    Ok(t)
}

fn cmd_verify(args: &[String]) -> Result<i32, String> {
    let state = state_dir(args)?;
    let trust = trust_from(args)?;
    let mut code = 0;
    for chain in ["verified", "fast"] {
        let dir = state.join(chain);
        if !dir.join("receipts.jsonl").exists() { println!("{chain}: no receipts yet"); continue; }
        let rep = verify_state(&state, chain, &trust)?;
        println!("{chain}: {} receipts, {} errors, {} warnings{}", rep.receipts, rep.errors.len(), rep.warnings.len(),
            rep.kid.as_ref().map(|k| format!(", key {}", &k[..16])).unwrap_or_default());
        for e in &rep.errors { println!("  ERROR {e}"); code = 1; }
        for w in &rep.warnings { println!("  warn  {w}"); }
    }
    println!("{}", if code == 0 { "OK" } else { "FAILED" });
    Ok(code)
}

fn cmd_fingerprint(args: &[String]) -> Result<i32, String> {
    let state = state_dir(args)?;
    match Signer::load_public(&state)? {
        Some((scheme, pk)) => println!("{} {}", scheme.as_str(), sha256_hex(&pk)),
        None => println!("unsigned"),
    }
    Ok(0)
}

/// Open the runtime with lanes and weighter from the command line. Shared by
/// `submit` and `serve` so the MCP surface runs exactly what the CLI runs.
fn open_qhr(args: &[String], state: &Path) -> Result<Qhr, String> {
    let sign: SignCfg = match std::fs::read_to_string(state.join("sign.toml")) {
        Ok(t) => toml::from_str(&t).map_err(|e| format!("sign.toml: {e}"))?,
        Err(_) => SignCfg::default(),
    };
    let fast = Durability { sync_every: 100, sync_max_ms: 10, background: true };
    let mut q = Qhr::open(state, &sign, fast)?;
    // Lane weighter: --weighter uniform|evidence, else QHR_WEIGHTER, else uniform.
    // J-lens stays unavailable here until the jspace-lab readout validation passes.
    match arg(args, "--weighter").or_else(|| std::env::var("QHR_WEIGHTER").ok()).as_deref().unwrap_or("uniform") {
        "uniform" => {}
        "evidence" => q.set_weighter(Box::new(ductei_qhr::weight::EvidenceWeighter)),
        "jlens" => return Err("weighter jlens is not enabled: jspace-lab readout validation has not passed".into()),
        w => return Err(format!("unknown weighter {w:?}; use uniform or evidence")),
    }
    q.register(Arc::new(CpuLane));
    q.register(Arc::new(LlmLane::ollama(Ollama::default())));
    if let Some(spool) = arg(args, "--spool") { q.register(Arc::new(QpuLane::new(QpuConfig::new(spool)))); }
    Ok(q)
}

fn cmd_submit(args: &[String]) -> Result<i32, String> {
    let state = state_dir(args)?;
    let job_path = arg(args, "--job").ok_or(USAGE)?;
    let job: Job = serde_json::from_str(&std::fs::read_to_string(&job_path).map_err(|e| format!("{job_path}: {e}"))?).map_err(|e| format!("{job_path}: {e}"))?;
    let approvals: Vec<String> = arg(args, "--approve").map(|a| a.split(',').map(String::from).collect()).unwrap_or_default();
    let mut q = open_qhr(args, &state)?;
    let report = q.submit(&job, &approvals)?;
    q.flush().map_err(|e| e.to_string())?;
    println!("{}", serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?);
    Ok(match report.status {
        Status::Done(_) => 0,
        Status::NeedsApproval(_) => 2,
        Status::Denied(_) | Status::Refused(_) => 3,
        Status::LaneError(_) | Status::DeadlineMissed { .. } => 4,
    })
}

/// One MCP stdio server: the router's decide / classify / outcome plus
/// qhr_submit / qhr_verify. Router state lives in <state>\router so the
/// decision chain and the QHR chains share one CANON-checked root.
fn cmd_serve(args: &[String]) -> Result<i32, String> {
    let state = state_dir(args)?;
    let qhr = open_qhr(args, &state)?;
    let mut ext = ductei_qhr::mcp::QhrExt { state: state.clone(), qhr };
    // Reuse the registered router's chain when told where it is, so decide
    // receipts stay in one chain whichever server Claude talks to.
    let router_state = arg(args, "--router-state").or_else(|| std::env::var("DUCTEI_ROUTER_STATE").ok())
        .map(PathBuf::from).unwrap_or_else(|| state.join("router"));
    ductei_router::mcp::serve_with(&router_state, &mut ext, "ductei-qhr").map_err(|e| e.to_string())?;
    Ok(0)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let r = match args.get(1).map(String::as_str) {
        Some("verify") => cmd_verify(&args),
        Some("submit") => cmd_submit(&args),
        Some("serve") => cmd_serve(&args),
        Some("fingerprint") => cmd_fingerprint(&args),
        Some("prefetch") => cmd_prefetch(&args),
        Some("--version" | "-V") => { println!("qhr {}", env!("CARGO_PKG_VERSION")); Ok(0) }
        _ => { eprintln!("{USAGE}"); Ok(2) }
    };
    match r { Ok(c) => std::process::exit(c), Err(e) => { eprintln!("qhr: {e}"); std::process::exit(1) } }
}
