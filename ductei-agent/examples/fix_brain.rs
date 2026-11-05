//! fix_brain: one fix proposal per run for D:\brain. Runs after the hourly sweep.
//!
//! 1. Scratch worktree of D:\brain at HEAD under D:\ATRIUM\private\fix (real checkout untouched).
//! 2. cargo test there. All green: report and stop.
//! 3. First failing test: find its file, ask the brain chain for a whole replacement file.
//! 4. Gate with ductei-verify (fail closed: check, clippy -D warnings, tests, content and command rules,
//!    breaker, kill switch, hash-chained ledger).
//! 5. Accepted: write a .patch to atrium-state\agent\fixes and one outbox line for the phone.
//!    Rejected or any error: one outbox line saying why. The worktree is always removed.
//!
//! Never commits, never pushes, never edits D:\brain. Every child process runs hidden.

use ductei_agent::fix::{defines_fn, extract_file, failing_tests, failure_text, precheck, prompt, stem, test_fn};
use ductei_agent::ollama::{build_chain, parse_specs, report};
use ductei_agent::{Entry, Model, ModelOut};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Repo and outbox can be pointed elsewhere for a dry run (FIX_BRAIN_REPO, FIX_BRAIN_OUTBOX).
const REPO: &str = r"D:\brain";
const WT_ROOT: &str = r"D:\ATRIUM\private\fix";
const TARGET: &str = r"D:\ATRIUM\private\fix\target";
const VERIFY: &str = r"D:\ATRIUM\DUCTEI\target\release\ductei-verify.exe";
const POLICY: &str = r"D:\ATRIUM\ops\agent\fix-verify.toml";
const FIXES: &str = r"D:\ATRIUM\ops\atrium-state\agent\fixes";
const OUTBOX: &str = r"D:\ATRIUM\ops\atrium-state\agent\outbox.jsonl";
const BRAINS: &str = r"D:\ATRIUM\ops\agent\brains.txt";
const TEST_TIMEOUT: Duration = Duration::from_secs(900);
const MAX_SRC: usize = 60_000;

fn hidden(exe: &str) -> Command {
    let mut c = Command::new(exe);
    c.stdin(Stdio::null()).env("CARGO_TARGET_DIR", TARGET);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        c.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    c
}

/// Run to completion with a hard timeout; returns (exit ok, stdout+stderr).
fn run(mut c: Command, limit: Duration) -> Result<(bool, String), String> {
    let dir = std::env::temp_dir();
    let tag = format!("fix-{}-{}", std::process::id(), now());
    let (op, ep) = (dir.join(format!("{tag}.out")), dir.join(format!("{tag}.err")));
    let o = std::fs::File::create(&op).map_err(|e| e.to_string())?;
    let e = std::fs::File::create(&ep).map_err(|e| e.to_string())?;
    let mut ch = c.stdout(o).stderr(e).spawn().map_err(|e| format!("spawn: {e}"))?;
    let start = Instant::now();
    let status = loop {
        if let Some(s) = ch.try_wait().map_err(|e| e.to_string())? {
            break Some(s);
        }
        if start.elapsed() > limit {
            let _ = ch.kill();
            let _ = ch.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(500));
    };
    let text = format!(
        "{}{}",
        std::fs::read_to_string(&op).unwrap_or_default(),
        std::fs::read_to_string(&ep).unwrap_or_default()
    );
    let _ = std::fs::remove_file(op);
    let _ = std::fs::remove_file(ep);
    match status {
        Some(s) => Ok((s.success(), text)),
        None => Err(format!("timed out after {}s", limit.as_secs())),
    }
}

fn git(dir: &str, args: &[&str]) -> Result<String, String> {
    let mut c = hidden("git");
    c.arg("-C").arg(dir).args(args);
    let (ok, out) = run(c, Duration::from_secs(120))?;
    if ok { Ok(out) } else { Err(format!("git {}: {}", args.join(" "), out.trim())) }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn say(text: &str) {
    let line = format!("[brain fix] {text}");
    println!("{line}");
    let outbox = std::env::var("FIX_BRAIN_OUTBOX").unwrap_or_else(|_| OUTBOX.into());
    if let Err(e) = report(Path::new(&outbox), &line) {
        eprintln!("outbox: {e}");
    }
}

/// Every .rs file under `root`, skipping target and .git.
fn rust_files(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(root) else { return };
    for e in rd.flatten() {
        let p = e.path();
        let name = e.file_name().to_string_lossy().to_string();
        if p.is_dir() {
            if name != "target" && name != ".git" && name != ".venv" {
                rust_files(&p, out);
            }
        } else if name.ends_with(".rs") {
            out.push(p);
        }
    }
}

/// The file that defines the failing test, preferring one whose path matches the module path.
fn locate(wt: &Path, test: &str) -> Option<PathBuf> {
    let mut files = Vec::new();
    rust_files(wt, &mut files);
    let f = test_fn(test);
    let hits: Vec<PathBuf> = files
        .into_iter()
        .filter(|p| std::fs::read_to_string(p).is_ok_and(|s| defines_fn(&s, f)))
        .collect();
    let first_mod = test.split("::").next().unwrap_or("");
    hits.iter()
        .find(|p| p.file_stem().is_some_and(|s| s.to_string_lossy() == first_mod))
        .cloned()
        .or_else(|| hits.first().cloned())
}

fn propose(repo: &str, wt: &str, task: &str) -> Result<String, String> {
    // 2. reproduce at HEAD
    let mut c = hidden("cargo");
    c.current_dir(wt).args(["test", "--workspace", "--no-fail-fast", "--color", "never"]);
    let (ok, out) = run(c, TEST_TIMEOUT).map_err(|e| format!("cargo test: {e}"))?;
    let fails = failing_tests(&out);
    if ok && fails.is_empty() {
        return Ok(format!("{task}: all brain tests pass at HEAD, nothing to fix"));
    }
    let Some(test) = fails.first().cloned() else {
        let tail: String = out.lines().rev().take(6).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join(" | ");
        return Err(format!("tests did not pass but no failing test was named (build error?): {tail}"));
    };

    // 3. ask the brain chain
    let file = locate(Path::new(wt), &test).ok_or_else(|| format!("could not find the file for {test}"))?;
    let old = std::fs::read_to_string(&file).map_err(|e| e.to_string())?;
    if old.len() > MAX_SRC {
        return Err(format!("{test}: {} is {} bytes, too big to send whole", file.display(), old.len()));
    }
    let rel = file.strip_prefix(wt).map(|p| p.display().to_string()).unwrap_or_else(|_| file.display().to_string());
    let failure = failure_text(&out, &test, 4000);
    let specs = parse_specs(&std::fs::read_to_string(BRAINS).map_err(|e| format!("{BRAINS}: {e}"))?)?;
    let charter = "You are the ATRIUM fix agent. You propose one small, correct Rust fix. A strict verifier rejects \
                   anything that fails cargo check, clippy -D warnings or cargo test.";
    let mut chain = build_chain(&specs, charter, &[], 900);
    let reply = match chain.complete(&[Entry::User { text: prompt(&test, &failure, &rel, &old) }])? {
        ModelOut::Text(t) => t,
        ModelOut::ToolCall { tool, .. } => return Err(format!("{test}: model asked for tool {tool} instead of a fix")),
    };
    let new = extract_file(&reply)
        .or_else(|| defines_fn(&reply, test_fn(&test)).then(|| reply.clone()))
        .ok_or_else(|| format!("{test}: model reply had no usable file"))?;
    precheck(&old, &new, &test).map_err(|e| format!("{test}: {e}"))?;
    std::fs::write(&file, &new).map_err(|e| e.to_string())?;

    // 4. gate
    let mut v = hidden(VERIFY);
    v.args(["check-git", "--policy", POLICY, "--worktree", wt, "--task", &format!("brain-{}", stem(&test))]);
    let (accepted, verdict) = run(v, Duration::from_secs(1800)).map_err(|e| format!("verifier: {e}"))?;
    if !accepted {
        let why: String = verdict.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(400).collect();
        return Err(format!("{test}: verifier rejected the fix: {why}"));
    }

    // 5. patch for Xing
    let diff = git(wt, &["diff", "HEAD"])?;
    std::fs::create_dir_all(FIXES).map_err(|e| e.to_string())?;
    let patch = Path::new(FIXES).join(format!("{}-{}.patch", stem(&test), now()));
    std::fs::write(&patch, &diff).map_err(|e| e.to_string())?;
    Ok(format!(
        "fix ready for {test} (verified: check, clippy, tests). Review: git -C {repo} apply --check {}",
        patch.display()
    ))
}

fn main() {
    let repo = std::env::var("FIX_BRAIN_REPO").unwrap_or_else(|_| REPO.into());
    let task = format!("run-{}", now());
    if Path::new(r"D:\ATRIUM\private\verify\STOP").exists() {
        println!("[brain fix] kill switch on, skipping");
        return;
    }
    let wt = format!(r"{WT_ROOT}\brain-{}", now());
    if let Err(e) = std::fs::create_dir_all(WT_ROOT) {
        return say(&format!("cannot create {WT_ROOT}: {e}"));
    }
    if let Err(e) = git(&repo, &["worktree", "add", "--detach", &wt, "HEAD"]) {
        return say(&format!("worktree: {e}"));
    }
    match propose(&repo, &wt, &task) {
        Ok(m) => say(&m),
        Err(e) => say(&format!("no fix this run: {e}")),
    }
    // 1b. always clean up the scratch worktree
    if let Err(e) = git(&repo, &["worktree", "remove", "--force", &wt]) {
        eprintln!("cleanup: {e}");
    }
    let _ = git(&repo, &["worktree", "prune"]);
}
