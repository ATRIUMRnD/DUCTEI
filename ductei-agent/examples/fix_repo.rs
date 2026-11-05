//! fix_repo: the fix_brain loop for any listed Rust repo. Runs after the hourly sweep.
//!
//! Repos come from D:\ATRIUM\ops\agent\fix-repos.txt, one per line: `name|D:\path\to\repo`.
//! The repo's git root must also be its cargo root (Cargo.toml at the top). For each repo:
//! 1. Scratch worktree at HEAD under D:\ATRIUM\private\fix (real checkout untouched).
//! 2. cargo test there. All green: report and move on.
//! 3. First failing test: find its file, ask the brain chain for a whole replacement file.
//! 4. Gate with ductei-verify check-git (fail closed).
//! 5. Accepted: write a .patch to atrium-state\agent\fixes and one outbox line for the phone.
//!    Rejected or any error: one outbox line saying why. The worktree is always removed.
//! Never commits, never pushes, never edits the real repo. Every child process runs hidden,
//! and scratch output stays on D: (never the system temp folder).

use ductei_agent::fix::{defines_fn, extract_file, failing_tests, failure_text, precheck, prompt, stem, test_fn};
use ductei_agent::ollama::{build_chain, parse_specs, report};
use ductei_agent::{Entry, Model, ModelOut};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const REPOS: &str = r"D:\ATRIUM\ops\agent\fix-repos.txt";
const WT_ROOT: &str = r"D:\ATRIUM\private\fix";
const TARGET: &str = r"D:\ATRIUM\private\fix\target";
const VERIFY: &str = r"D:\ATRIUM\DUCTEI\target\release\ductei-verify.exe";
const POLICY: &str = r"D:\ATRIUM\ops\agent\fix-verify.toml";
const FIXES: &str = r"D:\ATRIUM\ops\atrium-state\agent\fixes";
const OUTBOX: &str = r"D:\ATRIUM\ops\atrium-state\agent\outbox.jsonl";
const BRAINS: &str = r"D:\ATRIUM\ops\agent\brains.txt";
const STOP: &str = r"D:\ATRIUM\private\verify\STOP";
const TEST_TIMEOUT: Duration = Duration::from_secs(900);
const MAX_SRC: usize = 60_000;
const MAX_REPOS: usize = 8;

struct Repo {
    name: String,
    path: String,
}

/// Parse `name|path` lines; `#` comments and blanks are skipped. Names are short and file-safe,
/// paths must be absolute D: paths with no `..`.
fn parse_repos(text: &str) -> Result<Vec<Repo>, String> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, path) = line.split_once('|').ok_or_else(|| format!("line {}: expected name|path", i + 1))?;
        let (name, path) = (name.trim(), path.trim().trim_end_matches('\\'));
        let name_ok = !name.is_empty() && name.len() <= 7 && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
        let low = path.to_ascii_lowercase();
        let path_ok = low.starts_with(r"d:\") && !low.split('\\').any(|s| s == "..");
        if !name_ok {
            return Err(format!("line {}: name must be 1-7 letters, digits or -", i + 1));
        }
        if !path_ok {
            return Err(format!("line {}: path must be an absolute D: path", i + 1));
        }
        if out.iter().any(|r: &Repo| r.name == name) {
            return Err(format!("line {}: name {name} listed twice", i + 1));
        }
        out.push(Repo { name: name.into(), path: path.into() });
    }
    if out.len() > MAX_REPOS {
        return Err(format!("{} repos listed, limit {MAX_REPOS}", out.len()));
    }
    Ok(out)
}

/// Verifier task id: `<name>-<test stem>`, kept within the verifier's 64-char limit.
fn task_id(name: &str, test: &str) -> String {
    format!("{name}-{}", stem(test)).chars().take(64).collect()
}

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

/// Kill the child and everything it started (cargo spawns rustc and test binaries).
fn kill_tree(ch: &mut std::process::Child) {
    #[cfg(windows)]
    {
        let mut k = hidden("taskkill");
        let _ = k.args(["/PID", &ch.id().to_string(), "/T", "/F"]).stdout(Stdio::null()).stderr(Stdio::null()).status();
    }
    let _ = ch.kill();
    let _ = ch.wait();
}

/// Run to completion with a hard timeout; returns (exit ok, stdout+stderr).
fn run(mut c: Command, limit: Duration) -> Result<(bool, String), String> {
    let dir = Path::new(WT_ROOT);
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let tag = format!("fixrepo-{}-{}", std::process::id(), now_nanos());
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
            kill_tree(&mut ch);
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

fn now_nanos() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)
}

fn say(name: &str, text: &str) {
    let line = format!("[{name} fix] {text}");
    println!("{line}");
    let outbox = std::env::var("FIX_REPO_OUTBOX").unwrap_or_else(|_| OUTBOX.into());
    if let Err(e) = report(Path::new(&outbox), &line) {
        eprintln!("outbox: {e}");
    }
}

/// Every .rs file under `root`, skipping target, .git and .venv.
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

/// The file that defines the failing test, preferring one whose name matches the module path.
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

fn propose(repo: &Repo, wt: &str) -> Result<String, String> {
    if !Path::new(wt).join("Cargo.toml").exists() {
        return Err("no Cargo.toml at the repo root, skipped (only Rust repos rooted at git root)".into());
    }
    // 2. reproduce at HEAD
    let mut c = hidden("cargo");
    c.current_dir(wt).args(["test", "--workspace", "--no-fail-fast", "--color", "never"]);
    let (ok, out) = run(c, TEST_TIMEOUT).map_err(|e| format!("cargo test: {e}"))?;
    let fails = failing_tests(&out);
    if ok && fails.is_empty() {
        return Ok("all tests pass at HEAD, nothing to fix".into());
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
    let ask = prompt(&test, &failure, &rel, &old).replace("Xing's brain repo", &format!("Xing's {} repo", repo.name));
    let reply = match chain.complete(&[Entry::User { text: ask }])? {
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
    v.args(["check-git", "--policy", POLICY, "--worktree", wt, "--task", &task_id(&repo.name, &test)]);
    let (accepted, verdict) = run(v, Duration::from_secs(1800)).map_err(|e| format!("verifier: {e}"))?;
    if !accepted {
        let why: String = verdict.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(400).collect();
        return Err(format!("{test}: verifier rejected the fix: {why}"));
    }

    // 5. patch for Xing
    let diff = git(wt, &["diff", "HEAD"])?;
    std::fs::create_dir_all(FIXES).map_err(|e| e.to_string())?;
    let patch = Path::new(FIXES).join(format!("{}-{}-{}.patch", repo.name, stem(&test), now()));
    std::fs::write(&patch, &diff).map_err(|e| e.to_string())?;
    Ok(format!(
        "fix ready for {test} (verified: check, clippy, tests). Review: git -C {} apply --check {}",
        repo.path,
        patch.display()
    ))
}

fn one(repo: &Repo) {
    let wt = format!(r"{WT_ROOT}\{}-{}", repo.name, now());
    if let Err(e) = git(&repo.path, &["worktree", "add", "--detach", &wt, "HEAD"]) {
        return say(&repo.name, &format!("worktree: {e}"));
    }
    match propose(repo, &wt) {
        Ok(m) => say(&repo.name, &m),
        Err(e) => say(&repo.name, &format!("no fix this run: {e}")),
    }
    // always clean up the scratch worktree
    if let Err(e) = git(&repo.path, &["worktree", "remove", "--force", &wt]) {
        eprintln!("cleanup: {e}");
    }
    let _ = git(&repo.path, &["worktree", "prune"]);
}

fn main() {
    if Path::new(STOP).exists() {
        println!("[fix] kill switch on, skipping");
        return;
    }
    let list = std::env::var("FIX_REPOS").unwrap_or_else(|_| REPOS.into());
    let repos = match std::fs::read_to_string(&list).map_err(|e| format!("{list}: {e}")).and_then(|t| parse_repos(&t)) {
        Ok(r) => r,
        Err(e) => return say("all", &format!("repo list: {e}")),
    };
    if let Err(e) = std::fs::create_dir_all(WT_ROOT) {
        return say("all", &format!("cannot create {WT_ROOT}: {e}"));
    }
    for r in &repos {
        if Path::new(STOP).exists() {
            println!("[fix] kill switch turned on mid-run, stopping");
            return;
        }
        one(r);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_repo_list() {
        let r = parse_repos("# comment\n\nbrain|D:\\brain\nductei|D:\\ATRIUM\\DUCTEI\\\n").unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(r[1].path, r"D:\ATRIUM\DUCTEI");
    }

    #[test]
    fn rejects_bad_repo_lines() {
        for bad in [
            "brain D:\\brain",
            "brain|C:\\Users\\x",
            "brain|D:\\ATRIUM\\..\\x",
            "bad name|D:\\x",
            "toolongname|D:\\x",
            "a|D:\\x\na|D:\\y",
            "brain|relative\\path",
        ] {
            assert!(parse_repos(bad).is_err(), "{bad}");
        }
        let many: String = (0..9).map(|i| format!("r{i}|D:\\r{i}\n")).collect();
        assert!(parse_repos(&many).is_err());
    }

    #[test]
    fn task_ids_fit_the_verifier() {
        let t = task_id("ductei", &"x".repeat(200));
        assert!(t.len() <= 64 && t.starts_with("ductei-"));
        assert!(t.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }
}
