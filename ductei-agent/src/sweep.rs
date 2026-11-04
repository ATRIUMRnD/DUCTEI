//! Sweep resilience for the hourly ops agent: a report is ALWAYS sent.
//! - `fallback_report` builds a deterministic report straight from raw preset results
//!   (alarms, test failures, uncommitted work, LIMEN GPU, timeouts), no LLM involved.
//! - `final_report` picks the model's report or the fallback (empty answer, error).
//! - `health` checks a brain host before the sweep, with one retry and backoff.
//! - `heal_outcome` classifies auto-heal results: external rooms are skipped, not FAILED.

use crate::Entry;
use std::process::{Command, Stdio};
use std::time::Duration;

/// Default cap for one preset call (seconds). Override: env ATRIUM_AGENT_PRESET_TIMEOUT_S.
pub const PRESET_TIMEOUT_S: u64 = 120;
/// Presets the sweep runs itself when the LLM is offline.
pub const OFFLINE_SWEEP: &[&str] = &["fleet_alarms", "git_status", "cargo_test_agent", "cargo_test_ctl", "cargo_test_watch", "limen_gpu_tier0"];

/// Per-call timeout from env (1..=3600 s), else the default.
pub fn preset_timeout() -> Duration {
    let s = std::env::var("ATRIUM_AGENT_PRESET_TIMEOUT_S").ok().and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|s| (1..=3600).contains(s)).unwrap_or(PRESET_TIMEOUT_S);
    Duration::from_secs(s)
}

/// The result text recorded for a preset that ran past its cap.
pub fn timeout_text(preset: &str, secs: u64) -> String {
    format!("{preset}: timed out after {secs}s")
}

pub fn is_timeout(output: &str) -> bool {
    output.contains(": timed out after ")
}

// ---------- auto-heal classification ----------

#[derive(Debug, PartialEq)]
pub enum Heal { Did, Failed, Skipped }

/// A refusal because the room is external (owned by its own scheduled task) is not a failure.
pub fn heal_outcome(ok: bool, text: &str) -> Heal {
    if ok {
        Heal::Did
    } else if text.contains("is external") || text.contains("owned by its own task") {
        Heal::Skipped
    } else {
        Heal::Failed
    }
}

// ---------- results from history ----------

/// (preset name, output) for every finished tool call in the thread, in order.
pub fn results_from_history(h: &[Entry]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for e in h {
        if let Entry::ToolResult { call_id, output, .. } = e {
            let name = h.iter().find_map(|c| match c {
                Entry::ToolCall { call_id: id, args, .. } if id == call_id => args.get("name").and_then(|n| n.as_str()).map(str::to_string),
                _ => None,
            }).unwrap_or_else(|| "?".into());
            out.push((name, output.clone()));
        }
    }
    out
}

// ---------- deterministic report ----------

fn lines(s: &str) -> impl Iterator<Item = &str> {
    s.lines().map(str::trim_end).filter(|l| !l.trim().is_empty() && !l.starts_with('['))
}

fn clip(s: &str, n: usize) -> String {
    if s.chars().count() <= n { s.to_string() } else { format!("{}...", s.chars().take(n).collect::<String>()) }
}

fn summarize(name: &str, out: &str) -> String {
    if is_timeout(out) {
        return format!("TIMEOUT {}", clip(out.trim_start_matches("ERROR: "), 200));
    }
    if let Some(e) = out.strip_prefix("ERROR: ") {
        return format!("ERROR {}", clip(e.lines().next().unwrap_or(""), 200));
    }
    if name == "fleet_alarms" {
        let l: Vec<&str> = lines(out).collect();
        if l.is_empty() || l.iter().all(|x| x.to_lowercase().contains("no alarms")) {
            return "none".into();
        }
        return format!("ALARM {}", l.iter().take(5).map(|x| clip(x, 160)).collect::<Vec<_>>().join(" | "));
    }
    if name == "git_status" {
        let changed: Vec<&str> = lines(out).filter(|l| !l.starts_with("##")).collect();
        if changed.is_empty() {
            return "clean".into();
        }
        let names: Vec<&str> = changed.iter().take(8).map(|l| l.get(3..).unwrap_or(l).trim()).collect();
        return format!("{} uncommitted: {}{}", changed.len(), names.join(", "), if changed.len() > 8 { ", ..." } else { "" });
    }
    if name.starts_with("cargo_test") || name == "cargo_check" {
        let failed: Vec<&str> = lines(out).filter(|l| l.ends_with("FAILED") && l.trim_start().starts_with("test ")).collect();
        let bad = !failed.is_empty() || out.contains("test result: FAILED") || out.contains("error[") || out.contains("error: could not compile");
        if bad {
            let names: Vec<String> = failed.iter().take(5).map(|l| l.trim().trim_start_matches("test ").trim_end_matches("... FAILED").trim().to_string()).collect();
            return format!("FAIL{}", if names.is_empty() { " (build or test error)".into() } else { format!(": {}", names.join(", ")) });
        }
        let (mut passed, mut runs) = (0u64, 0u64);
        for l in out.lines().filter(|l| l.contains("test result: ok")) {
            runs += 1;
            passed += l.split(';').next().and_then(|p| p.split_whitespace().rev().nth(1)).and_then(|n| n.parse::<u64>().ok()).unwrap_or(0);
        }
        return if runs > 0 { format!("ok, {passed} passed") } else { "ok".into() };
    }
    // LIMEN GPU and anything else: the last meaningful line.
    lines(out).last().map(|l| clip(l.trim(), 200)).unwrap_or_else(|| "no output".into())
}

/// Plain report from raw results; one line per preset (latest result per name wins).
pub fn fallback_report(results: &[(String, String)]) -> String {
    if results.is_empty() {
        return "no preset results".into();
    }
    let mut seen: Vec<&str> = Vec::new();
    let mut rows = Vec::new();
    for (name, out) in results.iter().rev() {
        if seen.contains(&name.as_str()) {
            continue;
        }
        seen.push(name);
        rows.push(format!("{name}: {}", summarize(name, out)));
    }
    rows.reverse();
    rows.join("\n")
}

/// What to send: the model's report when it gave one, else the deterministic report.
pub fn final_report(llm: Result<String, String>, results: &[(String, String)]) -> String {
    match llm {
        Ok(t) if !t.trim().is_empty() => t,
        Ok(_) => format!("LLM gave an empty answer, raw report:\n{}", fallback_report(results)),
        Err(e) => format!("LLM gave no report ({}), raw report:\n{}", clip(&e, 200), fallback_report(results)),
    }
}

pub fn offline_report(host: &str, results: &[(String, String)]) -> String {
    format!("LLM offline ({host}), raw report:\n{}", fallback_report(results))
}

// ---------- health ----------

/// Try `check` up to `1 + retries` times, sleeping `backoff * attempt` between tries.
pub fn with_retry(retries: u32, backoff: Duration, check: &mut dyn FnMut() -> Result<(), String>) -> Result<(), String> {
    let mut last = String::new();
    for attempt in 0..=retries {
        match check() {
            Ok(()) => return Ok(()),
            Err(e) => last = e,
        }
        if attempt < retries {
            std::thread::sleep(backoff * (attempt + 1));
        }
    }
    Err(last)
}

/// GET `url` with curl (hidden window), short timeout; Ok when the server answers with JSON.
pub fn http_alive(url: &str, timeout_s: u64) -> Result<(), String> {
    let mut c = Command::new("curl");
    c.args(["-s", "-f", "--max-time", &timeout_s.to_string(), url]).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        c.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let o = c.output().map_err(|e| format!("curl: {e}"))?;
    if !o.status.success() || o.stdout.is_empty() {
        return Err(format!("no reply from {url}"));
    }
    serde_json::from_slice::<serde_json::Value>(&o.stdout).map(|_| ()).map_err(|e| format!("{url}: {e}"))
}

/// Health URL for a brain: Ollama /api/tags, OpenAI-compatible /v1/models.
pub fn health_url(spec: &crate::ollama::Spec) -> String {
    let b = spec.base.trim_end_matches('/');
    match spec.kind {
        crate::ollama::Kind::Ollama => format!("{b}/api/tags"),
        _ => format!("{b}/v1/models"),
    }
}

/// Kill a process tree, hidden (no console flash).
pub fn kill_tree(pid: u32) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let _ = Command::new("taskkill").args(["/T", "/F", "/PID", &pid.to_string()])
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).creation_flags(0x0800_0000).status();
    }
    #[cfg(not(windows))]
    {
        let _ = Command::new("kill").args(["-9", &pid.to_string()]).stdout(Stdio::null()).stderr(Stdio::null()).status();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn r(n: &str, o: &str) -> (String, String) { (n.into(), o.into()) }

    #[test]
    fn fallback_report_covers_alarms_tests_git_gpu_and_timeouts() {
        let res = vec![
            r("fleet_alarms", "[fleet_alarms in D:\\ATRIUM exit Some(0)]\nI3 tamper on ward\n"),
            r("git_status", "## timeline\n M ductei-agent/src/ollama.rs\n?? ductei-braid/\n"),
            r("cargo_test_agent", "test a ... ok\ntest result: ok. 12 passed; 0 failed; 0 ignored\ntest result: ok. 3 passed; 0 failed\n"),
            r("cargo_test_ctl", "test fleet::x ... FAILED\ntest result: FAILED. 4 passed; 1 failed\n"),
            r("cargo_test_watch", &format!("ERROR: {}", timeout_text("cargo_test_watch", 120))),
            r("limen_gpu_tier0", "warmup\ntier0 ok: 24 qubits 1.8 ms\n"),
        ];
        let t = fallback_report(&res);
        assert!(t.contains("fleet_alarms: ALARM I3 tamper on ward"), "{t}");
        assert!(t.contains("git_status: 2 uncommitted: ductei-agent/src/ollama.rs, ductei-braid/"), "{t}");
        assert!(t.contains("cargo_test_agent: ok, 15 passed"), "{t}");
        assert!(t.contains("cargo_test_ctl: FAIL: fleet::x"), "{t}");
        assert!(t.contains("cargo_test_watch: TIMEOUT cargo_test_watch: timed out after 120s"), "{t}");
        assert!(t.contains("limen_gpu_tier0: tier0 ok: 24 qubits"), "{t}");
        assert_eq!(fallback_report(&[r("fleet_alarms", "no alarms"), r("git_status", "## timeline\n")]), "fleet_alarms: none\ngit_status: clean");
        assert_eq!(fallback_report(&[]), "no preset results");
    }

    #[test]
    fn latest_result_per_preset_wins() {
        let t = fallback_report(&[r("git_status", " M a"), r("git_status", "## x")]);
        assert_eq!(t, "git_status: clean");
    }

    #[test]
    fn report_is_always_sent() {
        let res = vec![r("fleet_alarms", "no alarms")];
        assert_eq!(final_report(Ok("all green".into()), &res), "all green");
        assert!(final_report(Ok("  ".into()), &res).contains("fleet_alarms: none"));
        let e = final_report(Err("gpt-oss:20b returned an empty answer twice".into()), &res);
        assert!(e.starts_with("LLM gave no report") && e.contains("fleet_alarms: none"), "{e}");
        let o = offline_report("http://100.106.147.75:11434", &res);
        assert!(o.starts_with("LLM offline (http://100.106.147.75:11434), raw report:\n"), "{o}");
    }

    #[test]
    fn timeouts_are_classified() {
        let t = timeout_text("cargo_test_ctl", 120);
        assert_eq!(t, "cargo_test_ctl: timed out after 120s");
        assert!(is_timeout(&format!("ERROR: {t}")));
        assert!(!is_timeout("test result: ok"));
        assert!(preset_timeout().as_secs() >= 1);
    }

    #[test]
    fn external_restart_refusal_is_skipped_not_failed() {
        assert_eq!(heal_outcome(false, "ductei-sync is external (owned by its own task); not restartable from fleet"), Heal::Skipped);
        assert_eq!(heal_outcome(false, "ductei-sync is external with no `task` configured; not restartable from fleet"), Heal::Skipped);
        assert_eq!(heal_outcome(false, "loop has no live pid (is atrium up?)"), Heal::Failed);
        assert_eq!(heal_outcome(true, "loop (pid 4) stopped"), Heal::Did);
    }

    #[test]
    fn health_retries_once_then_gives_up() {
        let mut n = 0;
        assert!(with_retry(1, Duration::from_millis(1), &mut || { n += 1; if n == 2 { Ok(()) } else { Err("down".into()) } }).is_ok());
        assert_eq!(n, 2);
        let mut m = 0;
        assert_eq!(with_retry(1, Duration::from_millis(1), &mut || { m += 1; Err(format!("down {m}")) }).unwrap_err(), "down 2");
        assert_eq!(m, 2);
    }

    #[test]
    fn results_map_back_to_preset_names() {
        let h = vec![
            Entry::ToolCall { call_id: "c1".into(), tool: "run_preset".into(), args: json!({"name": "git_status"}) },
            Entry::ToolResult { call_id: "c1".into(), tool: "run_preset".into(), output: "## x".into() },
        ];
        assert_eq!(results_from_history(&h), vec![r("git_status", "## x")]);
    }
}
