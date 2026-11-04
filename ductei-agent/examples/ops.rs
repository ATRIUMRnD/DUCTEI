//! ATRIUM ops agent: charter-driven, local brains, reports to Telegram via the fleet bot.
//!   cargo run -q -p ductei-agent --example ops -- "check atrium-watch tests and report"
//! Each slice is persisted before acting; between tool calls the agent holds nothing.
//! Brains, first match wins:
//!   1. env ATRIUM_AGENT_BRAINS   (kind|base|model[|lms load key], ';' separated)
//!   2. D:\ATRIUM\ops\agent\brains.txt (same, one per line; written by brains-setup.ps1)
//!   3. legacy: one Ollama brain from OLLAMA_URL / ATRIUM_AGENT_MODEL (default gpt-oss:20b)
//!
//! A report is ALWAYS sent: if every brain is offline, or the model errors or answers empty,
//! the deterministic report built from the raw preset results goes out instead (sweep.rs).
//! Each preset call is capped (env ATRIUM_AGENT_PRESET_TIMEOUT_S, default 120 s); a hung call
//! is killed, recorded as "<preset>: timed out after Ns", and the sweep goes on.
use ductei_agent::{ollama, preset, run_slice, sweep, Body, Dispatcher, Entry, Message, SliceOutcome, Store};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const ROOT: &str = r"D:\ATRIUM\ops\atrium-state\agent";
const CHARTER: &str = r"D:\ATRIUM\ops\agent\CHARTER.md";
const BRAINS_FILE: &str = r"D:\ATRIUM\ops\agent\brains.txt";
const MAX_STEPS: usize = 10; // goal 1 bound: no endless self-driven loops
const HEALTH_TIMEOUT_S: u64 = 5;
const HEALTH_BACKOFF: Duration = Duration::from_secs(3);

fn main() {
    if let Err(e) = run() {
        let _ = ollama::report(&PathBuf::from(ROOT).join("outbox.jsonl"), &format!("ERROR: {e}"));
        eprintln!("ops: {e}");
        std::process::exit(1);
    }
}

fn brain_specs() -> Result<Vec<ollama::Spec>, String> {
    if let Ok(s) = std::env::var("ATRIUM_AGENT_BRAINS") {
        if !s.trim().is_empty() {
            return ollama::parse_specs(&s).map_err(|e| format!("ATRIUM_AGENT_BRAINS: {e}"));
        }
    }
    if let Ok(s) = std::fs::read_to_string(BRAINS_FILE) {
        return ollama::parse_specs(&s).map_err(|e| format!("{BRAINS_FILE}: {e}"));
    }
    let base = std::env::var("OLLAMA_URL").unwrap_or_else(|_| "http://100.106.147.75:11434".into());
    let model = std::env::var("ATRIUM_AGENT_MODEL").unwrap_or_else(|_| "gpt-oss:20b".into());
    ollama::parse_specs(&format!("ollama|{base}|{model}"))
}

/// Ok when at least one brain answers its health URL (1 retry with backoff each); Err lists the hosts.
fn any_brain_alive(specs: &[ollama::Spec]) -> Result<(), String> {
    let mut down = Vec::new();
    for s in specs {
        let url = sweep::health_url(s);
        match sweep::with_retry(1, HEALTH_BACKOFF, &mut || sweep::http_alive(&url, HEALTH_TIMEOUT_S)) {
            Ok(()) => return Ok(()),
            Err(_) => down.push(s.base.clone()),
        }
    }
    down.dedup();
    Err(down.join(", "))
}

/// Wait for `call_id`'s result, capped at `cap`. On timeout the call is killed and recorded
/// as a timeout result, so the returned messages always contain this call's result.
fn wait_result(inbox: &Path, thread: &str, call_id: &str, preset_name: &str, cap: Duration) -> Result<Vec<Message>, String> {
    let t0 = Instant::now();
    loop {
        let got = preset::collect(inbox, thread)?;
        if got.iter().any(|m| matches!(&m.body, Body::ToolResult { call_id: c, .. } if c == call_id)) {
            preset::ack(inbox, thread, &got)?;
            return Ok(got);
        }
        if t0.elapsed() > cap {
            eprintln!("[{thread}] {preset_name}: timed out after {}s, killing", cap.as_secs());
            preset::expire(inbox, thread, call_id, preset_name, cap.as_secs(), &mut sweep::kill_tree)?;
            continue; // the timeout result is collected on the next pass
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

/// LLM offline: run the standard sweep presets directly and return (name, output).
fn offline_sweep(d: &mut preset::PresetDispatcher, inbox: &Path, thread: &str, cap: Duration) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (i, name) in sweep::OFFLINE_SWEEP.iter().enumerate() {
        let call_id = format!("off_{i}_{name}");
        let args = serde_json::json!({ "name": name });
        let r = d.dispatch(thread, &call_id, preset::TOOL, &args)
            .and_then(|()| wait_result(inbox, thread, &call_id, name, cap));
        let text = match r {
            Ok(msgs) => msgs.into_iter().find_map(|m| match m.body {
                Body::ToolResult { call_id: c, output } if c == call_id => Some(output),
                _ => None,
            }).unwrap_or_else(|| "ERROR: no result".into()),
            Err(e) => format!("ERROR: {e}"),
        };
        out.push((name.to_string(), text));
    }
    out
}

fn run() -> Result<(), String> {
    let task = std::env::args().skip(1).collect::<Vec<_>>().join(" ");
    if task.trim().is_empty() {
        return Err("usage: ops <task for the agent>".into());
    }
    let root = PathBuf::from(ROOT);
    let outbox = root.join("outbox.jsonl");
    let store = Store::open(root.join("history"))?;
    let inbox = root.join("inbox");
    let allow: Vec<String> = ["git_status", "git_log", "git_diff_stat", "cargo_check", "cargo_test_watch", "cargo_test_agent", "cargo_test_ctl", "fleet_status", "fleet_alarms", "nvidia_smi", "limen_gpu_tier0"]
        .iter().map(|s| s.to_string()).collect();
    let charter = std::fs::read_to_string(CHARTER).map_err(|e| format!("{CHARTER}: {e}"))?;
    let specs = brain_specs()?;
    let cap = sweep::preset_timeout();
    let mut brain = ollama::build_chain(&specs, &charter, &allow, 300);
    let mut d = ollama::GpuHandoff {
        inner: preset::PresetDispatcher {
            exe: r"D:\ATRIUM\xing-pc-mcp\target\release\xing-pc-mcp.exe".into(),
            inbox: inbox.clone(),
            allow,
        },
        brains: specs.clone(),
    };
    // One thread per run, so tasks never bleed into each other.
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let thread = format!("ops-{now}");
    ollama::report(&outbox, &format!("[{thread}] task: {task}"))?;
    eprintln!("[{thread}] brains: {} (preset cap {}s)", brain.names.join(" > "), cap.as_secs());

    // The one auto-action (Xing, Nov 3 2026): bring atrium back if it is down, else restart a
    // down room. Only through the signed fleet verbs, never a shell; every action is reported.
    for line in auto_heal() {
        ollama::report(&outbox, &format!("[{thread}] AUTO {line}"))?;
    }

    // Health pre-check: if no brain answers, send the raw report instead of an error.
    if let Err(hosts) = any_brain_alive(&specs) {
        eprintln!("[{thread}] LLM offline ({hosts}); running the raw sweep");
        let results = offline_sweep(&mut d.inner, &inbox, &thread, cap);
        return ollama::report(&outbox, &format!("[{thread}] {}", sweep::offline_report(&hosts, &results)));
    }

    let results = |store: &Store| store.history(&thread).map(|h| sweep::results_from_history(&h)).unwrap_or_default();
    let mut msgs = vec![Message { id: "task".into(), body: Body::User { text: task } }];
    for step in 1..=MAX_STEPS {
        let outcome = match run_slice(&store, &thread, &msgs, &mut brain, &mut d) {
            Ok(o) => o,
            Err(e) => {
                // Model error (empty twice, all brains failed): the deterministic report goes out.
                eprintln!("[{thread}] step {step}: {e}");
                ollama::report(&outbox, &format!("[{thread}] {}", sweep::final_report(Err(e), &results(&store))))?;
                ollama::unload_all(&specs);
                return Ok(());
            }
        };
        match outcome {
            SliceOutcome::Idle => {
                let last = store.history(&thread)?.into_iter().rev().find_map(|e| match e {
                    Entry::Assistant { text } => Some(text),
                    _ => None,
                }).unwrap_or_default();
                // Models sometimes emit a broken tool call as plain text (extra brace etc.).
                // That is not a report: tell it and let it try again within MAX_STEPS.
                if looks_like_tool_call(&last) {
                    eprintln!("[{thread}] step {step}: malformed tool call, retrying: {}", last.chars().take(160).collect::<String>());
                    msgs = vec![Message { id: format!("retry-{step}"), body: Body::User {
                        text: "That was not a valid tool call and nothing ran. Call run_preset with a JSON object {\"name\":..., \"cwd\":...}, or if every preset has run, write the final plain-text report.".into() } }];
                    continue;
                }
                ollama::report(&outbox, &format!("[{thread}] {}", sweep::final_report(Ok(last), &results(&store))))?;
                ollama::unload_all(&specs); // free VRAM between sweeps
                return Ok(());
            }
            SliceOutcome::Waiting { call_id } => {
                // Log the folder the preset ACTUALLY runs in (pinned), not the model's guess.
                // Steps go to sweep.log only; the phone gets the task line and the final report.
                let call = store.history(&thread)?.into_iter().rev().find_map(|e| match e {
                    Entry::ToolCall { args, .. } => Some(args),
                    _ => None,
                });
                let name = call.as_ref().and_then(|a| a.get("name")).and_then(|v| v.as_str()).unwrap_or("?").to_string();
                let cwd = preset::pinned_cwd(&name).map(str::to_string)
                    .or_else(|| call.as_ref().and_then(|a| a.get("cwd")).and_then(|v| v.as_str()).map(str::to_string))
                    .unwrap_or_default();
                eprintln!("[{thread}] step {step}: {name} in {cwd}");
                msgs = wait_result(&inbox, &thread, &call_id, &name, cap)?;
            }
            SliceOutcome::Duplicate => return Ok(()),
        }
    }
    ollama::unload_all(&specs);
    ollama::report(&outbox, &format!("[{thread}] stopped after {MAX_STEPS} steps without a final answer, raw report:\n{}", sweep::fallback_report(&results(&store))))
}

/// A "final answer" that is really a tool call the model failed to format.
fn looks_like_tool_call(t: &str) -> bool {
    let t = t.trim();
    (t.starts_with('{') || t.starts_with("```")) && (t.contains("\"tool\"") || t.contains("run_preset"))
}

const FLEET: &str = r"D:\dev\bin\atrium.exe";
const FLEET_CFG: &str = r"D:\ATRIUM\ops\atrium.toml";

fn fleet(args: &[&str]) -> (bool, String) {
    let mut c = std::process::Command::new(FLEET);
    c.arg("fleet").arg(FLEET_CFG).args(args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        c.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    match c.output() {
        Ok(o) => (o.status.success(), format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)).trim().to_string()),
        Err(e) => (false, format!("spawn {FLEET}: {e}")),
    }
}

/// What to do for one `fleet status` reading. Pure, so it is tested without a fleet.
/// Rooms the supervisor itself spawns (kind = "managed" in atrium.toml). Only these can be
/// restarted from fleet; external rooms belong to their own scheduled tasks.
fn managed_rooms(toml: &str) -> Vec<String> {
    let mut out = Vec::new();
    for block in toml.split("[[room]]").skip(1) {
        let block = block.split("\n[").next().unwrap_or("");
        let val = |key: &str| block.lines().map(str::trim).find_map(|l| {
            let (k, v) = l.split_once('=')?;
            (k.trim() == key).then(|| v.trim().trim_matches('"').to_string())
        });
        if val("kind").as_deref() == Some("managed") {
            if let Some(n) = val("name") { out.push(n); }
        }
    }
    out
}

fn heal_plan(status: &str, managed: &[String]) -> Vec<Vec<String>> {
    let Some(pc) = status.lines().find(|l| l.starts_with("xing-pc:")) else { return vec![] };
    if pc.contains("atrium DOWN") {
        return vec![vec!["up".into()]];
    }
    // "xing-pc: atrium UP, 7 rooms, 1 down (loop), restarts ..."
    let Some(open) = pc.find(" down (") else { return vec![] };
    let rest = &pc[open + 7..];
    let Some(close) = rest.find(')') else { return vec![] };
    rest[..close].split(',').map(str::trim).filter(|r| !r.is_empty() && managed.iter().any(|m| m == r))
        .map(|r| vec!["restart".into(), r.to_string(), "--yes".into()]).collect()
}

/// One AUTO line. External-room refusals are info ("skipped"), never "FAILED".
fn heal_line(plan: &[String], ok: bool, text: &str) -> String {
    let verb = match sweep::heal_outcome(ok, text) {
        sweep::Heal::Did => "did",
        sweep::Heal::Failed => "FAILED",
        sweep::Heal::Skipped => "skipped (external, owned by its own task)",
    };
    format!("{verb} {}: {}", plan.join(" ").replace(" --yes", ""), text.lines().next().unwrap_or(""))
}

fn auto_heal() -> Vec<String> {
    let (ok, status) = fleet(&["status"]);
    if !ok { return vec![format!("could not read fleet status: {}", status.lines().next().unwrap_or(""))] }
    let mut out = Vec::new();
    let managed = managed_rooms(&std::fs::read_to_string(FLEET_CFG).unwrap_or_default());
    for plan in heal_plan(&status, &managed) {
        let a: Vec<&str> = plan.iter().map(String::as_str).collect();
        let (ok, text) = fleet(&a);
        out.push(heal_line(&plan, ok, &text));
    }
    out
}

#[cfg(test)]
mod heal_tests {
    use super::{heal_line, heal_plan, managed_rooms};
    #[test]
    fn plans() {
        let m: Vec<String> = vec!["loop".into(), "fleet-bot".into()];
        assert!(heal_plan("xing-pc: atrium UP, 7 rooms, 0 down, restarts 0, chain seq 1", &m).is_empty());
        assert_eq!(heal_plan("xing-pc: atrium DOWN (no live supervisor)", &m), vec![vec!["up".to_string()]]);
        assert_eq!(heal_plan("xing-pc: atrium UP, 7 rooms, 2 down (loop, fleet-bot), restarts 3, chain seq 9", &m).len(), 2);
        assert!(heal_plan("mini: anchor-peer up", &m).is_empty());
    }
    #[test]
    fn external_rooms_are_never_restarted() {
        let toml = "[[room]]\nname = \"ward\"\nfresh_file = \"x\"\n\n[[room]]\nname = \"loop\"\nkind = \"managed\"\nexe = \"y\"\n\n[[room]]\nname = \"xing-pc-mcp\"\nprocess = \"xing-pc-mcp.exe\"\n\n[[verify]]\nname = \"n\"\nkind = \"managed\"\n";
        let m = managed_rooms(toml);
        assert_eq!(m, vec!["loop".to_string()]);
        let p = heal_plan("xing-pc: atrium UP, 7 rooms, 3 down (ductei-sync, xing-pc-mcp, loop), restarts 0", &m);
        assert_eq!(p, vec![vec!["restart".to_string(), "loop".into(), "--yes".into()]]);
    }
    #[test]
    fn external_refusal_is_reported_as_skipped() {
        let plan = vec!["restart".to_string(), "ductei-sync".into(), "--yes".into()];
        let l = heal_line(&plan, false, "ductei-sync is external (owned by its own task); not restartable from fleet");
        assert!(l.starts_with("skipped") && !l.contains("FAILED"), "{l}");
        assert!(heal_line(&plan, false, "no live pid").starts_with("FAILED"));
        assert!(heal_line(&plan, true, "stopped").starts_with("did restart ductei-sync"));
    }
    #[test]
    fn broken_tool_call_is_not_a_report() {
        assert!(super::looks_like_tool_call(r#"{"tool":"run_preset","args":{"name":"fleet_alarms","cwd":"D:\\ATRIUM"}}}"#));
        assert!(!super::looks_like_tool_call("Alarms: none. Tests: all passed."));
    }
}
