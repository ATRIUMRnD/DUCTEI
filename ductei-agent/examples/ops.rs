//! ATRIUM ops agent: charter-driven, local brain, reports to Telegram via the fleet bot.
//!   cargo run -q -p ductei-agent --example ops -- "check atrium-watch tests and report"
//! Each slice is persisted before acting; between tool calls the agent holds nothing.
//! Env overrides: ATRIUM_AGENT_MODEL (default gpt-oss:20b), OLLAMA_URL.
use ductei_agent::{ollama, preset, run_slice, Body, Message, SliceOutcome, Store};
use std::path::PathBuf;
use std::time::{Duration, Instant};

const ROOT: &str = r"D:\ATRIUM\ops\atrium-state\agent";
const CHARTER: &str = r"D:\ATRIUM\ops\agent\CHARTER.md";
const MAX_STEPS: usize = 6; // goal 1 bound: no endless self-driven loops
const JOB_WAIT: Duration = Duration::from_secs(30 * 60);

fn main() {
    if let Err(e) = run() {
        let _ = ollama::report(&PathBuf::from(ROOT).join("outbox.jsonl"), &format!("ERROR: {e}"));
        eprintln!("ops: {e}");
        std::process::exit(1);
    }
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
    let mut brain = ollama::Ollama {
        base: std::env::var("OLLAMA_URL").unwrap_or_else(|_| "http://100.106.147.75:11434".into()),
        model: std::env::var("ATRIUM_AGENT_MODEL").unwrap_or_else(|_| "gpt-oss:20b".into()),
        charter: std::fs::read_to_string(CHARTER).map_err(|e| format!("{CHARTER}: {e}"))?,
        presets: allow.clone(),
        timeout_s: 300,
    };
    let mut d = ollama::GpuHandoff {
        inner: preset::PresetDispatcher {
            exe: r"D:\ATRIUM\xing-pc-mcp\target\release\xing-pc-mcp.exe".into(),
            inbox: inbox.clone(),
            allow,
        },
        base: brain.base.clone(),
        model: brain.model.clone(),
    };
    // One thread per run, so tasks never bleed into each other.
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let thread = format!("ops-{now}");
    ollama::report(&outbox, &format!("[{thread}] task: {task}"))?;

    let mut msgs = vec![Message { id: "task".into(), body: Body::User { text: task } }];
    for step in 1..=MAX_STEPS {
        match run_slice(&store, &thread, &msgs, &mut brain, &mut d)? {
            SliceOutcome::Idle => {
                let last = store.history(&thread)?.into_iter().rev().find_map(|e| match e {
                    ductei_agent::Entry::Assistant { text } => Some(text),
                    _ => None,
                });
                ollama::report(&outbox, &format!("[{thread}] {}", last.unwrap_or_default()))?;
                return Ok(());
            }
            SliceOutcome::Waiting { call_id } => {
                let call = store.history(&thread)?.into_iter().rev().find_map(|e| match e {
                    ductei_agent::Entry::ToolCall { args, .. } => Some(args.to_string()),
                    _ => None,
                });
                ollama::report(&outbox, &format!("[{thread}] step {step}: running {}", call.unwrap_or_default()))?;
                let t0 = Instant::now();
                loop {
                    let got = preset::collect(&inbox, &thread)?;
                    if got.iter().any(|m| matches!(&m.body, Body::ToolResult { call_id: c, .. } if *c == call_id)) {
                        preset::ack(&inbox, &thread, &got)?;
                        msgs = got;
                        break;
                    }
                    if t0.elapsed() > JOB_WAIT {
                        return Err(format!("{call_id}: no result after {}s", JOB_WAIT.as_secs()));
                    }
                    std::thread::sleep(Duration::from_secs(2));
                }
            }
            SliceOutcome::Duplicate => return Ok(()),
        }
    }
    ollama::report(&outbox, &format!("[{thread}] stopped after {MAX_STEPS} steps without a final answer; needs Xing"))
}
