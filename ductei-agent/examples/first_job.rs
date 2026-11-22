//! First real job: ductei-agent asks xing-pc-mcp to run atrium-watch's tests,
//! hibernates (process may exit), then a later slice collects the result.
//!   cargo run -q -p ductei-agent --example first_job -- dispatch
//!   cargo run -q -p ductei-agent --example first_job -- collect
//! Scripted model for now; a real model (Ollama on the 5080) slots into `Model`.
use ductei_agent::{preset, run_slice, Body, Entry, Message, Model, ModelOut, Store};
use std::path::PathBuf;

const ROOT: &str = r"D:\ATRIUM\ops\atrium-state\agent";
const THREAD: &str = "first-job";

struct Scripted;
impl Model for Scripted {
    fn complete(&mut self, h: &[Entry]) -> Result<ModelOut, String> {
        Ok(match h.last() {
            Some(Entry::User { .. }) => ModelOut::ToolCall {
                tool: preset::TOOL.into(),
                args: serde_json::json!({"name": "cargo_test_watch", "cwd": r"D:\ATRIUM\DUCTEI"}),
            },
            Some(Entry::ToolResult { output, .. }) => {
                let tail: Vec<&str> = output.lines().filter(|l| l.contains("test result")).collect();
                ModelOut::Text(format!("atrium-watch: {}", if tail.is_empty() { "no test summary (see output)".into() } else { tail.join(" | ") }))
            }
            _ => ModelOut::Text("nothing to do".into()),
        })
    }
}

fn main() -> Result<(), String> {
    let store = Store::open(PathBuf::from(ROOT).join("history"))?;
    let inbox = PathBuf::from(ROOT).join("inbox");
    let mut d = preset::PresetDispatcher {
        exe: r"D:\ATRIUM\xing-pc-mcp\target\release\xing-pc-mcp.exe".into(),
        inbox: inbox.clone(),
        allow: vec!["cargo_test_watch".into(), "cargo_test_agent".into(), "git_status".into()],
    };
    match std::env::args().nth(1).as_deref() {
        Some("dispatch") => {
            let id = format!("u{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs());
            let o = run_slice(&store, THREAD, &[Message { id, body: Body::User { text: "run atrium-watch tests".into() } }], &mut Scripted, &mut d)?;
            println!("{o:?} (agent now hibernates; nothing held in memory)");
        }
        Some("collect") => {
            let msgs = preset::collect(&inbox, THREAD)?;
            if msgs.is_empty() { println!("still running"); return Ok(()); }
            let o = run_slice(&store, THREAD, &msgs, &mut Scripted, &mut d)?;
            preset::ack(&inbox, THREAD, &msgs)?;
            if let Some(Entry::Assistant { text }) = store.history(THREAD)?.last() { println!("{o:?}: {text}"); }
        }
        _ => return Err("usage: first_job dispatch|collect".into()),
    }
    Ok(())
}
