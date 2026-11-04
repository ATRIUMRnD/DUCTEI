//! ductei-agent: slice-based agent loop.
//!
//! Pattern taken from hydro-project/infinity (Apache-2.0), rewritten small and
//! dependency-light for ATRIUM:
//! - Between turns an agent is only its history on disk (append-only JSONL).
//!   No task, no stack, no open connection, so a waiting agent costs nothing.
//! - A slice starts when messages arrive, loads history, drops already
//!   processed message ids (safe redelivery), calls the model, persists the
//!   new turn (fsync) BEFORE dispatching a tool (DUCTEI persistence-before-ack),
//!   fires the tool call without waiting, and ends.
//! - Tool results and outside events come back later as messages and start a
//!   new slice. Events are injected as synthetic tool results named
//!   `receive_event__injected`, so the model never mistakes them for the user.

pub mod ollama;
pub mod preset;
pub mod sweep;

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

pub const INJECTED_TOOL: &str = "receive_event__injected";

/// Something arriving in a thread's input queue.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Message {
    /// Unique id; a message delivered twice is processed once.
    pub id: String,
    pub body: Body,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Body {
    User { text: String },
    ToolResult { call_id: String, output: String },
    Event { source: String, payload: String },
}

/// One line of the durable history.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Entry {
    User { text: String },
    Assistant { text: String },
    ToolCall { call_id: String, tool: String, args: serde_json::Value },
    ToolResult { call_id: String, tool: String, output: String },
}

/// What the model returns for one completion.
#[derive(Debug, Clone, PartialEq)]
pub enum ModelOut {
    Text(String),
    ToolCall { tool: String, args: serde_json::Value },
}

pub trait Model {
    fn complete(&mut self, history: &[Entry]) -> Result<ModelOut, String>;
}

/// Fire-and-forget tool dispatch. Return Ok once the tool server has
/// acknowledged the request; the result arrives later as a Message.
pub trait Dispatcher {
    fn dispatch(&mut self, thread: &str, call_id: &str, tool: &str, args: &serde_json::Value)
        -> Result<(), String>;
}

#[derive(Debug, Clone, PartialEq)]
pub enum SliceOutcome {
    /// Model answered with text; the agent hibernates until a new message.
    Idle,
    /// A tool call was persisted and dispatched; the agent hibernates until its result.
    Waiting { call_id: String },
    /// Every input was already processed; nothing ran.
    Duplicate,
}

/// Durable per-thread store: `<dir>/<thread>.jsonl` and `<dir>/<thread>.ids`.
pub struct Store {
    dir: PathBuf,
}

impl Store {
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, String> {
        fs::create_dir_all(dir.as_ref()).map_err(|e| e.to_string())?;
        Ok(Self { dir: dir.as_ref().to_path_buf() })
    }

    fn path(&self, thread: &str, ext: &str) -> Result<PathBuf, String> {
        let ok = !thread.is_empty()
            && thread.len() <= 64
            && thread.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
        if !ok {
            return Err(format!("invalid thread name: {thread:?}"));
        }
        Ok(self.dir.join(format!("{thread}.{ext}")))
    }

    pub fn history(&self, thread: &str) -> Result<Vec<Entry>, String> {
        read_lines(&self.path(thread, "jsonl")?)?
            .iter()
            .map(|l| serde_json::from_str(l).map_err(|e| format!("corrupt history: {e}")))
            .collect()
    }

    fn processed(&self, thread: &str) -> Result<HashSet<String>, String> {
        Ok(read_lines(&self.path(thread, "ids")?)?.into_iter().collect())
    }

    fn append(&self, thread: &str, entries: &[Entry], ids: &[String]) -> Result<(), String> {
        // History first, then ids: a crash between the two replays the input,
        // which the model sees as a repeat, never as a lost message.
        let lines: Vec<String> = entries
            .iter()
            .map(|e| serde_json::to_string(e).map_err(|e| e.to_string()))
            .collect::<Result<_, _>>()?;
        append_fsync(&self.path(thread, "jsonl")?, &lines)?;
        append_fsync(&self.path(thread, "ids")?, ids)
    }
}

fn read_lines(p: &Path) -> Result<Vec<String>, String> {
    match File::open(p) {
        Ok(f) => BufReader::new(f)
            .lines()
            .filter(|l| l.as_ref().map(|s| !s.trim().is_empty()).unwrap_or(true))
            .collect::<Result<_, _>>()
            .map_err(|e| e.to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e.to_string()),
    }
}

fn append_fsync(p: &Path, lines: &[String]) -> Result<(), String> {
    if lines.is_empty() {
        return Ok(());
    }
    if lines.iter().any(|l| l.contains('\n')) {
        return Err("line contains newline".into());
    }
    let mut f = OpenOptions::new().create(true).append(true).open(p).map_err(|e| e.to_string())?;
    for l in lines {
        writeln!(f, "{l}").map_err(|e| e.to_string())?;
    }
    f.sync_all().map_err(|e| e.to_string())
}

fn tool_for(history: &[Entry], call_id: &str) -> Option<String> {
    history.iter().rev().find_map(|e| match e {
        Entry::ToolCall { call_id: c, tool, .. } if c == call_id => Some(tool.clone()),
        _ => None,
    })
}

/// Run one slice for `thread` with the messages that just arrived.
/// One model call per slice: a tool call ends the slice, so a confused model
/// cannot spin without a fresh message arriving.
pub fn run_slice(
    store: &Store,
    thread: &str,
    inbox: &[Message],
    model: &mut dyn Model,
    dispatcher: &mut dyn Dispatcher,
) -> Result<SliceOutcome, String> {
    let mut history = store.history(thread)?;
    let mut seen = store.processed(thread)?;

    let mut new_entries = Vec::new();
    let mut new_ids = Vec::new();
    for m in inbox {
        if !seen.insert(m.id.clone()) {
            continue; // already processed: safe redelivery
        }
        new_ids.push(m.id.clone());
        new_entries.push(match &m.body {
            Body::User { text } => Entry::User { text: text.clone() },
            Body::ToolResult { call_id, output } => Entry::ToolResult {
                call_id: call_id.clone(),
                tool: tool_for(&history, call_id)
                    .ok_or_else(|| format!("result for unknown call {call_id}"))?,
                output: output.clone(),
            },
            Body::Event { source, payload } => Entry::ToolResult {
                call_id: format!("evt_{}", m.id),
                tool: INJECTED_TOOL.into(),
                output: format!("[{source}] {payload}"),
            },
        });
    }
    if new_ids.is_empty() {
        return Ok(SliceOutcome::Duplicate);
    }
    history.extend(new_entries.iter().cloned());

    match model.complete(&history)? {
        ModelOut::Text(text) => {
            new_entries.push(Entry::Assistant { text });
            store.append(thread, &new_entries, &new_ids)?;
            Ok(SliceOutcome::Idle)
        }
        ModelOut::ToolCall { tool, args } => {
            if tool == INJECTED_TOOL {
                return Err("model may not call the injected-event tool".into());
            }
            let call_id = format!("call_{}_{}", thread, history.len());
            new_entries.push(Entry::ToolCall { call_id: call_id.clone(), tool: tool.clone(), args: args.clone() });
            // Persistence before dispatch: the call is on disk before anyone acts on it.
            store.append(thread, &new_entries, &new_ids)?;
            dispatcher.dispatch(thread, &call_id, &tool, &args)?;
            Ok(SliceOutcome::Waiting { call_id })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("ductei-agent-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    /// Calls a tool on the first user turn, answers with text after a result.
    struct Scripted;
    impl Model for Scripted {
        fn complete(&mut self, h: &[Entry]) -> Result<ModelOut, String> {
            Ok(match h.last() {
                Some(Entry::User { .. }) => ModelOut::ToolCall { tool: "cargo_test".into(), args: json!({"cwd": "D:\\ATRIUM\\DUCTEI"}) },
                Some(Entry::ToolResult { output, .. }) => ModelOut::Text(format!("saw: {output}")),
                _ => ModelOut::Text("?".into()),
            })
        }
    }

    /// Records dispatches and checks the call is already on disk.
    struct Rec { dir: PathBuf, calls: Vec<String> }
    impl Dispatcher for Rec {
        fn dispatch(&mut self, thread: &str, call_id: &str, _t: &str, _a: &serde_json::Value) -> Result<(), String> {
            let h = Store::open(&self.dir)?.history(thread)?;
            assert!(h.iter().any(|e| matches!(e, Entry::ToolCall { call_id: c, .. } if c == call_id)), "dispatched before persisted");
            self.calls.push(call_id.into());
            Ok(())
        }
    }

    #[test]
    fn hibernates_and_resumes_across_process_restart() {
        let dir = tmp("resume");
        let mut d = Rec { dir: dir.clone(), calls: vec![] };
        let s1 = Store::open(&dir).unwrap();
        let o = run_slice(&s1, "t1", &[Message { id: "m1".into(), body: Body::User { text: "run tests".into() } }], &mut Scripted, &mut d).unwrap();
        let SliceOutcome::Waiting { call_id } = o else { panic!("{o:?}") };
        drop(s1); // "process exits": nothing left in memory

        let s2 = Store::open(&dir).unwrap();
        let o = run_slice(&s2, "t1", &[Message { id: "r1".into(), body: Body::ToolResult { call_id, output: "11 passed".into() } }], &mut Scripted, &mut d).unwrap();
        assert_eq!(o, SliceOutcome::Idle);
        let h = s2.history("t1").unwrap();
        assert_eq!(h.last(), Some(&Entry::Assistant { text: "saw: 11 passed".into() }));
        assert_eq!(d.calls.len(), 1);
    }

    #[test]
    fn redelivered_message_runs_once() {
        let dir = tmp("dedupe");
        let s = Store::open(&dir).unwrap();
        let mut d = Rec { dir: dir.clone(), calls: vec![] };
        let m = Message { id: "m1".into(), body: Body::User { text: "go".into() } };
        run_slice(&s, "t", std::slice::from_ref(&m), &mut Scripted, &mut d).unwrap();
        assert_eq!(run_slice(&s, "t", &[m], &mut Scripted, &mut d).unwrap(), SliceOutcome::Duplicate);
        assert_eq!(d.calls.len(), 1);
    }

    #[test]
    fn events_are_injected_not_user() {
        let dir = tmp("inject");
        let s = Store::open(&dir).unwrap();
        let mut d = Rec { dir: dir.clone(), calls: vec![] };
        run_slice(&s, "t", &[Message { id: "e1".into(), body: Body::Event { source: "ward".into(), payload: "I3 ok".into() } }], &mut Scripted, &mut d).unwrap();
        let h = s.history("t").unwrap();
        assert!(matches!(&h[0], Entry::ToolResult { tool, .. } if tool == INJECTED_TOOL));
        assert!(!h.iter().any(|e| matches!(e, Entry::User { .. })));
    }

    #[test]
    fn rejects_path_traversal_thread_names() {
        let s = Store::open(tmp("names")).unwrap();
        assert!(s.history("..\\..\\x").is_err());
        assert!(s.history("../x").is_err());
        assert!(s.history("").is_err());
    }

    #[test]
    fn unknown_tool_result_is_refused() {
        let dir = tmp("unknown");
        let s = Store::open(&dir).unwrap();
        let mut d = Rec { dir: dir.clone(), calls: vec![] };
        let r = run_slice(&s, "t", &[Message { id: "x".into(), body: Body::ToolResult { call_id: "nope".into(), output: "".into() } }], &mut Scripted, &mut d);
        assert!(r.is_err());
        assert!(s.history("t").unwrap().is_empty());
    }
}
