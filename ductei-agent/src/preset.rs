//! Real tools for ductei-agent: xing-pc-mcp command presets.
//!
//! The agent never gets its own exec path. Dispatch spawns
//! `xing-pc-mcp run-preset <name> <cwd> <out>` detached, so the server's policy applies
//! unchanged (preset by name only, cwd under the roots, kill switch, audit chain).
//! The child writes `<inbox>/<thread>/<call_id>.json` via tmp + rename and outlives this
//! process; the agent hibernates and a later `collect` turns the file into a ToolResult.

use crate::{Body, Dispatcher, Message};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The only tool name the model may call through this dispatcher.
pub const TOOL: &str = "run_preset";

pub struct PresetDispatcher {
    /// Path to xing-pc-mcp.exe.
    pub exe: PathBuf,
    /// Result inbox root; must sit under xing-pc-mcp's roots.
    pub inbox: PathBuf,
    /// Deny-by-default allowlist of preset names this agent may run.
    pub allow: Vec<String>,
}

fn safe(s: &str) -> bool {
    !s.is_empty() && s.len() <= 96 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

impl PresetDispatcher {
    fn thread_dir(&self, thread: &str) -> Result<PathBuf, String> {
        if !safe(thread) {
            return Err(format!("invalid thread name: {thread:?}"));
        }
        Ok(self.inbox.join(thread))
    }
}

impl Dispatcher for PresetDispatcher {
    fn dispatch(&mut self, thread: &str, call_id: &str, tool: &str, args: &serde_json::Value) -> Result<(), String> {
        if tool != TOOL {
            return Err(format!("tool `{tool}` is not allowed (only `{TOOL}`)"));
        }
        if !safe(call_id) {
            return Err(format!("invalid call id: {call_id:?}"));
        }
        let name = args.get("name").and_then(|v| v.as_str()).ok_or("missing `name`")?;
        if !self.allow.iter().any(|a| a == name) {
            return Err(format!("preset `{name}` is not on this agent's allowlist"));
        }
        // Models often over-escape Windows paths (D:\\\\ATRIUM); collapse doubled separators.
        let mut cwd = args.get("cwd").and_then(|v| v.as_str()).ok_or("missing `cwd`")?.replace('/', "\\");
        while cwd.contains("\\\\") {
            cwd = cwd.replace("\\\\", "\\");
        }
        let cwd = cwd.as_str();
        let dir = self.thread_dir(thread)?;
        fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let out = dir.join(format!("{call_id}.json"));
        if out.exists() {
            return Ok(()); // already dispatched and finished: redelivery is a no-op
        }
        let mut cmd = Command::new(&self.exe);
        cmd.args(["run-preset", name, cwd])
            .arg(&out)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            // CREATE_NO_WINDOW | DETACHED_PROCESS: survives this process, no console flash.
            cmd.creation_flags(0x0800_0000 | 0x0000_0008);
        }
        cmd.spawn().map(|_| ()).map_err(|e| format!("spawn {}: {e}", self.exe.display()))
    }
}

/// Finished results for `thread`, as messages ready for `run_slice`. Ids are
/// `res_<call_id>`, so a file read twice is processed once by the store's dedupe.
pub fn collect(inbox: &Path, thread: &str) -> Result<Vec<Message>, String> {
    if !safe(thread) {
        return Err(format!("invalid thread name: {thread:?}"));
    }
    let dir = inbox.join(thread);
    let rd = match fs::read_dir(&dir) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.to_string()),
    };
    let mut files: Vec<PathBuf> = rd
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    let mut out = Vec::new();
    for p in files {
        let call_id = p.file_stem().and_then(|s| s.to_str()).unwrap_or_default().to_string();
        if !safe(&call_id) {
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(&fs::read_to_string(&p).map_err(|e| e.to_string())?)
            .map_err(|e| format!("{}: {e}", p.display()))?;
        let ok = v.get("ok").and_then(|b| b.as_bool()).unwrap_or(false);
        let text = v.get("output").and_then(|s| s.as_str()).unwrap_or_default();
        let output = if ok { text.to_string() } else { format!("ERROR: {text}") };
        out.push(Message { id: format!("res_{call_id}"), body: Body::ToolResult { call_id, output } });
    }
    Ok(out)
}

/// Move processed results into `<thread>/done/` (kept for audit, never deleted).
pub fn ack(inbox: &Path, thread: &str, msgs: &[Message]) -> Result<(), String> {
    if !safe(thread) {
        return Err(format!("invalid thread name: {thread:?}"));
    }
    let dir = inbox.join(thread);
    let done = dir.join("done");
    fs::create_dir_all(&done).map_err(|e| e.to_string())?;
    for m in msgs {
        if let Body::ToolResult { call_id, .. } = &m.body {
            let f = format!("{call_id}.json");
            let src = dir.join(&f);
            if src.exists() {
                fs::rename(&src, done.join(&f)).map_err(|e| e.to_string())?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{run_slice, Entry, Model, ModelOut, SliceOutcome, Store};
    use serde_json::json;

    fn tmp(name: &str) -> PathBuf {
        let d = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("target").join("agent-test").join(format!("{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn disp(inbox: &Path) -> PresetDispatcher {
        PresetDispatcher { exe: PathBuf::from("does-not-exist.exe"), inbox: inbox.into(), allow: vec!["cargo_test".into()] }
    }

    #[test]
    fn deny_by_default() {
        let d = tmp("deny");
        let mut p = disp(&d);
        assert!(p.dispatch("t", "c1", "shell", &json!({})).unwrap_err().contains("not allowed"));
        assert!(p.dispatch("t", "c1", TOOL, &json!({"name": "fleet_up", "cwd": "D:\\ATRIUM"})).unwrap_err().contains("allowlist"));
        assert!(p.dispatch("..\\x", "c1", TOOL, &json!({"name": "cargo_test", "cwd": "D:\\ATRIUM"})).is_err());
        assert!(p.dispatch("t", "..\\c", TOOL, &json!({"name": "cargo_test", "cwd": "D:\\ATRIUM"})).is_err());
    }

    struct OneShot;
    impl Model for OneShot {
        fn complete(&mut self, h: &[Entry]) -> Result<ModelOut, String> {
            Ok(match h.last() {
                Some(Entry::User { .. }) => ModelOut::ToolCall { tool: TOOL.into(), args: json!({"name": "cargo_test", "cwd": "D:\\ATRIUM\\DUCTEI"}) },
                Some(Entry::ToolResult { output, .. }) => ModelOut::Text(format!("done: {output}")),
                _ => ModelOut::Text("?".into()),
            })
        }
    }

    #[test]
    fn result_file_resumes_the_thread_once() {
        let d = tmp("resume");
        let store = Store::open(d.join("hist")).unwrap();
        let inbox = d.join("inbox");
        // Pretend the result already landed so the spawn is skipped (no real exe in tests).
        let call_id = "call_t_1";
        fs::create_dir_all(inbox.join("t")).unwrap();
        fs::write(inbox.join("t").join(format!("{call_id}.json")), r#"{"ok":true,"output":"5 passed"}"#).unwrap();
        let mut p = disp(&inbox);
        let o = run_slice(&store, "t", &[Message { id: "u1".into(), body: Body::User { text: "test".into() } }], &mut OneShot, &mut p).unwrap();
        assert_eq!(o, SliceOutcome::Waiting { call_id: call_id.into() });

        let msgs = collect(&inbox, "t").unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(run_slice(&store, "t", &msgs, &mut OneShot, &mut p).unwrap(), SliceOutcome::Idle);
        ack(&inbox, "t", &msgs).unwrap();
        assert!(collect(&inbox, "t").unwrap().is_empty());
        assert!(inbox.join("t").join("done").join(format!("{call_id}.json")).exists());
        // Redelivery of the same result is a no-op.
        assert_eq!(run_slice(&store, "t", &msgs, &mut OneShot, &mut p).unwrap(), SliceOutcome::Duplicate);
    }

    #[test]
    fn failed_preset_is_marked_error() {
        let d = tmp("err");
        fs::create_dir_all(d.join("t")).unwrap();
        fs::write(d.join("t").join("c9.json"), r#"{"ok":false,"output":"kill switch is on"}"#).unwrap();
        let m = collect(&d, "t").unwrap();
        assert!(matches!(&m[0].body, Body::ToolResult { output, .. } if output.starts_with("ERROR:")));
    }
}
