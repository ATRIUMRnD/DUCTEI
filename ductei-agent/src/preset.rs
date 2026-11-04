//! Real tools for ductei-agent: xing-pc-mcp command presets.
//!
//! The agent never gets its own exec path. Dispatch spawns
//! `xing-pc-mcp run-preset <name> <cwd> <out>` detached, so the server's policy applies
//! unchanged (preset by name only, cwd under the roots, kill switch, audit chain).
//! The child writes `<inbox>/<thread>/<call_id>.json` via tmp + rename and outlives this
//! process; the agent hibernates and a later `collect` turns the file into a ToolResult.
//! The child's pid goes to `<call_id>.pid` so a caller can kill a hung call (`expire`).

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

/// Write an error result for `call_id` (tmp + rename). No-op when a result already exists.
fn write_error(dir: &Path, call_id: &str, text: &str) -> Result<(), String> {
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let out = dir.join(format!("{call_id}.json"));
    if out.exists() {
        return Ok(());
    }
    let tmp = dir.join(format!("{call_id}.json.tmp"));
    fs::write(&tmp, serde_json::json!({ "ok": false, "output": text }).to_string()).map_err(|e| e.to_string())?;
    fs::rename(&tmp, &out).map_err(|e| e.to_string())
}

impl PresetDispatcher {
    fn thread_dir(&self, thread: &str) -> Result<PathBuf, String> {
        if !safe(thread) {
            return Err(format!("invalid thread name: {thread:?}"));
        }
        Ok(self.inbox.join(thread))
    }

    /// Answer a refused call with an error result (tmp + rename, like the real runner).
    /// Nothing is spawned; the thread resumes and the model sees `ERROR: <why>`.
    fn refuse(&self, thread: &str, call_id: &str, why: &str) -> Result<(), String> {
        write_error(&self.thread_dir(thread)?, call_id, &format!("refused: {why}"))
    }
}

impl Dispatcher for PresetDispatcher {
    fn dispatch(&mut self, thread: &str, call_id: &str, tool: &str, args: &serde_json::Value) -> Result<(), String> {
        // Ids name files: an unsafe one is a hard error (nothing is written anywhere).
        if !safe(call_id) {
            return Err(format!("invalid call id: {call_id:?}"));
        }
        // gpt-oss may namespace tool names ("tool.run_preset", "functions.run_preset"); compare the bare name.
        let tool = tool.rsplit('.').next().unwrap_or(tool);
        if tool != TOOL {
            // Refused, nothing runs; the model gets the reason as the call's result and can retry.
            return self.refuse(thread, call_id, &format!("tool `{tool}` is not allowed (only `{TOOL}`)"));
        }
        let Some(name) = args.get("name").and_then(|v| v.as_str()) else {
            return self.refuse(thread, call_id, "missing `name`");
        };
        if !self.allow.iter().any(|a| a == name) {
            return self.refuse(thread, call_id, &format!("preset `{name}` is not on this agent's allowlist"));
        }
        // Models often over-escape Windows paths (D:\\\\ATRIUM); collapse doubled separators.
        // cwd is optional for pinned presets (the pin wins anyway).
        let mut cwd = args.get("cwd").and_then(|v| v.as_str()).unwrap_or(pinned_cwd(name).unwrap_or("")).replace('/', "\\");
        if cwd.is_empty() {
            return self.refuse(thread, call_id, "missing `cwd`");
        }
        while cwd.contains("\\\\") {
            cwd = cwd.replace("\\\\", "\\");
        }
        // Pin the working folder for known presets so the model can't send them to the wrong repo.
        let cwd = pinned_cwd(name).unwrap_or(cwd.as_str());
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
        let child = cmd.spawn().map_err(|e| format!("spawn {}: {e}", self.exe.display()))?;
        // Best effort: without the pid a hung call is still expired, just not killed.
        let _ = fs::write(dir.join(format!("{call_id}.pid")), child.id().to_string());
        Ok(())
    }
}

/// Pid recorded for a dispatched call, if any.
pub fn call_pid(inbox: &Path, thread: &str, call_id: &str) -> Option<u32> {
    if !safe(thread) || !safe(call_id) {
        return None;
    }
    fs::read_to_string(inbox.join(thread).join(format!("{call_id}.pid"))).ok()?.trim().parse().ok()
}

/// A call ran past its cap: kill its process tree (via `kill`) and record
/// `<preset>: timed out after <secs>s` as its result so the sweep continues.
pub fn expire(inbox: &Path, thread: &str, call_id: &str, preset: &str, secs: u64, kill: &mut dyn FnMut(u32)) -> Result<(), String> {
    if !safe(thread) || !safe(call_id) {
        return Err(format!("invalid thread or call id: {thread:?} {call_id:?}"));
    }
    if let Some(pid) = call_pid(inbox, thread, call_id) {
        kill(pid);
    }
    write_error(&inbox.join(thread), call_id, &crate::sweep::timeout_text(preset, secs))
}

/// Fixed working folder per preset; `None` means the caller's cwd is used.
pub fn pinned_cwd(preset: &str) -> Option<&'static str> {
    match preset {
        "cargo_check" | "cargo_test_watch" | "cargo_test_agent" | "cargo_test_ctl" | "git_status" | "git_log"
        | "git_diff_stat" => Some(r"D:\ATRIUM\DUCTEI"),
        "fleet_status" | "fleet_alarms" | "nvidia_smi" => Some(r"D:\ATRIUM"),
        "limen_gpu_tier0" => Some(r"D:\ATRIUM\LIMEN"),
        _ => None,
    }
}

#[cfg(test)]
mod pin_tests {
    #[test]
    fn cargo_presets_pin_to_ductei() {
        assert_eq!(super::pinned_cwd("cargo_test_ctl"), Some(r"D:\ATRIUM\DUCTEI"));
        assert_eq!(super::pinned_cwd("fleet_alarms"), Some(r"D:\ATRIUM"));
        assert_eq!(super::pinned_cwd("limen_gpu_tier0"), Some(r"D:\ATRIUM\LIMEN"));
        assert_eq!(super::pinned_cwd("not_a_preset"), None);
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
            for f in [format!("{call_id}.json"), format!("{call_id}.pid")] {
                let src = dir.join(&f);
                if src.exists() {
                    fs::rename(&src, done.join(&f)).map_err(|e| e.to_string())?;
                }
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
        // Wrong tool / unlisted preset: refused as an ERROR result the model can read, nothing spawned
        // (the exe does not exist, so a spawn attempt would have been an Err).
        p.dispatch("t", "c1", "assistant", &json!({})).unwrap();
        p.dispatch("t", "c2", TOOL, &json!({"name": "fleet_up", "cwd": "D:\\ATRIUM"})).unwrap();
        let got = collect(&d, "t").unwrap();
        assert_eq!(got.len(), 2);
        for m in &got {
            assert!(matches!(&m.body, Body::ToolResult { output, .. } if output.starts_with("ERROR: refused:")), "{m:?}");
        }
        let o = |c: &str| fs::read_to_string(d.join("t").join(format!("{c}.json"))).unwrap();
        assert!(o("c1").contains("not allowed") && o("c2").contains("allowlist"));
        // Unsafe ids are still hard errors and write nothing.
        assert!(p.dispatch("..\\x", "c3", TOOL, &json!({"name": "cargo_test", "cwd": "D:\\ATRIUM"})).is_err());
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

    #[test]
    fn expired_call_is_killed_and_recorded_as_timeout() {
        let d = tmp("expire");
        fs::create_dir_all(d.join("t")).unwrap();
        fs::write(d.join("t").join("c7.pid"), "4242").unwrap();
        let mut killed = Vec::new();
        expire(&d, "t", "c7", "cargo_test_ctl", 120, &mut |p| killed.push(p)).unwrap();
        assert_eq!(killed, vec![4242]);
        let m = collect(&d, "t").unwrap();
        assert!(matches!(&m[0].body, Body::ToolResult { output, .. } if output == "ERROR: cargo_test_ctl: timed out after 120s"), "{m:?}");
        assert!(crate::sweep::is_timeout(match &m[0].body { Body::ToolResult { output, .. } => output, _ => "" }));
        // A late real result never overwrites the recorded timeout, and a missing pid still expires.
        expire(&d, "t", "c8", "git_status", 120, &mut |_| panic!("no pid, nothing to kill")).unwrap();
        ack(&d, "t", &m).unwrap();
        assert!(d.join("t").join("done").join("c7.pid").exists());
        assert!(expire(&d, "..", "c", "x", 1, &mut |_| {}).is_err());
    }
}
