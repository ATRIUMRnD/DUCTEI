//! ductei-hook: Claude Code PreToolUse hook that makes the router mandatory.
//!
//! stdin:  the hook JSON ({tool_name, tool_input, session_id, cwd, ...}).
//! stdout: {"hookSpecificOutput":{"hookEventName":"PreToolUse",
//!          "permissionDecision":"allow"|"ask"|"deny","permissionDecisionReason":...}}
//!
//! Mapping (tool call -> Task effects):
//!   Write / Edit / MultiEdit / NotebookEdit  -> write <file_path>
//!   Bash / PowerShell                         -> git commit -> commit, git push -> push,
//!                                                delete verbs -> delete <path>, write verbs
//!                                                or redirects -> write <path>
//!   Read and everything else                 -> pass through (no receipt) unless
//!                                                DUCTEI_HOOK_STRICT_READ=1
//! Approvals come from `<state>/approvals.txt` (one token per line, e.g.
//! `commit`, `push`, `delete:d:\dev\x`) and `DUCTEI_APPROVE` (comma list).
//! Any hook failure answers "ask", never a silent allow.

use ductei_router::*;
use serde_json::{json, Value};
use std::io::Read;
use std::path::{Path, PathBuf};

const DEFAULT_STATE: &str = r"D:\dev\ductei-router-state";

fn out(decision: &str, reason: String) {
    println!("{}", json!({ "hookSpecificOutput": { "hookEventName": "PreToolUse", "permissionDecision": decision, "permissionDecisionReason": reason } }));
}

fn approvals(state: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_to_string(state.join("approvals.txt")).unwrap_or_default()
        .lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty() && !l.starts_with('#')).collect();
    if let Ok(e) = std::env::var("DUCTEI_APPROVE") { v.extend(e.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty())); }
    v
}

fn looks_like_path(tok: &str) -> Option<PathBuf> {
    let t = tok.trim_matches(|c| c == '"' || c == '\'' || c == '`' || c == ',' || c == ';' || c == ')' || c == '(');
    let b = t.as_bytes();
    if b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/') { return Some(PathBuf::from(t)); }
    if t.starts_with("/mnt/") && t.len() > 6 { // WSL view of a Windows drive
        let drive = t.as_bytes()[5].to_ascii_uppercase() as char;
        return Some(PathBuf::from(format!("{drive}:{}", t[6..].replace('/', "\\"))));
    }
    None
}

/// Heuristic effect extraction for a shell command. Conservative: when a
/// write or delete verb is present, every absolute path in the command is
/// treated as its target.
pub fn shell_effects(cmd: &str) -> Vec<Effect> {
    let lower = cmd.to_ascii_lowercase();
    let mut eff = Vec::new();
    let has = |needles: &[&str]| needles.iter().any(|n| lower.contains(n));
    if has(&["git commit", "git merge", "git rebase", "git cherry-pick", "git am "]) { eff.push(Effect::Commit); }
    if has(&["git push"]) { eff.push(Effect::Push); }
    let deletes = has(&["remove-item", " rm ", "rm -", "del ", "erase ", "rmdir", " rd ", "git clean", "git reset --hard", "git checkout --", "git restore"]);
    let writes = deletes || has(&["set-content", "add-content", "out-file", "new-item", "copy-item", "move-item", "rename-item", " cp ", " mv ", "tee ", "sed -i", "mkdir", "touch ", "cargo build", "cargo run", "cargo test", "pip install", "npm install", "git stash", "git pull", "git checkout", "git switch", ">"]);
    let paths: Vec<PathBuf> = cmd.split(|c: char| c.is_whitespace() || c == '=').filter_map(looks_like_path).collect();
    for p in paths {
        if deletes { eff.push(Effect::Delete(p)); }
        else if writes { eff.push(Effect::Write(p)); }
        else if std::env::var("DUCTEI_HOOK_STRICT_READ").ok().as_deref() == Some("1") { eff.push(Effect::Read(p)); }
    }
    if deletes && !eff.iter().any(|e| matches!(e, Effect::Delete(_))) {
        // A delete with no recognisable absolute path: refuse to guess, make it ask.
        eff.push(Effect::Delete(PathBuf::from(r"D:\dev\<unresolved delete target>")));
    }
    eff
}

pub fn task_for(tool: &str, input: &Value, session: &str) -> Option<Task> {
    let s = |k: &str| input.get(k).and_then(Value::as_str).map(str::to_string);
    let effects = match tool {
        "Write" | "Edit" | "MultiEdit" => vec![Effect::Write(PathBuf::from(s("file_path")?))],
        "NotebookEdit" => vec![Effect::Write(PathBuf::from(s("notebook_path")?))],
        "Read" if std::env::var("DUCTEI_HOOK_STRICT_READ").ok().as_deref() == Some("1") => vec![Effect::Read(PathBuf::from(s("file_path")?))],
        "Bash" | "PowerShell" => shell_effects(&s("command")?),
        _ => return None,
    };
    if effects.is_empty() { return None; }
    let intent = match tool { "Bash" | "PowerShell" => s("command").unwrap_or_default(), _ => format!("{tool} {}", s("file_path").or_else(|| s("notebook_path")).unwrap_or_default()) };
    let crit = if effects.iter().any(|e| matches!(e, Effect::Delete(_) | Effect::Push | Effect::Commit)) { 3 } else { 1 };
    Some(Task { id: format!("hook-{session}-{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)), intent: intent.chars().take(400).collect(), kind: Kind::Code, criticality: crit, private: false, effects })
}

fn run() -> Result<(), String> {
    let mut raw = String::new();
    std::io::stdin().read_to_string(&mut raw).map_err(|e| e.to_string())?;
    let v: Value = serde_json::from_str(&raw).map_err(|e| format!("hook input is not JSON: {e}"))?;
    let tool = v.get("tool_name").and_then(Value::as_str).unwrap_or("");
    let session = v.get("session_id").and_then(Value::as_str).unwrap_or("na").chars().take(8).collect::<String>();
    let input = v.get("tool_input").cloned().unwrap_or(json!({}));
    let Some(task) = task_for(tool, &input, &session) else { return Ok(()) }; // pass through, no output = allow by default rules
    let state = PathBuf::from(std::env::var("DUCTEI_ROUTER_STATE").unwrap_or_else(|_| DEFAULT_STATE.into()));
    std::fs::create_dir_all(&state).map_err(|e| e.to_string())?;
    let d = decide(&state, &task, &approvals(&state))?;
    let tail = format!(" [tier {:?}, receipt {}]", d.decision.tier, &d.receipt[..12.min(d.receipt.len())]);
    match &d.decision.verdict {
        Verdict::Allow => out("allow", format!("CANON allow{tail}")),
        Verdict::NeedsApproval(need) => out("ask", format!("CANON needs approval: {}. Grant by adding the token(s) to {}\\approvals.txt{tail}", need.join(", "), state.display())),
        Verdict::Deny(r) => out("deny", format!("CANON deny: {r}{tail}")),
    }
    Ok(())
}

fn main() {
    if let Err(e) = run() { out("ask", format!("ductei-hook could not decide ({e}); asking instead of allowing")); }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn commit_push_and_c_write_detected() {
        let e = shell_effects(r#"git add . && git commit -m "x" && git push origin main"#);
        assert!(e.contains(&Effect::Commit) && e.contains(&Effect::Push));
        let e = shell_effects(r#"Set-Content C:\Users\xing\a.txt "hi""#);
        assert_eq!(e, vec![Effect::Write(PathBuf::from(r"C:\Users\xing\a.txt"))]);
        assert!(matches!(Canon::default().check(&Task { id: "t".into(), intent: "".into(), kind: Kind::Code, criticality: 1, private: false, effects: e }, &[]), Verdict::Deny(_)));
    }
    #[test] fn wsl_path_maps_to_drive_and_plain_read_passes() {
        let e = shell_effects("rm -rf /mnt/d/dev/tmp/x");
        assert_eq!(e, vec![Effect::Delete(PathBuf::from(r"D:\dev\tmp\x"))]);
        assert!(shell_effects("cat D:\\dev\\a.txt").is_empty());
        assert!(task_for("Read", &json!({"file_path": "C:\\x"}), "s").is_none());
        let t = task_for("Write", &json!({"file_path": "D:\\ATRIUM\\x.rs"}), "s").unwrap();
        assert_eq!(Canon::default().check(&t, &[]), Verdict::Allow);
    }
}
