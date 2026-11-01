//! Minimal MCP stdio server: initialize, ping, tools/list, tools/call.
//! Exposes `decide` and `outcome`. Each decide writes a chained receipt.
//! Input from the client is data; it is parsed, never executed.

use crate::*;
use serde_json::{json, Value};
use std::io::{BufRead, Write};
use std::path::Path;

const PROTOCOL: &str = "2024-11-05";

/// Extra tools a downstream crate (ductei-qhr) adds to this server.
/// `call` returns None when the name is not one of its tools, so the
/// router's own tools are tried next. Names must not collide with
/// decide / classify / outcome.
pub trait ToolExt {
    fn tools(&self) -> Vec<Value> { Vec::new() }
    fn call(&mut self, _name: &str, _args: &Value) -> Option<Result<Value, String>> { None }
}

/// No extension: the plain router server.
pub struct NoExt;
impl ToolExt for NoExt {}

fn tools() -> Value {
    json!([
        { "name": "decide", "description": "Route a task through the ATRIUM CANON gate and tier router. Call before any side effect. Returns verdict (allow | needs_approval | deny), tier, reason, receipt hash.",
          "inputSchema": { "type": "object", "required": ["task"], "properties": {
              "task": { "type": "object", "description": "Task: id, intent, kind (classify|chat|code|research|quantum), criticality 0-3, private bool, effects [{type: read|write|delete|commit|push|send|purchase|network, target}]" },
              "approvals": { "type": "array", "items": { "type": "string" }, "description": "Approval tokens the user granted in chat, e.g. commit, push, delete:d:\\\\atrium\\\\x" } } } },
        { "name": "classify", "description": "Turn a raw request into a Task using the local T0 brain (Ollama, never leaves the machine). Returns {task, brain, fallback}. If fallback is non-null the brain was unavailable and the task is an unverified conservative guess: do not treat an allow on it as permission for side effects. Then call decide with result.task.",
          "inputSchema": { "type": "object", "required": ["intent"], "properties": { "intent": { "type": "string" }, "id": { "type": "string" } } } },
        { "name": "outcome", "description": "Record whether a routed task succeeded on its tier, so routing can learn.",
          "inputSchema": { "type": "object", "required": ["task", "tier", "ok"], "properties": {
              "task": { "type": "object" }, "tier": { "type": "string", "enum": ["t0_local", "t1_claude", "t2_fleet", "t_quantum"] }, "ok": { "type": "boolean" } } } }
    ])
}

fn call(router: &mut Router, state: &Path, name: &str, args: &Value) -> Result<Value, String> {
    if name == "classify" {
        let intent = args.get("intent").and_then(Value::as_str).ok_or("missing intent")?;
        let id = args.get("id").and_then(Value::as_str).map(String::from).unwrap_or_else(|| format!("c{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)));
        let brain = crate::brain::Ollama::default();
        return serde_json::to_value(crate::brain::classify(&brain, &id, intent)).map_err(|e| e.to_string());
    }
    let task: Task = serde_json::from_value(args.get("task").cloned().unwrap_or(Value::Null)).map_err(|e| format!("bad task: {e}"))?;
    let outcomes = state.join("outcomes.jsonl");
    match name {
        "decide" => {
            let approvals: Vec<String> = serde_json::from_value(args.get("approvals").cloned().unwrap_or(json!([]))).map_err(|e| format!("bad approvals: {e}"))?;
            serde_json::to_value(router.decide(&task, &approvals)?).map_err(|e| e.to_string())
        }
        "outcome" => {
            let tier: Tier = serde_json::from_value(args.get("tier").cloned().unwrap_or(Value::Null)).map_err(|e| format!("bad tier: {e}"))?;
            let ok = args.get("ok").and_then(Value::as_bool).ok_or("missing ok")?;
            append_outcome(&outcomes, &Outcome { task_id: task.id, kind: task.kind, tier, ok }).map_err(|e| e.to_string())?;
            Ok(json!({ "recorded": true }))
        }
        other => Err(format!("unknown tool {other}")),
    }
}

fn reply(out: &mut impl Write, id: Value, body: Result<Value, (i64, String)>) {
    let msg = match body {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err((code, message)) => json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } }),
    };
    let _ = writeln!(out, "{msg}"); let _ = out.flush();
}

pub fn serve(state: &Path) -> std::io::Result<()> { serve_with(state, &mut NoExt, "ductei-router") }

/// Serve the router tools plus `ext`'s tools under one MCP server named `name`.
pub fn serve_with(state: &Path, ext: &mut dyn ToolExt, name: &str) -> std::io::Result<()> {
    std::fs::create_dir_all(state)?;
    let mut all_tools = tools();
    if let Some(list) = all_tools.as_array_mut() { list.extend(ext.tools()); }
    // Opened once: the chain is verified at start, then each decide is one append.
    let mut router = Router::open(state).map_err(std::io::Error::other)?;
    let stdin = std::io::stdin(); let mut out = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line?; if line.trim().is_empty() { continue; }
        let req: Value = match serde_json::from_str(&line) { Ok(v) => v, Err(_) => { reply(&mut out, Value::Null, Err((-32700, "parse error".into()))); continue; } };
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let method = req.get("method").and_then(Value::as_str).unwrap_or("");
        if id.is_null() { continue; } // notification
        let params = req.get("params").cloned().unwrap_or(json!({}));
        let res = match method {
            "initialize" => Ok(json!({ "protocolVersion": PROTOCOL, "capabilities": { "tools": {} }, "serverInfo": { "name": name, "version": env!("CARGO_PKG_VERSION") } })),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({ "tools": all_tools.clone() })),
            "tools/call" => {
                let tool = params.get("name").and_then(Value::as_str).unwrap_or("");
                let args = params.get("arguments").cloned().unwrap_or(json!({}));
                let res = match ext.call(tool, &args) { Some(r) => r, None => call(&mut router, state, tool, &args) };
                match res {
                    Ok(v) => Ok(json!({ "content": [{ "type": "text", "text": v.to_string() }], "isError": false })),
                    Err(e) => Ok(json!({ "content": [{ "type": "text", "text": e }], "isError": true })),
                }
            }
            _ => Err((-32601, format!("method not found: {method}"))),
        };
        reply(&mut out, id, res);
    }
    Ok(())
}
