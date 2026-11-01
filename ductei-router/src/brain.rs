//! T0 local brain: Ollama on 127.0.0.1 only. Used for classification and
//! private work. Model output is data; it is parsed into a Task and then
//! goes through the CANON gate like anything else.

use crate::{Effect, Kind, Task};
use serde::Deserialize;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub trait Brain {
    fn name(&self) -> String;
    fn complete(&self, system: &str, prompt: &str) -> Result<String, String>;
}

pub struct Ollama { pub host: String, pub port: u16, pub model: String, pub timeout: Duration }

impl Default for Ollama {
    fn default() -> Self {
        Self { host: "127.0.0.1".into(), port: 11434, model: std::env::var("DUCTEI_T0_MODEL").unwrap_or_else(|_| "llama3.2:latest".into()), timeout: Duration::from_secs(60) }
    }
}

#[derive(Deserialize)]
struct GenResp { response: String }

impl Ollama {
    fn post(&self, path: &str, body: &str) -> Result<String, String> {
        if self.host != "127.0.0.1" && self.host != "localhost" { return Err("T0 brain must be local".into()); }
        let mut s = TcpStream::connect_timeout(&format!("{}:{}", self.host, self.port).parse().map_err(|e| format!("{e}"))?, Duration::from_secs(3)).map_err(|e| format!("ollama not reachable: {e}"))?;
        s.set_read_timeout(Some(self.timeout)).map_err(|e| e.to_string())?;
        let req = format!("POST {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", self.host, body.len());
        s.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
        let mut raw = String::new(); s.read_to_string(&mut raw).map_err(|e| e.to_string())?;
        let (head, body) = raw.split_once("\r\n\r\n").ok_or("bad http response")?;
        if !head.starts_with("HTTP/1.1 200") { return Err(format!("ollama: {}", head.lines().next().unwrap_or(""))); }
        // Connection: close, so chunked bodies may arrive; de-chunk if needed.
        if head.to_ascii_lowercase().contains("transfer-encoding: chunked") {
            let mut out = String::new(); let mut rest = body;
            loop {
                let (len, tail) = rest.split_once("\r\n").ok_or("bad chunk")?;
                let n = usize::from_str_radix(len.trim(), 16).map_err(|_| "bad chunk len")?;
                if n == 0 { break; }
                out.push_str(tail.get(..n).ok_or("short chunk")?); rest = tail.get(n + 2..).unwrap_or("");
            }
            Ok(out)
        } else { Ok(body.to_string()) }
    }
}

impl Brain for Ollama {
    fn name(&self) -> String { format!("ollama:{}", self.model) }
    fn complete(&self, system: &str, prompt: &str) -> Result<String, String> {
        let body = serde_json::json!({ "model": self.model, "system": system, "prompt": prompt, "stream": false, "format": "json", "options": { "temperature": 0 } }).to_string();
        let raw = self.post("/api/generate", &body)?;
        let r: GenResp = serde_json::from_str(&raw).map_err(|e| format!("bad ollama json: {e}"))?;
        Ok(r.response)
    }
}

const CLASSIFY_SYSTEM: &str = r#"You classify a user request for a task router. Output one JSON object and nothing else.
Fields:
  kind: one word, exactly one of: chat, code, research, quantum, classify
  criticality: integer 0 to 3 (0 trivial, 1 routine, 2 important, 3 irreversible or security-sensitive)
  private: true only if the request involves personal data, secrets, credentials, finances or health
  effects: list of side effects the request itself asks for. Each is {"type": T, "target": S} where T is exactly one of read, write, delete, commit, push, send, purchase, network. Use a file path or host as target. Omit effects you are unsure about. Answering a question has no effects.
Examples:
  "what time is it in Tokyo" -> {"kind":"chat","criticality":0,"private":false,"effects":[]}
  "commit and push the router crate" -> {"kind":"code","criticality":3,"private":false,"effects":[{"type":"commit","target":""},{"type":"push","target":""}]}
  "summarize my bank statement in D:\\docs\\bank.pdf" -> {"kind":"chat","criticality":1,"private":true,"effects":[{"type":"read","target":"D:\\docs\\bank.pdf"}]}
  "run the max-cut circuit on ibm_fez" -> {"kind":"quantum","criticality":2,"private":false,"effects":[{"type":"network","target":"ibm_fez"}]}"#;
#[derive(Deserialize)]
struct Classified { kind: Kind, #[serde(default)] criticality: u8, #[serde(default)] private: bool, #[serde(default)] effects: Vec<serde_json::Value> }

/// Effects as the model wrote them; drop anything that is not a known effect.
fn lenient_effect(v: serde_json::Value) -> Option<Effect> {
    let t = v.get("type")?.as_str()?.to_ascii_lowercase();
    let target = v.get("target").and_then(|s| s.as_str()).unwrap_or("").trim().to_string();
    let p = || std::path::PathBuf::from(&target);
    Some(match t.as_str() {
        "read" if !target.is_empty() => Effect::Read(p()),
        "write" if !target.is_empty() => Effect::Write(p()),
        "delete" if !target.is_empty() => Effect::Delete(p()),
        "commit" => Effect::Commit, "push" => Effect::Push, "send" => Effect::Send, "purchase" => Effect::Purchase,
        "network" if !target.is_empty() => Effect::Network(target),
        _ => return None,
    })
}

/// Turn a raw intent into a Task via the local brain. Fallible and bounded:
/// bad model output falls back to a conservative T1 code task with no effects.
pub fn classify(brain: &dyn Brain, id: &str, intent: &str) -> Task {
    let fallback = Task { id: id.into(), intent: intent.into(), kind: Kind::Code, criticality: 2, private: false, effects: vec![] };
    let raw = match brain.complete(CLASSIFY_SYSTEM, intent) { Ok(r) => r, Err(e) => { eprintln!("t0: {e}; fallback"); return fallback } };
    match serde_json::from_str::<Classified>(&raw) {
        Ok(c) => Task { id: id.into(), intent: intent.into(), kind: c.kind, criticality: c.criticality.min(3), private: c.private, effects: c.effects.into_iter().filter_map(lenient_effect).collect() },
        Err(e) => { eprintln!("t0: unparsable {raw:?} ({e}); fallback"); fallback }
    }
}
