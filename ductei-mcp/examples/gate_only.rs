//! Server-side half of the launch nonce. Drop this into an MCP server (e.g.
//! video-watch) and call `require_gate()` before serving stdio.
//!
//! The gate sets DUCTEI_GATE_NONCE and DUCTEI_GATE_DIR for the child and
//! writes gate-launch.json in that dir. We accept only if the env nonce's
//! SHA-256 equals the record's nonce_sha256 and (on Windows) the recorded
//! gate pid is alive. No crates beyond sha2 + serde_json.
//!
//! Opt-out for local testing: VIDEO_WATCH_ALLOW_UNGATED=1.
use sha2::{Digest, Sha256};

#[derive(serde::Deserialize)]
struct LaunchRecord { gate_pid: u32, nonce_sha256: String, server: String }

pub fn require_gate(expected_server: &str) -> Result<(), String> {
    if std::env::var("VIDEO_WATCH_ALLOW_UNGATED").as_deref() == Ok("1") { return Ok(()); }
    let nonce = std::env::var("DUCTEI_GATE_NONCE").map_err(|_| "not launched by ductei-mcp-gate (no DUCTEI_GATE_NONCE); set VIDEO_WATCH_ALLOW_UNGATED=1 to run bare")?;
    let dir = std::env::var("DUCTEI_GATE_DIR").map_err(|_| "DUCTEI_GATE_DIR missing")?;
    let text = std::fs::read_to_string(std::path::Path::new(&dir).join("gate-launch.json")).map_err(|e| format!("gate-launch.json: {e}"))?;
    let rec: LaunchRecord = serde_json::from_str(&text).map_err(|e| format!("gate-launch.json: {e}"))?;
    let got = Sha256::digest(nonce.as_bytes()).iter().map(|b| format!("{b:02x}")).collect::<String>();
    if got != rec.nonce_sha256 { return Err("launch nonce does not match gate-launch.json".into()); }
    if rec.server != expected_server { return Err(format!("gate-launch.json is for server {:?}, not {expected_server:?}", rec.server)); }
    if !pid_alive(rec.gate_pid) { return Err(format!("gate pid {} is not running", rec.gate_pid)); }
    Ok(())
}

#[cfg(windows)]
fn pid_alive(pid: u32) -> bool {
    // OpenProcess + GetExitCodeProcess, same pattern video-watch already uses for its sentinel.
    use windows_sys::Win32::Foundation::{CloseHandle, STILL_ACTIVE};
    use windows_sys::Win32::System::Threading::{GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() { return false; }
        let mut code = 0u32;
        let ok = GetExitCodeProcess(h, &mut code) != 0;
        CloseHandle(h);
        ok && code == STILL_ACTIVE as u32
    }
}

#[cfg(not(windows))]
fn pid_alive(pid: u32) -> bool { std::path::Path::new(&format!("/proc/{pid}")).exists() }

fn main() {
    match require_gate("video-watch") {
        Ok(()) => eprintln!("gate_only: launched by gate, ok"),
        Err(e) => { eprintln!("gate_only: refusing to serve: {e}"); std::process::exit(3); }
    }
}
