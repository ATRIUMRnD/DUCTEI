//! ductei-qallow-relay: the second real consumer of DUCTEI, mirroring
//! ductei-limen-relay's pattern. Tails a LIMEN channel's accepted.jsonl
//! (produced by ductei-limen-relay), re-frames each envelope as a QSW v1
//! byte stream via ductei_qallow::encode_envelope, and hands it to a
//! real `qallow ingest` process, which calls Qallow's actual
//! ql_persist_merge_blob() (see Qallow/qallow_cli/src/ingest.rs).
//!
//! Usage:
//!   ductei-qallow-relay <limen_ductei_dir> <out_dir>
//!     [--poll-interval-ms N] [--once]
//!     [--qallow-cli PATH] [--store-dir PATH]
//!
//! <limen_ductei_dir> is the *source*: the `ductei/` directory a running
//! ductei-limen-relay writes accepted.jsonl into (sibling of its spool
//! dir, not inside it). <out_dir> is this relay's *own* working tree:
//!
//!   out_dir/
//!     pending/   QSW frame files not yet confirmed ingested
//!     sent/      frame files after a successful `qallow ingest` call
//!     failed/    frame files (+ a sibling .error.txt) that qallow
//!                rejected or that failed this relay's own channel gate
//!     ductei/    this relay's own accepted/rejected log, node id, and
//!                the cursor into <limen_ductei_dir>/accepted.jsonl
//!
//! Never touches LIMEN's spool or credentials -- the only input is
//! already-certified envelopes from LIMEN's own channel log.
use ductei_core::{scoped, Channel, LogStore, ScopePolicy, SessionBound};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

pub const QALLOW_FORWARD_SCOPE: &str = "qallow.ingest.forwarded";
/// Envelope budget of the bounded session that carries one delivery;
/// also the session_bound recorded in Qallow's LMDB record.
pub const SESSION_BOUND: u32 = 1;

fn to_hex(bytes: &[u8; 16]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_node_id(hex: &str) -> Option<[u8; 16]> {
    if hex.len() != 32 {
        return None;
    }
    let mut node = [0u8; 16];
    for i in 0..16 {
        node[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(node)
}

fn generate_node_id() -> [u8; 16] {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let mut bytes = [0u8; 16];
    for chunk in bytes.chunks_mut(8) {
        let h = RandomState::new().build_hasher().finish();
        chunk.copy_from_slice(&h.to_le_bytes());
    }
    bytes
}

fn load_or_create_node_id(ductei_dir: &Path) -> std::io::Result<[u8; 16]> {
    let path = ductei_dir.join("relay-node-id");
    if let Ok(existing) = fs::read_to_string(&path) {
        if let Some(id) = parse_node_id(existing.trim()) {
            return Ok(id);
        }
    }
    let id = generate_node_id();
    fs::write(&path, to_hex(&id))?;
    Ok(id)
}

/// Cursor into the *source* LIMEN accepted.jsonl -- persisted so a
/// restarted relay resumes instead of re-forwarding everything (this is
/// this relay's restart-replicability story; the LIMEN accepted.jsonl
/// itself is immutable history it only ever reads).
fn load_cursor(ductei_dir: &Path) -> usize {
    fs::read_to_string(ductei_dir.join("limen-cursor"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

fn save_cursor(ductei_dir: &Path, cursor: usize) -> std::io::Result<()> {
    fs::write(ductei_dir.join("limen-cursor"), cursor.to_string())
}

fn ensure_dirs(out_dir: &Path) -> std::io::Result<(PathBuf, PathBuf, PathBuf, PathBuf)> {
    let pending = out_dir.join("pending");
    let sent = out_dir.join("sent");
    let failed = out_dir.join("failed");
    let ductei_dir = out_dir.join("ductei");
    fs::create_dir_all(&pending)?;
    fs::create_dir_all(&sent)?;
    fs::create_dir_all(&failed)?;
    fs::create_dir_all(&ductei_dir)?;
    Ok((pending, sent, failed, ductei_dir))
}

fn sanitize_key(key: &str) -> String {
    key.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .take(80)
        .collect()
}

fn write_failed(failed_dir: &Path, file_name: &str, frame: &[u8], error: &str) {
    let dest = failed_dir.join(file_name);
    if let Err(e) = fs::write(&dest, frame) {
        eprintln!("relay: failed to archive frame for {file_name}: {e}");
    }
    let err_path = failed_dir.join(format!("{file_name}.error.txt"));
    if let Err(e) = fs::write(&err_path, error) {
        eprintln!("relay: failed to write failure record {}: {e}", err_path.display());
    }
}

/// Forward one already-certified LIMEN envelope: gate it through this
/// relay's own bounded channel, frame it as QSW v1 bytes, then hand the
/// frame to a real `qallow ingest` process (persistence before ack: a
/// file only reaches sent/ after qallow reports the merge succeeded).
#[allow(clippy::too_many_arguments)]
fn process_one(
    env: &ductei_core::Envelope,
    node: [u8; 16],
    channel: &mut Channel,
    pending_dir: &Path,
    sent_dir: &Path,
    failed_dir: &Path,
    qallow_cli: &Path,
    store_dir: &Path,
) {
    let file_name = format!("{}-{}.qsw", env.lamport, sanitize_key(&env.key));
    // Qallow's persist gate (Qallow@2b0009e, ATRIUM Task 4) refuses any
    // envelope that does not carry a bounded session and a non-open
    // scope inside the blob. The bounded session used below
    // (max_envelopes = 1) is exactly what gets written on disk: one
    // bounded session per delivery, unbounded unrepresentable (I5).
    let session_id = ductei_qallow::persist::session_id_for(&node, &env.key, env.lamport);
    let persist_env = ductei_qallow::persist::for_persist(env, session_id, SESSION_BOUND as u64);
    let frame = ductei_qallow::encode_envelope(&persist_env);

    let forward_env = scoped(&env.key, &[QALLOW_FORWARD_SCOPE], node, env.lamport, &frame);
    let mut session = channel.session(
        SessionBound::new(Some(SESSION_BOUND), None).expect("max_envelopes=Some(1) is a valid bound"),
    );
    if let Err(err) = session.send(forward_env, 1) {
        session.close();
        write_failed(failed_dir, &file_name, &frame, &format!("channel gate: {err:?}"));
        return;
    }
    session.close();

    let pending_path = pending_dir.join(&file_name);
    if let Err(e) = fs::write(&pending_path, &frame) {
        write_failed(failed_dir, &file_name, &frame, &format!("write pending: {e}"));
        return;
    }

    let output = Command::new(qallow_cli)
        .arg("ingest")
        .arg(store_dir)
        .arg(&pending_path)
        .output();

    match output {
        Ok(out) if out.status.success() => {
            let dest = sent_dir.join(&file_name);
            if let Err(e) = fs::rename(&pending_path, &dest) {
                eprintln!("relay: ingested but failed to archive {}: {e}", pending_path.display());
            }
        }
        Ok(out) => {
            let reason = format!(
                "qallow ingest exited {:?}\nstdout: {}\nstderr: {}",
                out.status.code(),
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            let _ = fs::remove_file(&pending_path);
            write_failed(failed_dir, &file_name, &frame, &reason);
        }
        Err(e) => {
            let _ = fs::remove_file(&pending_path);
            write_failed(
                failed_dir,
                &file_name,
                &frame,
                &format!("failed to spawn qallow ingest ({}): {e}", qallow_cli.display()),
            );
        }
    }
}

fn default_qallow_cli() -> PathBuf {
    let exe = if cfg!(windows) { "qallow.exe" } else { "qallow" };
    PathBuf::from("..").join("Qallow").join("target").join("debug").join(exe)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!(
            "usage: {} <limen_ductei_dir> <out_dir> [--poll-interval-ms N] [--once] [--qallow-cli PATH] [--store-dir PATH]",
            args[0]
        );
        std::process::exit(2);
    }
    let limen_dir = PathBuf::from(&args[1]);
    let out_dir = PathBuf::from(&args[2]);
    let mut poll_interval_ms: u64 = 1000;
    let mut once = false;
    let mut qallow_cli = default_qallow_cli();
    let mut store_dir_override: Option<PathBuf> = None;
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--poll-interval-ms" if i + 1 < args.len() => {
                poll_interval_ms = args[i + 1].parse().unwrap_or(1000);
                i += 2;
            }
            "--once" => {
                once = true;
                i += 1;
            }
            "--qallow-cli" if i + 1 < args.len() => {
                qallow_cli = PathBuf::from(&args[i + 1]);
                i += 2;
            }
            "--store-dir" if i + 1 < args.len() => {
                store_dir_override = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            _ => i += 1,
        }
    }

    let (pending_dir, sent_dir, failed_dir, ductei_dir) =
        ensure_dirs(&out_dir).expect("failed to create relay directories");
    let store_dir = store_dir_override.unwrap_or_else(|| out_dir.join("qallow-store"));
    fs::create_dir_all(&store_dir).expect("failed to create qallow store dir");

    let node = load_or_create_node_id(&ductei_dir).expect("failed to load/create relay node id");
    let policy = ScopePolicy::new().allow(QALLOW_FORWARD_SCOPE);
    let mut channel = Channel::open(
        policy,
        ductei_dir.join("accepted.jsonl"),
        ductei_dir.join("rejected.jsonl"),
    )
    .expect("failed to open channel log");

    println!(
        "ductei-qallow-relay: source={} out={} qallow-cli={} store={} (node={})",
        limen_dir.display(),
        out_dir.display(),
        qallow_cli.display(),
        store_dir.display(),
        to_hex(&node)
    );

    loop {
        let mut cursor = load_cursor(&ductei_dir);
        let source_log = LogStore::open(limen_dir.join("accepted.jsonl"))
            .expect("failed to open source accepted.jsonl");
        let (envelopes, next_cursor) = source_log
            .replay(cursor)
            .expect("failed to replay source accepted.jsonl");

        for env in &envelopes {
            process_one(
                env, node, &mut channel, &pending_dir, &sent_dir, &failed_dir,
                &qallow_cli, &store_dir,
            );
            cursor += 1;
            save_cursor(&ductei_dir, cursor).expect("failed to persist cursor");
        }
        save_cursor(&ductei_dir, next_cursor).expect("failed to persist cursor");

        if once {
            return;
        }

        std::thread::sleep(Duration::from_millis(poll_interval_ms));
    }
}
