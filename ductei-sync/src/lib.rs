//! ductei-sync: the peer sync agent (Qallow roadmap "Task 3, sync agent";
//! owned by DUCTEI per ATRIUM AGENTS.md section 1, since it is transport).
//!
//! It adds no new wire format and no new merge rule. It reuses:
//! - `ductei_core::transport::{TcpClient, serve_connection}` (length-prefixed
//!   JSON frames, persistence-before-ack, tri-state ack byte),
//! - `ductei_core::Channel` (deny-by-default scopes, causal-delta gate,
//!   fsynced append-only log),
//! - the node-id file convention from `ductei-qallow-relay`.
//!
//! Model: full mesh, origin-only push. Every node pushes the envelopes it
//! produced itself (`env.node_id == own node id`) to every peer. A node never
//! re-forwards what it received, so a 2-node or N-node full mesh converges
//! without loops, and the causal gate on the receiving side makes re-pushes
//! after a restart idempotent (ack 2 = already present).
//!
//! State directory contract (shared with producers such as brain):
//!
//! ```text
//! <state>/
//!   node-id                   32 lowercase hex chars, this node's origin id
//!   local/accepted.jsonl      envelopes produced on this node (writer: the producer)
//!   local/rejected.jsonl      the producer's causal-gate rejects
//!   inbound/accepted.jsonl    envelopes received from peers (writer: `ductei-sync serve`)
//!   inbound/rejected.jsonl    stale deltas a peer sent (audit only)
//!   cursors/push-<peer>       line cursor into local/accepted.jsonl, per peer
//!   failed/push-<peer>.jsonl  envelopes a peer explicitly refused (witness, never retried)
//!   outbox.jsonl              outbound intent/receipt log (ductei_core::outbox)
//! ```
//!
//! Each JSONL file has exactly one writer process, so no two processes ever
//! append to the same log.
//!
//! Peer identity and app-level encryption (formerly "ATRIUM Task 6, not in
//! scope here"): with the `qfltl` feature on, see [`qfltl_transport`]. It
//! wraps the TCP connection in QFLTL's post-quantum session crypto
//! (ML-KEM-768 + HKDF-SHA256 + AES-256-GCM) and refuses to complete a
//! handshake with a peer whose public key isn't pinned, on top of (not
//! instead of) the source IP allow-list below. With `qfltl` off, the only
//! peer check remains the source IP allow-list, meaningful on a
//! Tailscale/WireGuard network where 100.x addresses are authenticated, and
//! nothing more than that anywhere else.
//!
//! Everything here needs the `net` feature: `cargo build -p ductei-sync --features net`.
#![cfg(feature = "net")]

#[cfg(feature = "qfltl")]
pub mod qfltl_transport;

use ductei_core::transport::{serve_connection, TcpClient, Transport};
use ductei_core::{Channel, ChannelError, Envelope, LogStore, ScopePolicy};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const NODE_ID_FILE: &str = "node-id";
pub const LOCAL_DIR: &str = "local";
pub const INBOUND_DIR: &str = "inbound";
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

pub fn to_hex(bytes: &[u8; 16]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn parse_node_id(hex: &str) -> Option<[u8; 16]> {
    let hex = hex.trim();
    if hex.len() != 32 {
        return None;
    }
    let mut node = [0u8; 16];
    for (i, b) in node.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(node)
}

fn generate_node_id() -> [u8; 16] {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let mut bytes = [0u8; 16];
    for chunk in bytes.chunks_mut(8) {
        let mut h = RandomState::new().build_hasher();
        h.write_u128(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        );
        h.write_u32(std::process::id());
        chunk.copy_from_slice(&h.finish().to_le_bytes());
    }
    bytes
}

/// A node's sync state directory (see the module docs for the layout).
#[derive(Debug, Clone)]
pub struct StateDir {
    root: PathBuf,
}

impl StateDir {
    /// Creates the directory tree if needed.
    pub fn open(root: impl AsRef<Path>) -> std::io::Result<Self> {
        let root = root.as_ref().to_path_buf();
        for d in [LOCAL_DIR, INBOUND_DIR, "cursors", "failed"] {
            fs::create_dir_all(root.join(d))?;
        }
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The node id is created once and never reset (ATRIUM AGENTS.md
    /// section 3: node identity is daemon-owned).
    pub fn node_id(&self) -> std::io::Result<[u8; 16]> {
        let path = self.root.join(NODE_ID_FILE);
        if let Ok(s) = fs::read_to_string(&path) {
            return parse_node_id(&s).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("{} is not 32 hex chars; refusing to replace a node id", path.display()),
                )
            });
        }
        let id = generate_node_id();
        fs::write(&path, to_hex(&id))?;
        Ok(id)
    }

    pub fn local_log(&self) -> PathBuf {
        self.root.join(LOCAL_DIR).join("accepted.jsonl")
    }
    pub fn local_rejects(&self) -> PathBuf {
        self.root.join(LOCAL_DIR).join("rejected.jsonl")
    }
    pub fn inbound_log(&self) -> PathBuf {
        self.root.join(INBOUND_DIR).join("accepted.jsonl")
    }
    pub fn inbound_rejects(&self) -> PathBuf {
        self.root.join(INBOUND_DIR).join("rejected.jsonl")
    }
    pub fn outbox(&self) -> PathBuf {
        self.root.join("outbox.jsonl")
    }

    /// The producer's channel. Producers (brain, ...) append here.
    pub fn local_channel(&self, policy: ScopePolicy) -> std::io::Result<Channel> {
        Channel::open(policy, self.local_log(), self.local_rejects())
    }

    /// The receiving channel. Only `serve` appends here.
    pub fn inbound_channel(&self, policy: ScopePolicy) -> std::io::Result<Channel> {
        Channel::open(policy, self.inbound_log(), self.inbound_rejects())
    }

    fn cursor_path(&self, peer: &str) -> PathBuf {
        self.root.join("cursors").join(format!("push-{}", sanitize(peer)))
    }
    pub fn load_cursor(&self, peer: &str) -> usize {
        fs::read_to_string(self.cursor_path(peer))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0)
    }
    fn save_cursor(&self, peer: &str, cursor: usize) -> std::io::Result<()> {
        // write-then-rename so a crash never leaves a torn cursor
        let path = self.cursor_path(peer);
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, cursor.to_string())?;
        fs::rename(tmp, path)
    }
    fn witness_refusal(&self, peer: &str, env: &Envelope) -> std::io::Result<()> {
        let path = self.root.join("failed").join(format!("push-{}.jsonl", sanitize(peer)));
        let mut f = OpenOptions::new().create(true).append(true).open(path)?;
        let line = serde_json::json!({
            "refused_by_peer": peer,
            "reason": "peer acked 0 (scope denied or failed to apply); not retried",
            "envelope": env,
        });
        writeln!(f, "{line}")?;
        f.sync_data()
    }
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '_' })
        .collect()
}

/// Outcome of one push pass to one peer.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct PushReport {
    /// Envelopes the peer acked as persisted (applied or already present).
    pub delivered: usize,
    /// Envelopes the peer refused (ack 0); witnessed under failed/.
    pub refused: usize,
    /// Envelopes skipped because another node originated them.
    pub skipped_foreign: usize,
    /// True when the pass stopped early because the peer was unreachable or
    /// the connection broke; the cursor stays on the first undelivered line.
    pub interrupted: bool,
}

/// True if there is anything this node still owes `peer`, without opening a
/// connection to check. Both the plain-TCP and `qfltl`-encrypted push call
/// this first, so an idle pass (nothing new since last time) never pays for
/// a TCP connect -- or, under `qfltl`, a full KEM handshake -- for nothing.
pub fn has_pending(state: &StateDir, peer: &str) -> std::io::Result<bool> {
    let log = LogStore::open(state.local_log())?;
    let start = state.load_cursor(peer);
    let (envs, _) = log.replay(start)?;
    Ok(!envs.is_empty())
}

/// One push pass: send every not-yet-delivered envelope this node originated
/// to `peer`, in log order. The cursor only moves past an envelope after the
/// peer acked it (or explicitly refused it, which is witnessed). On any
/// transport error the pass stops and the same envelope is retried next pass.
pub fn push_once(state: &StateDir, peer: &str) -> std::io::Result<PushReport> {
    if !has_pending(state, peer)? {
        return Ok(PushReport::default());
    }
    let addr = match peer.to_socket_addrs().ok().and_then(|mut a| a.next()) {
        Some(a) => a,
        None => return Ok(PushReport { interrupted: true, ..Default::default() }),
    };
    let client = match TcpClient::connect_timeout(&addr, CONNECT_TIMEOUT) {
        Ok(c) => c.with_outbox_path(state.outbox()),
        Err(_) => return Ok(PushReport { interrupted: true, ..Default::default() }),
    };
    push_with_client(state, peer, client)
}

/// The envelope-sending loop shared by every transport: resolve what this
/// node still owes `peer` (recomputed here, not reused from [`has_pending`],
/// so a straggler appended between the two calls is still sent this pass),
/// send each in order over an already-connected `client`, and only advance
/// the cursor once the peer has acked it. [`push_once`] is the plain-TCP
/// caller; the `qfltl` feature's encrypted push is the other.
pub fn push_with_client(
    state: &StateDir,
    peer: &str,
    mut client: impl Transport,
) -> std::io::Result<PushReport> {
    let me = state.node_id()?;
    let mut report = PushReport::default();
    let log = LogStore::open(state.local_log())?;
    let start = state.load_cursor(peer);
    let (envs, _) = log.replay(start)?;

    let mut cursor = start;
    for env in envs {
        if env.node_id != me {
            report.skipped_foreign += 1;
        } else {
            match client.send_envelope(&env) {
                Ok(true) => report.delivered += 1,
                Ok(false) => {
                    state.witness_refusal(peer, &env)?;
                    report.refused += 1;
                }
                Err(ChannelError::Io(_)) | Err(_) => {
                    report.interrupted = true;
                    break;
                }
            }
        }
        cursor += 1;
        state.save_cursor(peer, cursor)?;
    }
    Ok(report)
}

/// Accept peers one connection at a time (one writer for inbound/), each
/// frame going scope policy -> causal gate -> fsync -> ack. Connections from
/// an IP outside `allow_ips` are closed before a single byte is read. Returns
/// after `max_conns` connections when set (tests, `--once`).
pub fn serve(
    state: &StateDir,
    listener: TcpListener,
    policy: ScopePolicy,
    allow_ips: &[IpAddr],
    max_conns: Option<usize>,
    on_conn: impl FnMut(SocketAddr, std::io::Result<usize>),
) -> std::io::Result<()> {
    serve_with(state, listener, policy, allow_ips, max_conns, on_conn, serve_connection)
}

/// The same accept loop as [`serve`], with the per-connection step pulled
/// out as `handle` so the `qfltl` feature can wrap each accepted
/// `TcpStream` in a handshake and an `EncryptedStream` before any frame is
/// read, instead of calling `serve_connection` on the raw socket. The
/// allow-list check still runs first either way, so an unpinned IP is
/// rejected before it can even attempt a handshake.
pub fn serve_with(
    state: &StateDir,
    listener: TcpListener,
    policy: ScopePolicy,
    allow_ips: &[IpAddr],
    max_conns: Option<usize>,
    mut on_conn: impl FnMut(SocketAddr, std::io::Result<usize>),
    mut handle: impl FnMut(TcpStream, &mut Channel) -> std::io::Result<usize>,
) -> std::io::Result<()> {
    let mut ch = state.inbound_channel(policy)?;
    let mut served = 0usize;
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        let from = match stream.peer_addr() {
            Ok(a) => a,
            Err(_) => continue,
        };
        if !allow_ips.is_empty() && !allow_ips.contains(&from.ip()) {
            on_conn(from, Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "ip not in --allow-ip")));
        } else {
            let res = handle(stream, &mut ch);
            on_conn(from, res);
        }
        served += 1;
        if max_conns.is_some_and(|m| served >= m) {
            break;
        }
    }
    Ok(())
}

/// Binding a non-loopback address without an IP allow-list is refused:
/// deny-by-default applies to peers as well as to scopes.
pub fn check_bind(listen: &SocketAddr, allow_ips: &[IpAddr]) -> Result<(), String> {
    if allow_ips.is_empty() && !listen.ip().is_loopback() {
        return Err(format!(
            "refusing to listen on {listen} with no --allow-ip; name each peer's (Tailscale) IP"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ductei_core::scoped;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("ductei-sync-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn node_id_is_stable_and_never_replaced() {
        let s = StateDir::open(tmp("nid")).unwrap();
        let a = s.node_id().unwrap();
        assert_eq!(a, s.node_id().unwrap());
        fs::write(s.root().join(NODE_ID_FILE), "garbage").unwrap();
        assert!(s.node_id().is_err(), "a corrupt node id is an error, not a silent reset");
    }

    #[test]
    fn non_loopback_bind_needs_allow_list() {
        let any: SocketAddr = "0.0.0.0:7420".parse().unwrap();
        let lo: SocketAddr = "127.0.0.1:7420".parse().unwrap();
        assert!(check_bind(&any, &[]).is_err());
        assert!(check_bind(&lo, &[]).is_ok());
        assert!(check_bind(&any, &["100.64.0.2".parse().unwrap()]).is_ok());
    }

    /// Two nodes on loopback: A pushes its own envelopes, B persists them,
    /// a re-push after a cursor loss is idempotent, a refused scope is
    /// witnessed and not retried, and an unreachable peer leaves the cursor.
    #[test]
    fn two_node_push_serve() {
        let a = StateDir::open(tmp("a")).unwrap();
        let b = StateDir::open(tmp("b")).unwrap();
        let na = a.node_id().unwrap();
        let foreign = [9u8; 16];

        let mut local = a
            .local_channel(ScopePolicy::new().allow("brain.correction").allow("other.scope"))
            .unwrap();
        local.send(scoped("k1", &["brain.correction"], na, 1, b"one")).unwrap();
        local.send(scoped("k2", &["brain.correction"], na, 2, b"two")).unwrap();
        local.send(scoped("k3", &["other.scope"], na, 3, b"denied by B")).unwrap();
        local.send(scoped("k4", &["brain.correction"], foreign, 4, b"not ours")).unwrap();

        // Unreachable peer: nothing moves.
        let dead = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().to_string()
        };
        let r = push_once(&a, &dead).unwrap();
        assert!(r.interrupted);
        assert_eq!(a.load_cursor(&dead), 0);

        let serve_pass = |conns: usize| {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap().to_string();
            let b2 = b.clone();
            let h = std::thread::spawn(move || {
                serve(&b2, listener, ScopePolicy::new().allow("brain.correction"), &[], Some(conns), |_, _| {})
                    .unwrap();
            });
            (addr, h)
        };

        let (addr, h) = serve_pass(1);
        let r = push_once(&a, &addr).unwrap();
        h.join().unwrap();
        assert_eq!(r, PushReport { delivered: 2, refused: 1, skipped_foreign: 1, interrupted: false });
        let (got, _) = LogStore::open(b.inbound_log()).unwrap().replay(0).unwrap();
        assert_eq!(got.iter().map(|e| e.key.as_str()).collect::<Vec<_>>(), vec!["k1", "k2"]);
        let refused = fs::read_to_string(a.root().join("failed").join(format!("push-{}.jsonl", sanitize(&addr)))).unwrap();
        assert!(refused.contains("\"k3\""));

        // B restarts on a new port, so A has no cursor for it and re-pushes
        // everything: a receipt (ack 2), never a duplicate write.
        let (addr2, h) = serve_pass(1);
        let r = push_once(&a, &addr2).unwrap();
        h.join().unwrap();
        assert_eq!(r.delivered, 2);
        let (got, _) = LogStore::open(b.inbound_log()).unwrap().replay(0).unwrap();
        assert_eq!(got.len(), 2, "re-push must not duplicate");
    }
}
