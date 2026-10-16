//! Build 1: network transport. TCP, length-prefixed JSON frames carrying
//! Envelopes unchanged (QSW wire translation stays in ductei-qallow).
//! Every inbound envelope passes: scope policy → causal gate → JSONL
//! persistence, and only THEN is acked (persistence-first). The transport
//! trait is vendor-neutral so gRPC/QUIC can slot in later.
//! Frame: u32 LE length | JSON bytes. Ack: 1 byte with tri-state:
//!   1 = applied (new write persisted), 2 = stale/already-present (receipt),
//!   0 = rejected (scope-denied/malformed/failed-to-apply).

use crate::{outbox::Outbox, Channel, ChannelError, Envelope};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::path::{PathBuf, Path};

pub trait Transport {
    fn send_envelope(&mut self, env: &Envelope) -> Result<bool, ChannelError>;
}

/// Default on-disk location for the outbound intent/receipt log.
/// Per-process file under the temp directory, stable across retries in the
/// same process lifetime.
pub fn default_outbox_path() -> PathBuf {
    // 1) Explicit override wins
    if let Ok(p) = std::env::var("DUCTEI_OUTBOX_PATH") {
        return PathBuf::from(p);
    }
    // 2) XDG state dir
    if let Ok(xdg) = std::env::var("XDG_STATE_HOME") {
        return PathBuf::from(xdg).join("ductei").join("outbox.jsonl");
    }
    // 3) HOME-based fallback
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".ductei").join("outbox.jsonl");
    }
    // 4) Last resort stable path
    std::env::temp_dir().join("ductei-outbox.jsonl")
}

fn write_frame(w: &mut impl Write, env: &Envelope) -> std::io::Result<()> {
    let body = serde_json::to_vec(env)?;
    w.write_all(&(body.len() as u32).to_le_bytes())?;
    w.write_all(&body)?;
    w.flush()
}

fn read_frame(r: &mut impl Read) -> std::io::Result<Option<Envelope>> {
    let mut len = [0u8; 4];
    if let Err(e) = r.read_exact(&mut len) {
        return if e.kind() == std::io::ErrorKind::UnexpectedEof { Ok(None) } else { Err(e) };
    }
    let n = u32::from_le_bytes(len) as usize;
    if n > 16 * 1024 * 1024 { return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "frame too big")); }
    let mut body = vec![0u8; n];
    r.read_exact(&mut body)?;
    Ok(Some(serde_json::from_slice(&body)?))
}

pub struct TcpClient {
    stream: TcpStream,
    outbox_path: PathBuf,
}
impl TcpClient {
    pub fn connect(addr: impl ToSocketAddrs) -> std::io::Result<Self> {
        Ok(Self { stream: TcpStream::connect(addr)?, outbox_path: default_outbox_path() })
    }
    /// Attach a durable outbound intent/receipt log. When set, the client
    /// records intents before any network write and receipts before returning.
    pub fn with_outbox_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.outbox_path = path.into();
        self
    }
}
impl Transport for TcpClient {
    /// Returns Ok(true) only after the remote has persisted the envelope.
    fn send_envelope(&mut self, env: &Envelope) -> Result<bool, ChannelError> {
        // Record outbound intent before any I/O.
        // Best-effort: if outbox write fails, surface as I/O error.
        let mut ob = Outbox::open(&self.outbox_path).map_err(|e| ChannelError::Io(e.to_string()))?;
        ob.record_intent(env).map_err(|e| ChannelError::Io(e.to_string()))?;
        write_frame(&mut self.stream, env).map_err(|e| ChannelError::Io(e.to_string()))?;
        let mut ack = [0u8; 1];
        if let Err(e) = self.stream.read_exact(&mut ack) {
            // Connect succeeded but read failed: receiver persistence unknown.
            // Mark as unknown-failed (distinct from 0/1/2).
            let mut ob = Outbox::open(&self.outbox_path).map_err(|e2| ChannelError::Io(e2.to_string()))?;
            let _ = ob.record_receipt(&env.key, env.lamport, &env.node_id, 0xFF);
            return Err(ChannelError::Io(e.to_string()));
        }
        let code = ack[0];
        // Persist the receipt outcome before returning to the caller.
        let mut ob = Outbox::open(&self.outbox_path).map_err(|e| ChannelError::Io(e.to_string()))?;
        ob.record_receipt(&env.key, env.lamport, &env.node_id, code)
            .map_err(|e| ChannelError::Io(e.to_string()))?;
        match code {
            1 | 2 => Ok(true),
            0 => Ok(false),
            _ => Err(ChannelError::Io(format!("unknown ack value {}", code))),
        }
    }
}

/// Serve one peer connection: every inbound frame goes through the channel
/// (scope check → gate → fsynced log) before the ack byte is written.
pub fn serve_connection(stream: TcpStream, ch: &mut Channel) -> std::io::Result<usize> {
    serve_stream(stream, ch)
}

/// True when an I/O error just means the peer went away (it crashed, was
/// killed, or closed without reading our ack). Linux usually reports that
/// as a clean EOF, but Windows reports a TCP reset as an error, so both
/// have to end the connection the same way.
fn peer_gone(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::{BrokenPipe, ConnectionAborted, ConnectionReset};
    matches!(e.kind(), ConnectionReset | ConnectionAborted | BrokenPipe)
}

/// `serve_connection` over any byte stream, so the reset/abort paths can be
/// tested deterministically instead of depending on OS socket timing.
///
/// A vanished peer ends the connection normally and returns the count of
/// envelopes accepted so far. That count is the truth about what was
/// persisted: an envelope is only counted after `Channel::send` returned
/// Ok (fsynced), and the ack is written after that, so losing the ack never
/// loses data. Every other I/O error is still returned to the caller.
pub(crate) fn serve_stream<S: Read + Write>(mut stream: S, ch: &mut Channel) -> std::io::Result<usize> {
    let mut accepted = 0usize;
    loop {
        let env = match read_frame(&mut stream) {
            Ok(Some(env)) => env,
            Ok(None) => break,
            Err(e) if peer_gone(&e) => break,
            Err(e) => return Err(e),
        };
        let result = ch.send(env);
        if result.is_ok() { accepted += 1; }
        let ack = ack_code(&result);
        if let Err(e) = stream.write_all(&[ack]).and_then(|_| stream.flush()) {
            if peer_gone(&e) { break; }
            return Err(e);
        }
    }
    Ok(accepted)
}

/// Map a channel verdict to the wire ack byte. `1` (applied) is produced
/// only for `Ok(())`, and `Channel::send` returns `Ok(())` only after
/// `LogStore::append` has fsynced, so an applied-ack never precedes
/// persistence. Model-checked in proofs.rs.
pub(crate) fn ack_code(result: &Result<(), ChannelError>) -> u8 {
    match result {
        Ok(()) => 1,
        Err(ChannelError::StaleDelta { .. }) => 2,
        Err(ChannelError::ScopeDenied(_)) => 0,
        Err(_) => 0, // I/O or other error: not applied
    }
}

pub fn listen_once(addr: impl ToSocketAddrs, ch: &mut Channel) -> std::io::Result<(std::net::SocketAddr, TcpListener)> {
    let l = TcpListener::bind(addr)?;
    let a = l.local_addr()?;
    let _ = ch; // channel is used by the caller when accepting
    Ok((a, l))
}

/// Where an envelope ended up: sent over the wire and acked by a remote
/// peer, or, because no peer was reachable, appended directly to the local
/// channel instead.
#[derive(Debug, PartialEq, Eq)]
pub enum DeliveryPath {
    Network,
    LocalFallback,
}

/// Local-first delivery (GAP 4): try the network path first; if the peer
/// is unreachable (connection refused, no route, DNS failure, timeout),
/// the envelope is not dropped -- it goes through the same
/// persistence-before-ack `Channel` used when there is no network at all.
/// A remote peer that is reachable but rejects the envelope (scope denial
/// or a stale causal delta) is a real, informative "no" and does NOT fall
/// back to local delivery -- only *unreachability* degrades.
pub fn send_local_first(
    addr: impl ToSocketAddrs,
    env: &Envelope,
    local: &mut Channel,
    outbox_path: impl AsRef<Path>,
) -> Result<DeliveryPath, ChannelError> {
    match TcpClient::connect(addr) {
        Ok(mut client) => {
            let p: PathBuf = outbox_path.as_ref().to_path_buf();
            match client.with_outbox_path(p).send_envelope(env) {
            Ok(accepted) => {
                if accepted {
                    Ok(DeliveryPath::Network)
                } else {
                    // Ack=0 is an explicit rejection (scope-denied/malformed). Do not fallback.
                    Err(ChannelError::ScopeDenied(env.key.clone()))
                }
            }
            Err(e) => {
                // Connect succeeded but a later I/O error occurred (write/read/ack).
                // Receiver persistence is unknown — do NOT LocalFallback here.
                Err(e)
            }
        }},
        Err(_) => {
            local.send(env.clone())?;
            Ok(DeliveryPath::LocalFallback)
        }
    }
}

#[cfg(test)]
mod stream_tests {
    use super::*;
    use crate::{scoped, ScopePolicy};
    use std::io::{Error, ErrorKind};

    /// Reads `input`, then fails with `read_end` (None = clean EOF).
    /// Every write fails with `write_err` when set, else is recorded.
    struct Script {
        input: std::io::Cursor<Vec<u8>>,
        read_end: Option<ErrorKind>,
        write_err: Option<ErrorKind>,
        written: Vec<u8>,
    }
    impl Read for Script {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.input.read(buf)?;
            match (n, self.read_end) {
                (0, Some(kind)) if !buf.is_empty() => Err(Error::from(kind)),
                _ => Ok(n),
            }
        }
    }
    impl Write for Script {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if let Some(kind) = self.write_err { return Err(Error::from(kind)); }
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
    }

    fn frame_bytes(key: &str, lamport: u64) -> Vec<u8> {
        let env = scoped(key, &["s"], [1; 16], lamport, b"x");
        let mut v = Vec::new();
        write_frame(&mut v, &env).unwrap();
        v
    }

    fn channel(tag: &str) -> Channel {
        let dir = std::env::temp_dir();
        let id = std::process::id();
        let log = dir.join(format!("{id}-stream-{tag}.jsonl"));
        let rej = dir.join(format!("{id}-stream-{tag}-rej.jsonl"));
        let _ = std::fs::remove_file(&log);
        Channel::open(ScopePolicy::new().allow("s"), log, rej).unwrap()
    }

    fn run(tag: &str, input: Vec<u8>, read_end: Option<ErrorKind>, write_err: Option<ErrorKind>)
        -> (std::io::Result<usize>, usize, Vec<u8>)
    {
        let mut ch = channel(tag);
        let s = Script { input: std::io::Cursor::new(input), read_end, write_err, written: Vec::new() };
        // serve_stream consumes the stream; recover `written` through a shared cell.
        let cell = std::cell::RefCell::new(s);
        struct Ref<'a>(&'a std::cell::RefCell<Script>);
        impl Read for Ref<'_> { fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> { self.0.borrow_mut().read(b) } }
        impl Write for Ref<'_> {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> { self.0.borrow_mut().write(b) }
            fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
        }
        let res = serve_stream(Ref(&cell), &mut ch);
        let persisted = ch.replay(0).unwrap().0.len();
        (res, persisted, cell.into_inner().written)
    }

    #[test]
    fn clean_eof_ends_connection() {
        let (res, persisted, acks) = run("eof", frame_bytes("a", 1), None, None);
        assert_eq!(res.unwrap(), 1);
        assert_eq!((persisted, acks), (1, vec![1]));
    }

    /// Windows reports a client that vanished as a reset on the next read.
    #[test]
    fn reset_after_frame_is_a_normal_end_and_keeps_the_count() {
        for kind in [ErrorKind::ConnectionReset, ErrorKind::ConnectionAborted, ErrorKind::BrokenPipe] {
            let (res, persisted, _) = run(&format!("rd-{kind:?}"), frame_bytes("a", 1), Some(kind), None);
            assert_eq!(res.unwrap(), 1, "{kind:?}");
            assert_eq!(persisted, 1, "{kind:?}");
        }
    }

    /// The ack write can fail because the client already left.
    #[test]
    fn failed_ack_write_to_a_gone_peer_keeps_the_count() {
        for kind in [ErrorKind::ConnectionReset, ErrorKind::ConnectionAborted, ErrorKind::BrokenPipe] {
            let (res, persisted, _) = run(&format!("wr-{kind:?}"), frame_bytes("a", 1), None, Some(kind));
            assert_eq!(res.unwrap(), 1, "{kind:?}");
            assert_eq!(persisted, 1, "{kind:?}");
        }
    }

    /// Only a vanished peer is swallowed; real errors still surface.
    #[test]
    fn other_io_errors_still_propagate() {
        let (res, persisted, _) = run("perm-rd", frame_bytes("a", 1), Some(ErrorKind::PermissionDenied), None);
        assert_eq!(res.unwrap_err().kind(), ErrorKind::PermissionDenied);
        assert_eq!(persisted, 1, "data persisted before the error is still durable");
        let (res, _, _) = run("perm-wr", frame_bytes("a", 1), None, Some(ErrorKind::PermissionDenied));
        assert_eq!(res.unwrap_err().kind(), ErrorKind::PermissionDenied);
    }

    #[test]
    fn nothing_is_acked_applied_before_it_is_persisted() {
        let mut input = frame_bytes("a", 1);
        input.extend(frame_bytes("a", 1)); // same triple again: stale
        let (res, persisted, acks) = run("order", input, None, None);
        assert_eq!(res.unwrap(), 1);
        assert_eq!(persisted, 1);
        assert_eq!(acks, vec![1, 2]);
    }
}
