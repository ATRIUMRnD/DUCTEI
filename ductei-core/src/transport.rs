//! Build 1: network transport. TCP, length-prefixed JSON frames carrying
//! Envelopes unchanged (QSW wire translation stays in ductei-qallow).
//! Every inbound envelope passes: scope policy → causal gate → JSONL
//! persistence, and only THEN is acked (persistence-first). The transport
//! trait is vendor-neutral so gRPC/QUIC can slot in later.
//! Frame: u32 LE length | JSON bytes. Ack: 1 byte with tri-state:
//!   1 = applied (new write persisted), 2 = stale/already-present (receipt),
//!   0 = rejected (scope-denied/malformed/failed-to-apply).

use crate::{Channel, ChannelError, Envelope};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};

pub trait Transport {
    fn send_envelope(&mut self, env: &Envelope) -> Result<bool, ChannelError>;
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

pub struct TcpClient { stream: TcpStream }
impl TcpClient {
    pub fn connect(addr: impl ToSocketAddrs) -> std::io::Result<Self> {
        Ok(Self { stream: TcpStream::connect(addr)? })
    }
}
impl Transport for TcpClient {
    /// Returns Ok(true) only after the remote has persisted the envelope.
    fn send_envelope(&mut self, env: &Envelope) -> Result<bool, ChannelError> {
        write_frame(&mut self.stream, env).map_err(|e| ChannelError::Io(e.to_string()))?;
        let mut ack = [0u8; 1];
        self.stream.read_exact(&mut ack).map_err(|e| ChannelError::Io(e.to_string()))?;
        // Success on applied (1) or already-present (2). Only 0 is rejection.
        Ok(ack[0] != 0)
    }
}

/// Serve one peer connection: every inbound frame goes through the channel
/// (scope check → gate → fsynced log) before the ack byte is written.
pub fn serve_connection(mut stream: TcpStream, ch: &mut Channel) -> std::io::Result<usize> {
    let mut accepted = 0usize;
    while let Some(env) = read_frame(&mut stream)? {
        let ack = match ch.send(env) {
            Ok(()) => { accepted += 1; 1u8 }
            Err(ChannelError::StaleDelta { .. }) => 2u8,
            Err(ChannelError::ScopeDenied(_)) => 0u8,
            Err(_) => 0u8, // I/O or other error: not applied
        };
        stream.write_all(&[ack])?;
        stream.flush()?;
    }
    Ok(accepted)
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
) -> Result<DeliveryPath, ChannelError> {
    match TcpClient::connect(addr) {
        Ok(mut client) => match client.send_envelope(env) {
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
        },
        Err(_) => {
            local.send(env.clone())?;
            Ok(DeliveryPath::LocalFallback)
        }
    }
}
