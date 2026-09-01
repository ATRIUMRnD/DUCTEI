//! QUIC transport behind the vendor-neutral `Transport` trait (feature
//! `quic`). Same length-prefixed JSON envelope framing as the TCP
//! transport, carried over a QUIC bidirectional stream instead of a raw
//! TCP socket. Same persistence-first ack contract: `send_envelope`
//! returns `Ok(true)` only once the remote has run scope policy -> causal
//! gate -> fsynced JSONL append.
//!
//! TLS is mandatory in QUIC; there is no CA here, so the server presents a
//! self-signed cert (`generate_self_signed`) and clients pin it by DER
//! bytes out-of-band (matching how peers are provisioned today: config,
//! not a PKI).
use crate::{outbox::Outbox, Channel, ChannelError, Envelope};
use quinn::{ClientConfig, Endpoint, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use std::io::{Error as IoError, ErrorKind};
use std::net::SocketAddr;
use std::sync::Arc;

/// Self-signed cert + key for a QUIC server. Distribute `cert_der` to
/// clients out-of-band so they can pin it.
pub struct SelfSigned {
    pub cert_der: Vec<u8>,
    key_der: Vec<u8>,
}

pub fn generate_self_signed(subject_alt_name: &str) -> Result<SelfSigned, ChannelError> {
    let cert = rcgen::generate_simple_self_signed(vec![subject_alt_name.into()])
        .map_err(|e| ChannelError::Io(e.to_string()))?;
    Ok(SelfSigned {
        cert_der: cert.cert.der().to_vec(),
        key_der: cert.key_pair.serialize_der(),
    })
}

fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn write_frame_sync(buf: &mut Vec<u8>, env: &Envelope) -> std::io::Result<()> {
    let body = serde_json::to_vec(env)?;
    buf.extend_from_slice(&(body.len() as u32).to_le_bytes());
    buf.extend_from_slice(&body);
    Ok(())
}

async fn read_frame(recv: &mut quinn::RecvStream) -> std::io::Result<Option<Envelope>> {
    let mut len = [0u8; 4];
    match recv.read_exact(&mut len).await {
        Ok(()) => {}
        Err(quinn::ReadExactError::FinishedEarly(_)) => return Ok(None),
        Err(e) => return Err(IoError::new(ErrorKind::UnexpectedEof, e)),
    }
    let n = u32::from_le_bytes(len) as usize;
    if n > 16 * 1024 * 1024 {
        return Err(IoError::new(ErrorKind::InvalidData, "frame too big"));
    }
    let mut body = vec![0u8; n];
    recv.read_exact(&mut body)
        .await
        .map_err(|e| IoError::new(ErrorKind::UnexpectedEof, e))?;
    Ok(Some(serde_json::from_slice(&body)?))
}

/// Blocking `Transport` impl: owns a small current-thread Tokio runtime and
/// one bidirectional stream per envelope (mirrors the TCP client's
/// one-ack-per-frame contract).
pub struct QuicClient {
    rt: tokio::runtime::Runtime,
    endpoint: Endpoint,
    connection: quinn::Connection,
    outbox_path: Option<std::path::PathBuf>,
}

impl QuicClient {
    pub fn connect(addr: SocketAddr, server_name: &str, server_cert_der: &[u8]) -> Result<Self, ChannelError> {
        ensure_crypto_provider();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| ChannelError::Io(e.to_string()))?;

        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(server_cert_der.to_vec()))
            .map_err(|e| ChannelError::Io(e.to_string()))?;
        let crypto = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let client_cfg = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
                .map_err(|e| ChannelError::Io(e.to_string()))?,
        ));

        let bind_addr: SocketAddr = if addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" }
            .parse()
            .unwrap();
        // Endpoint::client spawns internal driver tasks that need an
        // active Tokio runtime context, even though the call itself is sync.
        let _guard = rt.enter();
        let mut endpoint = Endpoint::client(bind_addr).map_err(|e| ChannelError::Io(e.to_string()))?;
        endpoint.set_default_client_config(client_cfg);

        let connection = rt
            .block_on(async {
                let connecting = endpoint.connect(addr, server_name).map_err(|e| ChannelError::Io(e.to_string()))?;
                connecting.await.map_err(|e| ChannelError::Io(e.to_string()))
            })?;

        Ok(Self { rt, endpoint, connection, outbox_path: None })
    }
    /// Attach a durable outbound intent/receipt log. When set, the client
    /// records intents before any network write and receipts before returning.
    pub fn with_outbox_path(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.outbox_path = Some(path.into());
        self
    }
}

impl super::transport::Transport for QuicClient {
    fn send_envelope(&mut self, env: &Envelope) -> Result<bool, ChannelError> {
        let mut buf = Vec::new();
        write_frame_sync(&mut buf, env).map_err(|e| ChannelError::Io(e.to_string()))?;
        self.rt.block_on(async {
            // Record outbound intent before any I/O.
            if let Some(p) = &self.outbox_path {
                let mut ob = Outbox::open(p).map_err(|e| ChannelError::Io(e.to_string()))?;
                ob.record_intent(env).map_err(|e| ChannelError::Io(e.to_string()))?;
            }
            let (mut send, mut recv) = self.connection.open_bi().await.map_err(|e| ChannelError::Io(e.to_string()))?;
            send.write_all(&buf).await.map_err(|e| ChannelError::Io(e.to_string()))?;
            send.finish().map_err(|e| ChannelError::Io(e.to_string()))?;
            let mut ack = [0u8; 1];
            if let Err(e) = recv.read_exact(&mut ack).await {
                if let Some(p) = &self.outbox_path {
                    let mut ob = Outbox::open(p).map_err(|e2| ChannelError::Io(e2.to_string()))?;
                    let _ = ob.record_receipt(&env.key, env.lamport, &env.node_id, 0xFF);
                }
                return Err(ChannelError::Io(e.to_string()));
            }
            let code = ack[0];
            if let Some(p) = &self.outbox_path {
                let mut ob = Outbox::open(p).map_err(|e| ChannelError::Io(e.to_string()))?;
                ob.record_receipt(&env.key, env.lamport, &env.node_id, code)
                    .map_err(|e| ChannelError::Io(e.to_string()))?;
            }
            match code {
                1 | 2 => Ok(true),
                0 => Ok(false),
                _ => Err(ChannelError::Io(format!("unknown ack value {}", code))),
            }
        })
    }
}

impl Drop for QuicClient {
    fn drop(&mut self) {
        self.connection.close(0u32.into(), b"bye");
        self.endpoint.close(0u32.into(), b"bye");
    }
}

/// Serve on `addr` until the process is killed. Every inbound envelope
/// goes through the same channel (scope check -> causal gate -> fsynced
/// log) as the TCP transport before the ack byte is written.
pub fn serve_quic_blocking(addr: SocketAddr, signed: SelfSigned, mut ch: Channel) -> std::io::Result<()> {
    ensure_crypto_provider();
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    rt.block_on(async move {
        let cert = CertificateDer::from(signed.cert_der);
        let key = PrivatePkcs8KeyDer::from(signed.key_der);
        let server_cfg = ServerConfig::with_single_cert(vec![cert], key.into())
            .map_err(|e| IoError::other(e.to_string()))?;
        let endpoint = Endpoint::server(server_cfg, addr)?;

        while let Some(incoming) = endpoint.accept().await {
            let conn = incoming.await.map_err(|e| IoError::other(e.to_string()))?;
            loop {
                let (mut send, mut recv) = match conn.accept_bi().await {
                    Ok(s) => s,
                    Err(_) => break, // peer closed the connection
                };
                let ack = match read_frame(&mut recv).await? {
                    Some(env) => match ch.send(env) {
                        Ok(()) => 1u8,
                        Err(crate::ChannelError::StaleDelta { .. }) => 2u8,
                        Err(crate::ChannelError::ScopeDenied(_)) => 0u8,
                        Err(_) => 0u8,
                    },
                    None => break,
                };
                send.write_all(&[ack]).await.map_err(|e| IoError::other(e.to_string()))?;
                send.finish().map_err(|e| IoError::other(e.to_string()))?;
            }
        }
        Ok(())
    })
}
