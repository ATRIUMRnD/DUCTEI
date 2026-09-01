//! gRPC transport behind the vendor-neutral `Transport` trait (feature
//! `grpc`). Envelope JSON bytes ride unchanged inside a single-field proto
//! message; gRPC supplies framing/multiplexing/TLS only. Same
//! persistence-first ack contract as the TCP transport: `send_envelope`
//! returns `Ok(true)` only once the remote has run scope policy -> causal
//! gate -> fsynced JSONL append.
use crate::{Channel, ChannelError, Envelope};
use std::sync::Arc;
use tokio::sync::Mutex;
use tonic::{transport::Server, Request, Response, Status};

pub mod proto {
    tonic::include_proto!("ductei.channel.v1");
}
use proto::channel_service_client::ChannelServiceClient;
use proto::channel_service_server::{ChannelService, ChannelServiceServer};
use proto::{Ack, EnvelopeMsg};

/// Blocking `Transport` impl: owns a small current-thread Tokio runtime so
/// the sync trait contract matches `TcpClient`.
pub struct GrpcClient {
    rt: tokio::runtime::Runtime,
    client: ChannelServiceClient<tonic::transport::Channel>,
}

impl GrpcClient {
    pub fn connect(addr: &str) -> Result<Self, ChannelError> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| ChannelError::Io(e.to_string()))?;
        let endpoint = format!("http://{addr}");
        let client = rt
            .block_on(ChannelServiceClient::connect(endpoint))
            .map_err(|e| ChannelError::Io(e.to_string()))?;
        Ok(Self { rt, client })
    }
}

impl super::transport::Transport for GrpcClient {
    fn send_envelope(&mut self, env: &Envelope) -> Result<bool, ChannelError> {
        let json_envelope = serde_json::to_vec(env).map_err(|e| ChannelError::Io(e.to_string()))?;
        let req = Request::new(EnvelopeMsg { json_envelope });
        let resp = self
            .rt
            .block_on(self.client.send_envelope(req))
            .map_err(|e| ChannelError::Io(e.to_string()))?;
        let code = resp.into_inner().code as u8;
        match code {
            1 | 2 => Ok(true),
            0 => Err(ChannelError::ScopeDenied(env.key.clone())),
            _ => Err(ChannelError::Io(format!("unknown ack value {}", code))),
        }
    }
}

struct Service {
    ch: Arc<Mutex<Channel>>,
}

#[tonic::async_trait]
impl ChannelService for Service {
    async fn send_envelope(&self, request: Request<EnvelopeMsg>) -> Result<Response<Ack>, Status> {
        let msg = request.into_inner();
        let env: Envelope = serde_json::from_slice(&msg.json_envelope)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let code = match self.ch.lock().await.send(env) {
            Ok(()) => 1u32,
            Err(crate::ChannelError::StaleDelta { .. }) => 2u32,
            Err(crate::ChannelError::ScopeDenied(_)) => 0u32,
            Err(_) => 0u32,
        };
        Ok(Response::new(Ack { code }))
    }
}

/// Serve on `addr` until the process is killed. Every inbound envelope
/// goes through the same channel (scope check -> causal gate -> fsynced
/// log) as the TCP transport before the ack is returned.
pub fn serve_grpc_blocking(addr: std::net::SocketAddr, ch: Channel) -> std::io::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let svc = Service { ch: Arc::new(Mutex::new(ch)) };
    rt.block_on(async move {
        Server::builder()
            .add_service(ChannelServiceServer::new(svc))
            .serve(addr)
            .await
            .map_err(std::io::Error::other)
    })
}
