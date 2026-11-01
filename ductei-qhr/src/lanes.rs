//! Built-in lanes. CPU is real. LLM wraps the router's T0 brain (Ollama on
//! this machine). CUDA and QPU are registered as unavailable until they are
//! wired to real backends, so jobs for them are refused in pre-flight with a
//! reason instead of pretending to run.

use crate::{Health, Job, Lane, LaneId};
use ductei_router::brain::{Brain, Ollama};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Local CPU work. Ops: `cpu.echo`, `cpu.sha256`, and `cpu.sleep` (a
/// diagnostic that deliberately ignores the deadline, to exercise misses).
pub struct CpuLane;

impl Lane for CpuLane {
    fn id(&self) -> LaneId { LaneId::Cpu }
    fn health(&self) -> Health { Health::Ready }
    fn preflight(&self, job: &Job) -> Result<(), String> {
        match job.op.as_str() {
            "cpu.echo" | "cpu.sha256" => Ok(()),
            "cpu.sleep" => job.payload.trim().parse::<u64>().map(|_| ()).map_err(|_| "cpu.sleep wants a millisecond count".into()),
            o => Err(format!("cpu lane has no op {o:?}")),
        }
    }
    fn run(&self, job: &Job, _deadline: Instant) -> Result<String, String> {
        match job.op.as_str() {
            "cpu.echo" => Ok(job.payload.clone()),
            "cpu.sha256" => Ok(ductei_mcp::sha256_hex(job.payload.as_bytes())),
            "cpu.sleep" => {
                let ms = job.payload.trim().parse::<u64>().map_err(|e| e.to_string())?;
                std::thread::sleep(Duration::from_millis(ms));
                Ok(format!("slept {ms} ms"))
            }
            o => Err(format!("cpu lane has no op {o:?}")),
        }
    }
}

/// A lane that exists in the plan but has no backend on this machine yet.
pub struct UnavailableLane { pub id: LaneId, pub why: String }

impl Lane for UnavailableLane {
    fn id(&self) -> LaneId { self.id }
    fn health(&self) -> Health { Health::Unavailable(self.why.clone()) }
    fn run(&self, _job: &Job, _deadline: Instant) -> Result<String, String> { Err(self.why.clone()) }
}

/// How long a health probe result is trusted, so probes stay out of the budget.
pub const HEALTH_TTL: Duration = Duration::from_secs(5);
const PROBE_TIMEOUT: Duration = Duration::from_millis(150);

/// Local LLM. Op: `llm.complete` (payload = prompt). The brain's own
/// locality rules apply (Ollama refuses non-local hosts).
pub struct LlmLane {
    brain: Box<dyn Brain + Send + Sync>,
    probe: Option<(String, u16)>,
    cache: Mutex<Option<(Instant, Health)>>,
}

impl LlmLane {
    pub fn ollama(o: Ollama) -> Self {
        let probe = Some((o.host.clone(), o.port));
        Self { brain: Box::new(o), probe, cache: Mutex::new(None) }
    }
    /// Any brain, no network probe (always Ready). For tests and in-process brains.
    pub fn with_brain(brain: Box<dyn Brain + Send + Sync>) -> Self {
        Self { brain, probe: None, cache: Mutex::new(None) }
    }
}

impl Lane for LlmLane {
    fn id(&self) -> LaneId { LaneId::Llm }
    fn health(&self) -> Health {
        let Some((host, port)) = &self.probe else { return Health::Ready };
        let mut c = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((at, h)) = c.as_ref() { if at.elapsed() < HEALTH_TTL { return h.clone(); } }
        let h = match (host.as_str(), *port).to_socket_addrs().ok().and_then(|mut a| a.next()) {
            None => Health::Unavailable(format!("cannot resolve {host}:{port}")),
            Some(addr) => match TcpStream::connect_timeout(&addr, PROBE_TIMEOUT) {
                Ok(_) => Health::Ready,
                Err(e) => Health::Unavailable(format!("{} not answering at {addr}: {e}", self.brain.name())),
            },
        };
        *c = Some((Instant::now(), h.clone()));
        h
    }
    fn preflight(&self, job: &Job) -> Result<(), String> {
        if job.op != "llm.complete" { return Err(format!("llm lane has no op {:?}", job.op)); }
        if job.payload.trim().is_empty() { return Err("llm.complete wants a prompt".into()); }
        Ok(())
    }
    fn run(&self, job: &Job, _deadline: Instant) -> Result<String, String> {
        self.brain.complete("Answer briefly.", &job.payload)
    }
}
