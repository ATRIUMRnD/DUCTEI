//! ductei-sync CLI.
//!
//!   ductei-sync node-id <state_dir>
//!   ductei-sync serve <state_dir> --listen ADDR --scope S [--scope S ...]
//!                     [--allow-ip IP ...] [--once]
//!   ductei-sync push  <state_dir> --peer ADDR [--peer ADDR ...]
//!                     [--interval-ms N] [--once]
//!
//!   ductei-sync key-show <state_dir>
//!   ductei-sync key-pin  <state_dir> --role server|client --peer NAME --file PATH [--replace]
//!
//! serve and push run as two processes per node. See src/lib.rs for the
//! state directory contract and the origin-only push model.
//!
//! Built with `--features qfltl`, serve and push are QFLTL-encrypted and
//! mutually authenticated BY DEFAULT (see src/qfltl_transport.rs); the
//! pushing side pins the server with `--role server`, the serving side pins
//! the client with `--role client`. `--plaintext` is an explicit opt-out and
//! must be given on both ends. A build WITHOUT qfltl refuses any
//! non-loopback address unless `--plaintext` is given, so an unencrypted
//! binary can't be deployed by accident.
use ductei_core::ScopePolicy;
use ductei_sync::{check_bind, push_once, serve, to_hex, PushReport, StateDir};
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::process::ExitCode;
use std::time::{Duration, Instant};

/// How long `serve` waits for its listen address to exist, and how often it retries.
const BIND_WAIT: Duration = Duration::from_secs(300);
const BIND_STEP: Duration = Duration::from_secs(5);

/// A tailnet address may not exist yet at logon: Tailscale can come up after
/// the task starts. Wait for it instead of exiting, because the scheduler's
/// restart-on-failure never fires when the task is launched through
/// `conhost --headless` (it always reports exit code 0). Only "address not
/// available" is retried; "address in use" (a second instance) fails at once.
fn bind_with_retry(addr: SocketAddr, wait: Duration, step: Duration) -> std::io::Result<TcpListener> {
    let deadline = Instant::now() + wait;
    loop {
        match TcpListener::bind(addr) {
            Ok(l) => return Ok(l),
            Err(e) if e.kind() == std::io::ErrorKind::AddrNotAvailable && Instant::now() < deadline => {
                eprintln!("ductei-sync serve: {addr} not available yet ({e}); retrying in {}s", step.as_secs());
                std::thread::sleep(step);
            }
            Err(e) => return Err(e),
        }
    }
}

const USAGE: &str = "usage:
  ductei-sync node-id <state_dir>
  ductei-sync serve <state_dir> --listen ADDR --scope S [--scope S ...] [--allow-ip IP ...] [--once] [--plaintext]
  ductei-sync push  <state_dir> --peer ADDR [--peer ADDR ...] [--interval-ms N] [--once] [--plaintext]
  ductei-sync key-show <state_dir>
  ductei-sync key-pin  <state_dir> --role server|client --peer NAME --file PATH [--replace]
    (--role server on the pushing side: NAME must be the exact --peer ADDR you push to;
     --role client on the serving side: NAME is just a label, e.g. xing-laptop;
     --replace only when that machine's key was rotated on purpose)";

/// True when this build encrypts by default (built with --features qfltl).
const QFLTL_BUILD: bool = cfg!(feature = "qfltl");

fn push_one(state: &StateDir, peer: &str, encrypted: bool) -> std::io::Result<PushReport> {
    #[cfg(feature = "qfltl")]
    if encrypted {
        return ductei_sync::qfltl_transport::push_once_qfltl(state, peer);
    }
    let _ = encrypted;
    push_once(state, peer)
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        return Err(USAGE.into());
    }
    let state = StateDir::open(&args[1]).map_err(|e| format!("state dir {}: {e}", args[1]))?;
    let node = state.node_id().map_err(|e| e.to_string())?;

    let mut listen: Option<String> = None;
    let mut scopes: Vec<String> = vec![];
    let mut allow_ips: Vec<IpAddr> = vec![];
    let mut peers: Vec<String> = vec![];
    let mut interval_ms: u64 = 2000;
    let mut once = false;
    let mut plaintext = false;
    let mut file: Option<String> = None;
    let mut role: Option<String> = None;
    let mut replace = false;
    let mut i = 2;
    while i < args.len() {
        let val = || args.get(i + 1).cloned().ok_or_else(|| format!("{} needs a value\n{USAGE}", args[i]));
        match args[i].as_str() {
            "--listen" => { listen = Some(val()?); i += 2; }
            "--scope" => { scopes.push(val()?); i += 2; }
            "--allow-ip" => {
                allow_ips.push(val()?.parse().map_err(|e| format!("--allow-ip: {e}"))?);
                i += 2;
            }
            "--peer" => { peers.push(val()?); i += 2; }
            "--interval-ms" => { interval_ms = val()?.parse().map_err(|e| format!("--interval-ms: {e}"))?; i += 2; }
            "--once" => { once = true; i += 1; }
            "--plaintext" => { plaintext = true; i += 1; }
            "--file" => { file = Some(val()?); i += 2; }
            "--role" => { role = Some(val()?); i += 2; }
            "--replace" => { replace = true; i += 1; }
            other => return Err(format!("unknown argument {other}\n{USAGE}")),
        }
    }
    let encrypted = QFLTL_BUILD && !plaintext;
    let mode = if encrypted {
        "qfltl (ML-KEM-768 + AES-256-GCM, mutual pin)"
    } else if QFLTL_BUILD {
        "PLAINTEXT (--plaintext given)"
    } else {
        "PLAINTEXT (built without --features qfltl)"
    };

    let is_net = matches!(args[0].as_str(), "serve" | "push");
    // An unencrypted build must not talk to anything off this machine unless
    // the operator says so explicitly.
    if is_net && !encrypted && !plaintext {
        let remote = |s: &str| s.parse::<SocketAddr>().map(|a| !a.ip().is_loopback()).unwrap_or(true);
        if listen.as_deref().is_some_and(remote) || peers.iter().any(|p| remote(p)) {
            return Err("this build has no qfltl encryption; refusing a non-loopback address without an explicit --plaintext (rebuild with --features qfltl)".into());
        }
    }
    #[cfg(feature = "qfltl")]
    if is_net && encrypted && ductei_sync::qfltl_transport::legacy_pins_present(state.root()) {
        eprintln!(
            "ductei-sync {}: warning: {} holds pins from before the server/client split; they are IGNORED. Re-pin with key-pin --role server (pushing side) or --role client (serving side).",
            args[0],
            state.root().join("qfltl").join("known_peers").display()
        );
    }

    match args[0].as_str() {
        #[cfg(feature = "qfltl")]
        "key-show" => {
            use ductei_sync::qfltl_transport as q;
            let kp = q::load_or_generate_identity(state.root()).map_err(|e| e.to_string())?;
            println!("public key:  {}", q::public_key_path(state.root()).display());
            println!("fingerprint: {}", q::fingerprint_hex(&kp.fingerprint()));
            println!("copy the public key file to the peer and run key-pin there;");
            println!("compare this fingerprint with what key-pin prints on the peer.");
            Ok(())
        }
        #[cfg(feature = "qfltl")]
        "key-pin" => {
            use ductei_sync::qfltl_transport as q;
            let name = match peers.as_slice() {
                [one] => one.clone(),
                _ => return Err(format!("key-pin needs exactly one --peer NAME\n{USAGE}")),
            };
            let pin_role = role
                .as_deref()
                .and_then(q::PinRole::parse)
                .ok_or_else(|| format!("key-pin needs --role server or --role client\n{USAGE}"))?;
            let path = file.ok_or_else(|| format!("key-pin needs --file PATH\n{USAGE}"))?;
            let bytes = std::fs::read(&path).map_err(|e| format!("{path}: {e}"))?;
            let fp = q::pin_key(state.root(), pin_role, &name, &bytes, replace).map_err(|e| e.to_string())?;
            println!("pinned {name} as {}", if pin_role == q::PinRole::Server { "server" } else { "client" });
            println!("fingerprint: {}", q::fingerprint_hex(&fp));
            println!("this MUST match key-show on that machine before you trust it.");
            Ok(())
        }
        #[cfg(not(feature = "qfltl"))]
        "key-show" | "key-pin" => {
            let _ = (file, role, replace);
            Err("key commands need a build with --features qfltl".into())
        }
        "node-id" => {
            println!("{}", to_hex(&node));
            Ok(())
        }
        "serve" => {
            let listen = listen.ok_or_else(|| format!("serve needs --listen\n{USAGE}"))?;
            if scopes.is_empty() {
                return Err("serve needs at least one --scope (deny by default)".into());
            }
            let addr: SocketAddr = listen.parse().map_err(|e| format!("--listen {listen}: {e}"))?;
            check_bind(&addr, &allow_ips)?;
            let mut policy = ScopePolicy::new();
            for s in &scopes {
                policy = policy.allow(s);
            }
            #[cfg(feature = "qfltl")]
            let identity = if encrypted {
                let kp = ductei_sync::qfltl_transport::load_or_generate_identity(state.root())
                    .map_err(|e| format!("qfltl identity: {e}"))?;
                let pinned = ductei_sync::qfltl_transport::load_pinned_clients(state.root())
                    .map_err(|e| e.to_string())?;
                if pinned.is_empty() {
                    eprintln!("ductei-sync serve: warning: no pinned clients yet, every client will be refused (use key-pin --role client)");
                }
                Some(kp)
            } else {
                None
            };
            let listener = bind_with_retry(addr, BIND_WAIT, BIND_STEP).map_err(|e| format!("bind {addr}: {e}"))?;
            println!(
                "ductei-sync serve: node={} listen={} transport={mode} scopes={:?} allow_ip={:?} inbound={}",
                to_hex(&node),
                listener.local_addr().map(|a| a.to_string()).unwrap_or(listen),
                scopes,
                allow_ips,
                state.inbound_log().display()
            );
            let log = |from: SocketAddr, res: std::io::Result<usize>| match res {
                Ok(n) => println!("ductei-sync serve: {from} persisted {n}"),
                Err(e) => eprintln!("ductei-sync serve: {from} {e}"),
            };
            #[cfg(feature = "qfltl")]
            if let Some(kp) = identity {
                return ductei_sync::qfltl_transport::serve_qfltl(
                    &state, listener, policy, &allow_ips, once.then_some(1), &kp, log,
                )
                .map_err(|e| e.to_string());
            }
            serve(&state, listener, policy, &allow_ips, once.then_some(1), log).map_err(|e| e.to_string())
        }
        "push" => {
            if peers.is_empty() {
                return Err(format!("push needs at least one --peer\n{USAGE}"));
            }
            #[cfg(feature = "qfltl")]
            if encrypted {
                for p in &peers {
                    if ductei_sync::qfltl_transport::pinned_server_key(state.root(), p)
                        .map_err(|e| e.to_string())?
                        .is_none()
                    {
                        return Err(format!(
                            "peer {p} has no pinned QFLTL server key; refusing to connect.\n  copy that machine's qfltl\\identity.pub here, then run:\n  ductei-sync key-pin \"{}\" --role server --peer {p} --file \"{}\"",
                            state.root().display(),
                            state.root().join("peer-identity.pub").display()
                        ));
                    }
                }
            }
            println!(
                "ductei-sync push: node={} transport={mode} peers={:?} local={}",
                to_hex(&node),
                peers,
                state.local_log().display()
            );
            loop {
                for p in &peers {
                    match push_one(&state, p, encrypted) {
                        Ok(r) if r.delivered + r.refused > 0 || r.interrupted => println!(
                            "ductei-sync push: {p} delivered={} refused={} skipped_foreign={}{}",
                            r.delivered, r.refused, r.skipped_foreign,
                            if r.interrupted { " (peer unreachable or connection broke; will retry)" } else { "" }
                        ),
                        Ok(_) => {}
                        Err(e) => eprintln!("ductei-sync push: {p}: {e}"),
                    }
                }
                if once {
                    return Ok(());
                }
                std::thread::sleep(Duration::from_millis(interval_ms));
            }
        }
        other => Err(format!("unknown command {other}\n{USAGE}")),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_succeeds_at_once_on_a_real_address() {
        let t0 = Instant::now();
        let l = bind_with_retry("127.0.0.1:0".parse().unwrap(), Duration::from_secs(5), Duration::from_millis(50)).unwrap();
        assert!(l.local_addr().unwrap().port() != 0);
        assert!(t0.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn bind_waits_for_an_address_that_does_not_exist_then_gives_up() {
        // 192.0.2.1 is TEST-NET-1 (RFC 5737): never assigned to a local interface.
        let t0 = Instant::now();
        let e = bind_with_retry("192.0.2.1:7420".parse().unwrap(), Duration::from_millis(400), Duration::from_millis(100)).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::AddrNotAvailable);
        assert!(t0.elapsed() >= Duration::from_millis(400), "must have retried until the deadline");
    }

    #[test]
    fn bind_does_not_retry_when_the_port_is_taken() {
        let held = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = held.local_addr().unwrap();
        let t0 = Instant::now();
        let e = bind_with_retry(addr, Duration::from_secs(5), Duration::from_millis(100)).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::AddrInUse);
        assert!(t0.elapsed() < Duration::from_secs(1), "a second instance must fail fast, not wait");
    }
}
