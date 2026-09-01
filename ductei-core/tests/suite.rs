use ductei_core::gate::{CausalGate, Verdict};
#[cfg(feature = "net")]
use ductei_core::transport::{serve_connection, DeliveryPath, TcpClient, Transport};
use ductei_core::*;
#[cfg(feature = "net")]
use std::io::{Read, Write};
#[cfg(feature = "net")]
use std::net::{TcpListener, TcpStream};
#[cfg(feature = "grpc")]
use ductei_core::grpc::{serve_grpc_blocking, GrpcClient};

fn node(n: u8) -> [u8; 16] { [n; 16] }
fn tmp(name: &str) -> String { format!("{}/{}-{}", std::env::temp_dir().display(), std::process::id(), name) }
fn env(key: &str, sc: &[&str], nd: u8, lam: u64) -> Envelope { scoped(key, sc, node(nd), lam, b"x") }
fn chan(name: &str) -> Channel {
    Channel::open(ScopePolicy::new().allow("qallow.semantic.cert").allow("veyn.sensor.eeg"),
        tmp(&format!("{name}.jsonl")), tmp(&format!("{name}-rej.jsonl"))).unwrap()
}

#[test]
fn scope_deny_by_default() {
    let mut ch = chan("t0");
    assert!(ch.send(env("a", &["qallow.semantic.cert"], 1, 1)).is_ok());
    assert!(matches!(ch.send(env("b", &["limen.credentials"], 1, 2)), Err(ChannelError::ScopeDenied(_))));
    assert!(matches!(ch.send(env("c", &[], 1, 3)), Err(ChannelError::ScopeDenied(_))));
}

#[test]
fn poisoned_envelope() {
    let mut ch = chan("t1");
    assert!(matches!(ch.send(env("a", &["qallow.semantic.cert", "secret"], 1, 1)), Err(ChannelError::ScopeDenied(_))));
}

#[test]
fn restart_survival() {
    let p = tmp("t2.jsonl"); let r = tmp("t2r.jsonl");
    let _ = std::fs::remove_file(&p);
    {
        let mut ch = Channel::open(ScopePolicy::new().allow("qallow.semantic.cert"), &p, &r).unwrap();
        ch.send(env("a", &["qallow.semantic.cert"], 1, 1)).unwrap();
        ch.send(env("b", &["qallow.semantic.cert"], 1, 2)).unwrap();
    }
    let ch = Channel::open(ScopePolicy::new().allow("qallow.semantic.cert"), &p, &r).unwrap();
    let (envs, cur) = ch.replay(0).unwrap();
    assert_eq!(envs.len(), 2); assert_eq!(cur, 2);
    assert_eq!(envs[1].key, "b");
}

#[test]
fn credential_drop_closed_type() {
    let json = r#"{"job_id":"j1","backend":"ibm_fez","tier":2,"fidelity_estimate":0.97,
                   "lamport":9,"api_token":"SECRET","qpu_instance":"h/g/p"}"#;
    let e = ductei_limen::cert_to_envelope(json, node(7)).unwrap();
    let s = serde_json::to_string(&e).unwrap();
    assert!(!s.contains("SECRET") && !s.contains("api_token") && !s.contains("h/g/p"));
}

#[test]
fn unbounded_session_unrepresentable() { assert!(SessionBound::new(None, None).is_none()); }

#[test]
fn session_bound_enforced() {
    let mut ch = chan("t3");
    let mut s = ch.session(SessionBound::new(Some(2), None).unwrap());
    s.send(env("a", &["qallow.semantic.cert"], 1, 1), 1).unwrap();
    s.send(env("b", &["qallow.semantic.cert"], 1, 2), 1).unwrap();
    assert!(matches!(s.send(env("c", &["qallow.semantic.cert"], 1, 3), 1), Err(ChannelError::BoundReached)));
    assert!(s.is_closed());
    assert_eq!(s.close(), 2);
}

// ---- Build 0: causal-delta gate ----

#[test]
fn gate_in_order_accept_stale_reject() {
    let mut g = CausalGate::new();
    assert_eq!(g.admit(&env("k", &["s"], 1, 5)), Verdict::Accept);
    assert_eq!(g.admit(&env("k", &["s"], 1, 6)), Verdict::Accept);
    assert_eq!(g.admit(&env("k", &["s"], 1, 6)), Verdict::Stale);
    assert_eq!(g.admit(&env("k", &["s"], 1, 4)), Verdict::Stale);
    assert_eq!(g.admit(&env("k2", &["s"], 1, 1)), Verdict::Accept);
}

#[test]
fn gate_tie_break_deterministic_by_node_id() {
    let mut g = CausalGate::new();
    assert_eq!(g.admit(&env("k", &["s"], 3, 5)), Verdict::Accept);
    assert_eq!(g.admit(&env("k", &["s"], 2, 5)), Verdict::Stale);
    assert_eq!(g.admit(&env("k", &["s"], 4, 5)), Verdict::Accept);
    let mut g2 = CausalGate::new();
    assert_eq!(g2.admit(&env("k", &["s"], 3, 5)), Verdict::Accept);
    assert_eq!(g2.admit(&env("k", &["s"], 2, 5)), Verdict::Stale);
}

#[test]
fn gate_replay_after_restart_consistent() {
    let p = tmp("t4.jsonl"); let r = tmp("t4r.jsonl");
    let _ = std::fs::remove_file(&p);
    {
        let mut ch = Channel::open(ScopePolicy::new().allow("qallow.semantic.cert"), &p, &r).unwrap();
        ch.send(env("k", &["qallow.semantic.cert"], 1, 10)).unwrap();
    }
    let mut ch = Channel::open(ScopePolicy::new().allow("qallow.semantic.cert"), &p, &r).unwrap();
    assert!(matches!(ch.send(env("k", &["qallow.semantic.cert"], 1, 9)),
        Err(ChannelError::StaleDelta { .. })));
    assert!(ch.send(env("k", &["qallow.semantic.cert"], 1, 11)).is_ok());
    let (envs, _) = ch.replay(0).unwrap();
    assert_eq!(envs.len(), 2);
}

// ---- Build 1: transport (two-node loopback acceptance gate) ----

#[cfg(feature = "net")]
#[test]
fn transport_two_node_loopback() {
    let p = tmp("t5.jsonl"); let r = tmp("t5r.jsonl");
    let _ = std::fs::remove_file(&p);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let mut ch = Channel::open(ScopePolicy::new().allow("qallow.semantic.cert"), &p, &r).unwrap();
        let (stream, _) = listener.accept().unwrap();
        let accepted = serve_connection(stream, &mut ch).unwrap();
        let (envs, _) = ch.replay(0).unwrap();
        (accepted, envs)
    });
    let mut c = TcpClient::connect(addr).unwrap();
    assert!(c.send_envelope(&env("a", &["qallow.semantic.cert"], 1, 1)).unwrap());
    // Duplicate (same triple) is a successful receipt (ack=2), not a rejection.
    assert!(c.send_envelope(&env("a", &["qallow.semantic.cert"], 1, 1)).unwrap());
    assert!(!c.send_envelope(&env("b", &["limen.credentials"], 1, 2)).unwrap());
    assert!(c.send_envelope(&env("a", &["qallow.semantic.cert"], 1, 2)).unwrap());
    drop(c);
    let (accepted, envs) = server.join().unwrap();
    assert_eq!(accepted, 2);
    assert_eq!(envs.len(), 2);
}

// ---- GAP 4: network transport, feature-gated, local-first ----

#[cfg(feature = "net")]
#[test]
fn transport_malformed_frame_rejected_without_corrupting_log() {
    let p = tmp("t5m.jsonl");
    let r = tmp("t5mr.jsonl");
    let _ = std::fs::remove_file(&p);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let mut ch = Channel::open(ScopePolicy::new().allow("qallow.semantic.cert"), &p, &r).unwrap();
        let (stream, _) = listener.accept().unwrap();
        // A malformed frame ends the connection (serve_connection returns
        // Err) but must never panic and must never touch the log for the
        // bad frame -- only whatever was already validly accepted before it.
        let _ = serve_connection(stream, &mut ch);
        let (envs, _) = ch.replay(0).unwrap();
        envs
    });

    let mut stream = TcpStream::connect(addr).unwrap();
    let good = env("a", &["qallow.semantic.cert"], 1, 1);
    let body = serde_json::to_vec(&good).unwrap();
    stream.write_all(&(body.len() as u32).to_le_bytes()).unwrap();
    stream.write_all(&body).unwrap();
    let mut ack = [0u8; 1];
    stream.read_exact(&mut ack).unwrap();
    assert_eq!(ack[0], 1);

    // Length prefix claims 5 bytes of body but they are not valid JSON.
    let garbage = [0u8, 1, 2, 3, 4];
    stream.write_all(&(garbage.len() as u32).to_le_bytes()).unwrap();
    stream.write_all(&garbage).unwrap();
    drop(stream);

    let envs = server.join().unwrap();
    assert_eq!(envs.len(), 1);
    assert_eq!(envs[0].key, "a");
}

#[cfg(feature = "net")]
#[test]
fn transport_restart_replay_over_network() {
    let p = tmp("t5s.jsonl");
    let r = tmp("t5sr.jsonl");
    let _ = std::fs::remove_file(&p);
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (pp, rp) = (p.clone(), r.clone());
        let server = std::thread::spawn(move || {
            let mut ch = Channel::open(ScopePolicy::new().allow("qallow.semantic.cert"), &pp, &rp).unwrap();
            let (stream, _) = listener.accept().unwrap();
            serve_connection(stream, &mut ch).unwrap();
        });
        let mut c = TcpClient::connect(addr).unwrap();
        assert!(c.send_envelope(&env("a", &["qallow.semantic.cert"], 1, 1)).unwrap());
        drop(c);
        server.join().unwrap();
    }
    // Simulate a restart: fresh Channel + fresh listener over the same
    // persisted log path. The gate/log must rebuild from what was already
    // accepted, exactly like the local restart_survival test.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let mut ch = Channel::open(ScopePolicy::new().allow("qallow.semantic.cert"), &p, &r).unwrap();
        let (stream, _) = listener.accept().unwrap();
        serve_connection(stream, &mut ch).unwrap();
        let (envs, _) = ch.replay(0).unwrap();
        envs
    });
    let mut c = TcpClient::connect(addr).unwrap();
    assert!(c.send_envelope(&env("b", &["qallow.semantic.cert"], 1, 2)).unwrap());
    drop(c);
    let envs = server.join().unwrap();
    assert_eq!(envs.len(), 2);
    assert_eq!(envs[0].key, "a");
    assert_eq!(envs[1].key, "b");
}

#[cfg(feature = "net")]
#[test]
fn transport_degrades_to_local_when_network_unavailable() {
    let p = tmp("t5d.jsonl");
    let r = tmp("t5dr.jsonl");
    let _ = std::fs::remove_file(&p);
    let mut local = Channel::open(ScopePolicy::new().allow("qallow.semantic.cert"), &p, &r).unwrap();

    // Bind then immediately drop to get a port nothing is listening on --
    // the network path must fail to connect, and the send must not be lost.
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    drop(l);

    let e = env("a", &["qallow.semantic.cert"], 1, 1);
    let path = ductei_core::transport::send_local_first(addr, &e, &mut local).unwrap();
    assert_eq!(path, DeliveryPath::LocalFallback);

    let (envs, _) = local.replay(0).unwrap();
    assert_eq!(envs.len(), 1);
    assert_eq!(envs[0].key, "a");
}

#[cfg(feature = "net")]
#[test]
fn transport_crash_window_retry_ack2() {
    use std::net::TcpListener;
    use std::io::{Read, Write};

    let p = tmp("t5c.jsonl"); let r = tmp("t5cr.jsonl");
    let _ = std::fs::remove_file(&p);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let mut ch = Channel::open(ScopePolicy::new().allow("qallow.semantic.cert"), &p, &r).unwrap();
        // Accept two connections: first writer crashes before reading ack; second is retry.
        let mut accepted_total = 0usize;
        for _ in 0..2 {
            let (stream, _) = listener.accept().unwrap();
            let res = serve_connection(stream, &mut ch);
            if let Ok(n) = res { accepted_total += n; }
        }
        let (envs, _) = ch.replay(0).unwrap();
        (accepted_total, envs)
    });

    // First attempt: write frame then drop before reading ack (simulate crash).
    let e = env("a", &["qallow.semantic.cert"], 1, 1);
    let mut s1 = std::net::TcpStream::connect(addr).unwrap();
    let body = serde_json::to_vec(&e).unwrap();
    s1.write_all(&(body.len() as u32).to_le_bytes()).unwrap();
    s1.write_all(&body).unwrap();
    drop(s1); // crash before reading ack

    // Retry after "restart": identical triple, expect ack=2 and no second apply.
    let mut s2 = std::net::TcpStream::connect(addr).unwrap();
    s2.write_all(&(body.len() as u32).to_le_bytes()).unwrap();
    s2.write_all(&body).unwrap();
    let mut ack = [0u8; 1];
    s2.read_exact(&mut ack).unwrap();
    assert_eq!(ack[0], 2);
    drop(s2);

    let (accepted_total, envs) = server.join().unwrap();
    assert_eq!(accepted_total, 1);
    assert_eq!(envs.len(), 1);
    assert_eq!(envs[0].key, "a");
}

#[cfg(feature = "net")]
#[test]
fn transport_same_triple_stale_while_newer_lamport_applies() {
    use std::net::TcpListener;
    use std::io::{Read, Write};

    let p = tmp("t5n.jsonl"); let r = tmp("t5nr.jsonl");
    let _ = std::fs::remove_file(&p);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let mut ch = Channel::open(ScopePolicy::new().allow("qallow.semantic.cert"), &p, &r).unwrap();
        let (stream, _) = listener.accept().unwrap();
        let _ = serve_connection(stream, &mut ch);
        let (envs, _) = ch.replay(0).unwrap();
        envs
    });

    let mut s = std::net::TcpStream::connect(addr).unwrap();
    // Send lamport=1
    let e1 = env("k", &["qallow.semantic.cert"], 1, 1);
    let b1 = serde_json::to_vec(&e1).unwrap();
    s.write_all(&(b1.len() as u32).to_le_bytes()).unwrap();
    s.write_all(&b1).unwrap();
    let mut a = [0u8; 1]; s.read_exact(&mut a).unwrap(); assert_eq!(a[0], 1);
    // Duplicate (stale)
    s.write_all(&(b1.len() as u32).to_le_bytes()).unwrap();
    s.write_all(&b1).unwrap();
    s.read_exact(&mut a).unwrap(); assert_eq!(a[0], 2);
    // Newer lamport applies
    let e2 = env("k", &["qallow.semantic.cert"], 1, 2);
    let b2 = serde_json::to_vec(&e2).unwrap();
    s.write_all(&(b2.len() as u32).to_le_bytes()).unwrap();
    s.write_all(&b2).unwrap();
    s.read_exact(&mut a).unwrap(); assert_eq!(a[0], 1);
    drop(s);

    let envs = server.join().unwrap();
    assert_eq!(envs.len(), 2);
    assert_eq!(envs[0].lamport, 1);
    assert_eq!(envs[1].lamport, 2);
}

#[cfg(feature = "net")]
#[test]
fn transport_unknown_ack_is_error_and_outbox_keeps_pending() {
    use std::net::TcpListener;
    // Server that echoes a valid frame then replies with unknown ack=5.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        // Read one frame (length + body)
        let mut len = [0u8; 4];
        s.read_exact(&mut len).unwrap();
        let n = u32::from_le_bytes(len) as usize;
        let mut body = vec![0u8; n];
        s.read_exact(&mut body).unwrap();
        // Send unknown ack
        s.write_all(&[5u8]).unwrap();
        s.flush().unwrap();
    });
    let outbox_path = tmp("outbox-unknown.jsonl");
    let _ = std::fs::remove_file(&outbox_path);
    let mut c = ductei_core::transport::TcpClient::connect(addr).unwrap().with_outbox_path(&outbox_path);
    let e = env("u", &["qallow.semantic.cert"], 1, 1);
    let res = c.send_envelope(&e);
    assert!(res.is_err(), "unknown ack must not be treated as success");
    server.join().unwrap();
    // Pending should include this envelope (unknown ack does not resolve)
    let ob = ductei_core::outbox::Outbox::open(&outbox_path).unwrap();
    let pending = ob.pending().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].key, "u");
}

#[cfg(feature = "net")]
#[test]
fn transport_outbox_intent_and_unknown_receipt_on_io_error() {
    use std::net::TcpListener;
    // Server accepts then drops immediately to force I/O error after connect.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (s, _) = listener.accept().unwrap();
        drop(s);
    });
    let outbox_path = tmp("outbox-ioerr.jsonl");
    let _ = std::fs::remove_file(&outbox_path);
    let mut c = ductei_core::transport::TcpClient::connect(addr).unwrap().with_outbox_path(&outbox_path);
    let e = env("w", &["qallow.semantic.cert"], 1, 1);
    let res = c.send_envelope(&e);
    assert!(res.is_err(), "I/O error after connect must surface as error");
    server.join().unwrap();
    let ob = ductei_core::outbox::Outbox::open(&outbox_path).unwrap();
    // Intent recorded
    let pending = ob.pending().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].key, "w");
}

#[cfg(feature = "net")]
#[test]
fn local_fallback_only_on_connect_failure() {
    use std::net::TcpListener;
    // Local channel to confirm no fallback append happens when connect succeeds
    let p = tmp("t5lf.jsonl"); let r = tmp("t5lfr.jsonl");
    let _ = std::fs::remove_file(&p);
    let mut local = Channel::open(ScopePolicy::new().allow("qallow.semantic.cert"), &p, &r).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    // Server accepts then immediately drops the connection (no ack).
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        drop(stream); // close without reading/writing
    });

    let e = env("a", &["qallow.semantic.cert"], 1, 1);
    let res = ductei_core::transport::send_local_first(addr, &e, &mut local);
    assert!(res.is_err(), "must not LocalFallback after successful connect+I/O error");
    server.join().unwrap();
    let (envs, _) = local.replay(0).unwrap();
    assert!(envs.is_empty(), "no local fallback append expected");
}

#[test]
fn outbox_restart_recovery_of_intents_and_receipts() {
    use ductei_core::outbox::Outbox;
    let path = tmp("outbox.jsonl");
    let _ = std::fs::remove_file(&path);
    let e = env("o", &["qallow.semantic.cert"], 7, 42);
    // Record intent, verify it's pending
    {
        let mut ob = Outbox::open(&path).unwrap();
        ob.record_intent(&e).unwrap();
        let pending = ob.pending().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].key, "o");
    }
    // Record a successful receipt (ack 1), verify no pending after reopen
    {
        let mut ob = Outbox::open(&path).unwrap();
        ob.record_receipt(&e.key, e.lamport, &e.node_id, 1).unwrap();
    }
    {
        let ob = Outbox::open(&path).unwrap();
        let pending = ob.pending().unwrap();
        assert!(pending.is_empty());
    }
}

// ---- Build 2: VEYN adapter end-to-end (synthetic OSC/EEG sample) ----

#[cfg(feature = "net")]
#[test]
fn veyn_event_flows_gate_transport_qallow() {
    let p = tmp("t6.jsonl"); let r = tmp("t6r.jsonl");
    let _ = std::fs::remove_file(&p);
    let json = r#"{"source":"osc.eeg","kind":"eeg.sample","node_hex":"0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
                   "lamport":42,"payload":{"ch":[1.2,3.4],"band":"theta"}}"#;
    let e = ductei_veyn::event_to_envelope(json).unwrap();
    assert_eq!(e.scopes[0].0, "veyn.sensor.eeg");

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let e2 = e.clone();
    let server = std::thread::spawn(move || {
        let mut ch = Channel::open(ScopePolicy::new().allow("veyn.sensor.eeg"), &p, &r).unwrap();
        let (s, _) = listener.accept().unwrap();
        serve_connection(s, &mut ch).unwrap();
        let (envs, _) = ch.replay(0).unwrap();
        envs
    });
    let mut c = TcpClient::connect(addr).unwrap();
    assert!(c.send_envelope(&e2).unwrap());
    drop(c);
    let envs = server.join().unwrap();
    assert_eq!(envs.len(), 1);

    let wire = ductei_qallow::encode_envelope(&envs[0]);
    assert_eq!(wire[0], ductei_qallow::F_ENVELOPE);
    let back = ductei_qallow::decode_envelope_body(&wire[5..]).unwrap();
    assert_eq!(back, envs[0]);

    // Qallow-side ingestion seam: the real ql_persist_merge_blob() lives in
    // the Qallow repo and doesn't exist yet, but the call site does, and a
    // local stand-in proves "envelope decoded -> merge called" end-to-end.
    let mut sink = ductei_qallow::ingest::MemorySink::default();
    ductei_qallow::ingest::ingest_envelope(&mut sink, &back).unwrap();
    assert_eq!(sink.merged, vec![(back.key.clone(), back.blob.clone())]);
}

// ---- QSW proto v2: scopes as native wire field ----

#[test]
fn qsw_v2_roundtrip_multi_scope() {
    let e = env("k", &["qallow.semantic.cert", "veyn.sensor.eeg"], 9, 7);
    let wire = ductei_qallow::v2::encode_envelope(&e);
    assert_eq!(wire[0], ductei_qallow::F_ENVELOPE);
    let back = ductei_qallow::v2::decode_envelope_body(&wire[5..]).unwrap();
    assert_eq!(back, e);
}

#[test]
fn qsw_v2_survives_comma_in_scope_name() {
    // v1's key-prefix shim joins scopes with ',' and would corrupt a scope
    // name containing a comma; v2's length-prefixed native field does not.
    let e = env("k", &["weird,scope"], 1, 1);
    let wire = ductei_qallow::v2::encode_envelope(&e);
    let back = ductei_qallow::v2::decode_envelope_body(&wire[5..]).unwrap();
    assert_eq!(back.scopes[0].0, "weird,scope");
}

// ---- Phase 3: VEYN adapter (narrow scopes, coalescing policy) ----

fn veyn_json(source: &str, kind: &str, lamport: u64) -> String {
    veyn_json_node(source, kind, lamport, "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a")
}

fn veyn_json_node(source: &str, kind: &str, lamport: u64, node_hex: &str) -> String {
    format!(
        r#"{{"source":"{source}","kind":"{kind}","node_hex":"{node_hex}","lamport":{lamport},"payload":{{}}}}"#
    )
}

#[test]
fn veyn_rem_and_hrv_get_narrow_scopes() {
    assert_eq!(ductei_veyn::scope_for("osc.eeg", "rem.detected"), ductei_veyn::REM_EVENT_SCOPE);
    assert_eq!(ductei_veyn::scope_for("watch", "hrv"), ductei_veyn::HRV_SCOPE);
    // Unrelated kinds still fall back to the broader per-source scope.
    assert_eq!(ductei_veyn::scope_for("osc.eeg", "eeg.sample"), ductei_veyn::EEG_SCOPE);

    let e = ductei_veyn::event_to_envelope(&veyn_json("osc.eeg", "rem.detected", 1)).unwrap();
    assert_eq!(e.scopes[0].0, "veyn.rem_event");

    // The real VEYN EEG adapter reports source "eeg", not "osc.eeg".
    assert_eq!(ductei_veyn::scope_for("eeg", "delta_absolute"), ductei_veyn::EEG_SCOPE);
}

#[test]
fn veyn_distinct_devices_same_metric_dont_collide_in_gate() {
    // Two BLE heart-rate straps report the same (source, kind). Device A's
    // lamport (its own event ts) racing ahead of device B's must not
    // stale-reject B's legitimate, independent stream -- each device is
    // its own causal-gate key.
    let mut g = CausalGate::new();
    let a1 = ductei_veyn::event_to_envelope(&veyn_json_node(
        "ble", "heart_rate", 1_000, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ))
    .unwrap();
    let b1 = ductei_veyn::event_to_envelope(&veyn_json_node(
        "ble", "heart_rate", 100, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    ))
    .unwrap();
    assert_eq!(g.admit(&a1), Verdict::Accept);
    // Device B's much smaller lamport must still be accepted: it's a
    // different device, not a stale resend of device A's stream.
    assert_eq!(g.admit(&b1), Verdict::Accept);
}

#[test]
fn veyn_hrv_coalesced_to_one_per_minute() {
    let mut a = ductei_veyn::Adapter::new(ductei_veyn::CoalescePolicy::default_policy());
    let mut accepted = 0;
    // Simulate VEYN seeing HRV at 1 Hz for ~125 seconds.
    for i in 0..125u64 {
        let json = veyn_json("watch", "hrv", i);
        if a.ingest(&json, i * 1000).unwrap().is_some() {
            accepted += 1;
        }
    }
    // Admitted at t=0, 60_000, 120_000ms: raw firehose stays in VEYN,
    // DUCTEI only sees the throttled 1/min stream.
    assert_eq!(accepted, 3);
}

// ---- gRPC / QUIC transport, ML-KEM key exchange (feature-gated) ----

#[cfg(feature = "grpc")]
#[test]
fn grpc_two_node_loopback() {
    use ductei_core::transport::Transport;
    let p = tmp("g0.jsonl");
    let r = tmp("g0r.jsonl");
    let _ = std::fs::remove_file(&p);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener); // release the port; grpc server binds it itself

    let server = std::thread::spawn(move || {
        let ch = Channel::open(ScopePolicy::new().allow("qallow.semantic.cert"), &p, &r).unwrap();
        serve_grpc_blocking(addr, ch)
    });
    // Give the server a moment to bind before the client connects.
    std::thread::sleep(std::time::Duration::from_millis(200));

    let mut c = GrpcClient::connect(&addr.to_string()).unwrap();
    assert!(c.send_envelope(&env("a", &["qallow.semantic.cert"], 1, 1)).unwrap());
    // Scope-denied must be a rejection (false)
    assert!(!c.send_envelope(&env("b", &["limen.credentials"], 1, 2)).unwrap());
    drop(c);
    drop(server); // detach; serve_grpc_blocking runs until the process exits
}

#[cfg(feature = "grpc")]
#[test]
fn grpc_stale_duplicate_is_success() {
    use ductei_core::transport::Transport;
    let p = tmp("g1.jsonl");
    let r = tmp("g1r.jsonl");
    let _ = std::fs::remove_file(&p);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let server = std::thread::spawn(move || {
        let ch = Channel::open(ScopePolicy::new().allow("qallow.semantic.cert"), &p, &r).unwrap();
        serve_grpc_blocking(addr, ch)
    });
    std::thread::sleep(std::time::Duration::from_millis(200));
    let mut c = GrpcClient::connect(&addr.to_string()).unwrap();
    // First apply
    assert!(c.send_envelope(&env("a", &["qallow.semantic.cert"], 1, 1)).unwrap());
    // Duplicate should be treated as successful receipt (ack 2)
    assert!(c.send_envelope(&env("a", &["qallow.semantic.cert"], 1, 1)).unwrap());
    drop(c);
    drop(server);
}

#[cfg(feature = "quic")]
#[test]
fn quic_two_node_loopback() {
    use ductei_core::quic::{generate_self_signed, serve_quic_blocking, QuicClient};
    use ductei_core::transport::Transport;

    let p = tmp("q0.jsonl");
    let r = tmp("q0r.jsonl");
    let _ = std::fs::remove_file(&p);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let signed = generate_self_signed("localhost").unwrap();
    let cert_der = signed.cert_der.clone();
    let server = std::thread::spawn(move || {
        let ch = Channel::open(ScopePolicy::new().allow("qallow.semantic.cert"), &p, &r).unwrap();
        serve_quic_blocking(addr, signed, ch)
    });
    std::thread::sleep(std::time::Duration::from_millis(200));

    let mut c = QuicClient::connect(addr, "localhost", &cert_der).unwrap();
    assert!(c.send_envelope(&env("a", &["qallow.semantic.cert"], 1, 1)).unwrap());
    assert!(!c.send_envelope(&env("b", &["limen.credentials"], 1, 2)).unwrap());
    drop(c);
    drop(server);
}

#[cfg(feature = "pq")]
#[test]
fn mlkem_shared_secret_agreement() {
    let pair = ductei_core::pq::generate_keypair();
    let (ciphertext, sender_secret) = ductei_core::pq::encapsulate_to(&pair.public_key).unwrap();
    let receiver_secret = ductei_core::pq::decapsulate_from(&pair, &ciphertext).unwrap();
    assert_eq!(sender_secret, receiver_secret);
}

#[test]
fn veyn_rem_events_pass_uncoalesced() {
    let mut a = ductei_veyn::Adapter::new(ductei_veyn::CoalescePolicy::default_policy());
    let mut accepted = 0;
    // REM triggers are discrete events, not a sampled stream -- even at
    // high simulated frequency, none should be dropped.
    for i in 0..50u64 {
        let json = veyn_json("osc.eeg", "rem.detected", i);
        if a.ingest(&json, i * 10).unwrap().is_some() {
            accepted += 1;
        }
    }
    assert_eq!(accepted, 50);
}
