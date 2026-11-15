// Copyright (C) 2026 xingxerx
// Licensed under the Elastic License 2.0. See the LICENSE file in this crate.

//! The job door against real QHR state on disk. limend is faked by a thread
//! that follows the spool contract (same pattern as ductei-qhr/tests/qpu.rs);
//! the live LIMEN and Qallow hops are covered by ops\os_probe.ps1.

use atrium_os::{exit_code, parse_request, spec, verify_receipt, JobRequest, Os, OsConfig, PersistCfg};
use ductei_mcp::VerifyTrust;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const SMOKE_QUBO: &str = r#"{"qubo":[[["hub","leaf0"],2.0],[["leaf0","leaf0"],-1.0],[["hub","leaf1"],2.0],[["leaf1","leaf1"],-1.0],[["hub","hub"],-1.0]],"credit_budget":0.0,"fidelity_target":0.9,"offline":true}"#;

fn dir(name: &str) -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("os-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    for sub in ["state", "spool/pending", "spool/certs", "spool/failed", "spool/done"] { std::fs::create_dir_all(d.join(sub)).unwrap(); }
    d
}

fn cfg(d: &Path, persist: bool) -> OsConfig {
    OsConfig {
        state: d.join("state"),
        spool: Some(d.join("spool")),
        persist: persist.then(|| PersistCfg { channel: d.join("os").join("ductei"), qallow_relay: None, qallow_cli: None, store: None, out: None }),
        pubkey_fingerprint: None,
        anchor: None,
        llm: false,
        weighter: "uniform".into(),
    }
}

fn req(id: &str, op: &str, payload: &str) -> JobRequest {
    JobRequest { id: id.into(), intent: "os test".into(), op: op.into(), payload: payload.into(), budget_ms: 3_000, kind: None, private: None, assurance: None, effects_json: None }
}

fn unpinned() -> VerifyTrust { VerifyTrust { allow_unpinned: true, ..Default::default() } }

/// Pretends to be limend: turns each pending request into a cert.
fn fake_limend(spool: PathBuf, stop_after: Duration) {
    std::thread::spawn(move || {
        let t = Instant::now();
        while t.elapsed() < stop_after {
            for e in std::fs::read_dir(spool.join("pending")).unwrap().filter_map(Result::ok) {
                let p = e.path();
                if p.extension().is_none_or(|x| x != "json") { continue; }
                let id = p.file_stem().unwrap().to_string_lossy().to_string();
                let cert = format!(r#"{{"job_id":"{id}","backend":"statevector","tier":0,"success_probability":0.178,"fidelity_target":0.9,"target_met":false,"lamport":1}}"#);
                if std::fs::rename(&p, spool.join("done").join(format!("{id}.json"))).is_ok() { std::fs::write(spool.join("certs").join(format!("{id}.json")), cert).unwrap(); }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    });
}

#[test]
fn a_done_job_returns_a_receipt_that_verifies() {
    let d = dir("done");
    let c = cfg(&d, false);
    let r = req("j-done", "cpu.sha256", "abc");
    let rc = Os::open(c.clone()).unwrap().submit(&r, &[]).unwrap();
    assert_eq!((rc.verdict.as_str(), rc.lane.as_deref(), rc.tier.as_str(), rc.chain.as_str()), ("done", Some("cpu"), "t0_local", "verified"));
    assert_eq!((rc.reason.as_deref(), exit_code(&rc)), (None, spec::OS_EXIT_DONE));
    assert_eq!(rc.persist_state, spec::OS_PERSIST_NONE);
    assert!(rc.persist_reason.as_deref().unwrap().contains("no [os.persist]"), "an unpersisted receipt says why");
    let checked = verify_receipt(&c, &rc, Some(&r), &unpinned()).unwrap();
    assert_eq!((checked.seq, checked.chain_receipts), (0, 1));
}

#[test]
fn a_changed_receipt_or_a_different_job_is_caught() {
    let d = dir("tamper");
    let c = cfg(&d, false);
    let r = req("j-tamper", "cpu.sha256", "abc");
    let rc = Os::open(c.clone()).unwrap().submit(&r, &[]).unwrap();
    let fails = |rc: &atrium_os::JobReceipt, r: &JobRequest, needle: &str| {
        let errs = verify_receipt(&c, rc, Some(r), &unpinned()).unwrap_err();
        assert!(errs.iter().any(|e| e.contains(needle)), "wanted {needle:?} in {errs:?}");
    };

    let mut v = rc.clone(); v.verdict = "refused".into();
    fails(&v, &r, "verdict");
    let mut s = rc.clone(); s.status_json = r#"{"status":"done","detail":"something else"}"#.into();
    fails(&s, &r, "do not hash to the signed result hash");
    let mut b = rc.clone(); b.backend = Some("ibm_fez".into());
    fails(&b, &r, "summary fields");
    let mut h = rc.clone(); h.qhr_receipt = "0".repeat(64);
    fails(&h, &r, "no entry with hash");
    fails(&rc, &req("j-tamper", "cpu.sha256", "abd"), "not the job this receipt was issued for");
    let mut ch = rc.clone(); ch.chain = "../verified".into();
    fails(&ch, &r, "unknown chain");
}

#[test]
fn an_unsafe_job_is_denied_with_a_reason_and_still_receipted() {
    let d = dir("unsafe");
    let c = cfg(&d, false);
    let mut r = req("j-unsafe", "cpu.echo", "hi");
    r.effects_json = Some(r#"[{"type":"write","target":"C:\\probe.txt"}]"#.into());
    let rc = Os::open(c.clone()).unwrap().submit(&r, &[]).unwrap();
    assert_eq!((rc.verdict.as_str(), rc.lane.as_deref(), exit_code(&rc)), ("denied", None, spec::OS_EXIT_REFUSED));
    assert!(!rc.reason.as_deref().unwrap_or("").is_empty(), "a denial carries its reason");
    verify_receipt(&c, &rc, Some(&r), &unpinned()).unwrap();
}

#[test]
fn an_oversized_qubo_is_refused_in_preflight_and_never_spooled() {
    let d = dir("big");
    let c = cfg(&d, false);
    let terms: Vec<String> = (0..65).map(|i| format!(r#"[["x{i}","x{i}"],-1.0]"#)).collect();
    let payload = format!(r#"{{"qubo":[{}],"credit_budget":0.0,"fidelity_target":0.9,"offline":true}}"#, terms.join(","));
    let mut r = req("j-big", "qpu.run", &payload);
    r.budget_ms = 120_000;
    let rc = Os::open(c.clone()).unwrap().submit(&r, &[]).unwrap();
    assert_eq!((rc.verdict.as_str(), rc.lane.as_deref(), exit_code(&rc)), ("refused", Some("qpu"), spec::OS_EXIT_REFUSED));
    assert!(rc.reason.as_deref().unwrap().contains("exceeds the lane ceiling"), "{:?}", rc.reason);
    assert_eq!(std::fs::read_dir(d.join("spool/pending")).unwrap().count(), 0, "a refused job never reaches limend");
    verify_receipt(&c, &rc, Some(&r), &unpinned()).unwrap();
}

#[test]
fn a_job_id_that_is_not_a_file_name_is_refused_at_the_door() {
    let d = dir("id");
    let mut os = Os::open(cfg(&d, false)).unwrap();
    for bad in ["..\\..\\evil", "../evil", "a/b", "", ".hidden", "nul", "COM1.x", "sp ace"] {
        let e = os.submit(&req(bad, "qpu.run", SMOKE_QUBO), &[]).unwrap_err();
        assert!(e.contains("not a safe file name"), "{bad:?}: {e}");
    }
    assert!(!d.join("evil.json").exists() && !d.join("spool").join("evil.json").exists());
    assert_eq!(std::fs::read_dir(d.join("spool/pending")).unwrap().count(), 0);
}

#[test]
fn a_qpu_job_round_trips_and_the_cert_fills_the_summary() {
    let d = dir("qpu");
    fake_limend(d.join("spool"), Duration::from_secs(10));
    let c = cfg(&d, true);
    let mut r = req("j-qpu", "qpu.run", SMOKE_QUBO);
    r.budget_ms = 60_000; // above the lane's 30 s queue estimate; the fake answers in milliseconds
    let rc = Os::open(c.clone()).unwrap().submit(&r, &[]).unwrap();
    assert_eq!((rc.verdict.as_str(), rc.lane.as_deref()), ("done", Some("qpu")), "{:?}", rc.reason);
    assert_eq!((rc.backend.as_deref(), rc.success_probability, rc.target_met), (Some("statevector"), Some(0.178), Some(false)));
    assert_eq!(rc.persist_state, spec::OS_PERSIST_CHANNEL);
    assert_eq!(rc.persist_key.as_deref(), Some("atrium.os.receipt.j-qpu"));
    assert!(rc.persist_reason.as_deref().unwrap().contains("no Qallow hop"), "{:?}", rc.persist_reason);
    verify_receipt(&c, &rc, Some(&r), &unpinned()).unwrap();

    // A receipt that survives a JSON round trip (the file the caller keeps) still verifies.
    let kept: atrium_os::JobReceipt = serde_json::from_str(&serde_json::to_string_pretty(&rc).unwrap()).unwrap();
    verify_receipt(&c, &kept, None, &unpinned()).unwrap();

    // The persisted copy is checked, not assumed: point at an empty channel and it fails.
    let mut elsewhere = c.clone();
    elsewhere.persist.as_mut().unwrap().channel = d.join("os").join("empty");
    let errs = verify_receipt(&elsewhere, &rc, None, &unpinned()).unwrap_err();
    assert!(errs.iter().any(|e| e.contains("not in the DUCTEI channel log")), "{errs:?}");
}

#[test]
fn a_pin_refuses_an_unsigned_chain() {
    let d = dir("pin");
    let c = cfg(&d, false);
    let r = req("j-pin", "cpu.echo", "hi");
    let rc = Os::open(c.clone()).unwrap().submit(&r, &[]).unwrap();
    assert_eq!((rc.sig_scheme.as_str(), rc.signer_fingerprint.as_deref()), ("none", None));
    let pin = VerifyTrust { fingerprint: Some("ab".repeat(32)), ..Default::default() };
    let errs = verify_receipt(&c, &rc, None, &pin).unwrap_err();
    assert!(errs.iter().any(|e| e.contains("not signed by the pinned key")), "{errs:?}");
    assert!(errs.iter().any(|e| e.contains("this chain entry is unsigned")), "{errs:?}");

    // And the door will not open unsigned when the config pins a key.
    let mut pinned = c.clone();
    pinned.pubkey_fingerprint = Some("ab".repeat(32));
    assert!(Os::open(pinned).err().unwrap().contains("refusing to run unsigned"));
}

#[test]
fn job_files_accept_json_payloads_and_refuse_unknown_fields() {
    let r = parse_request(r#"{"id":"a","intent":"i","op":"qpu.run","budget_ms":5,"payload":{"qubo":[],"offline":true},"effects":[{"type":"push"}]}"#).unwrap();
    let payload: serde_json::Value = serde_json::from_str(&r.payload).expect("an object payload becomes JSON text");
    assert_eq!(payload, serde_json::json!({"qubo": [], "offline": true}));
    assert_eq!(r.effects_json.as_deref(), Some(r#"[{"type":"push"}]"#));
    assert!(parse_request(r#"{"id":"a","intent":"i","op":"x","budget_ms":5,"payload":"","budgetms":9}"#).unwrap_err().contains("unknown job field"));
    assert!(parse_request("\u{feff}{\"id\":\"a\",\"intent\":\"i\",\"op\":\"x\",\"budget_ms\":5,\"payload\":\"p\"}").is_ok(), "a BOM from PowerShell is tolerated");
    assert!(parse_request(r#"{"id":"a","intent":"i","op":"x","budget_ms":5,"payload":"p","effects":[],"effects_json":"[]"}"#).is_err());
}

#[test]
fn the_os_table_ignores_other_rooms_and_refuses_its_own_typos() {
    let ok = OsConfig::parse("state = \"D:/x\"\n[sign]\nscheme = \"ml-dsa-65\"\n[[room]]\nname = \"ward\"\n[os]\nstate = \"D:/os/state\"\n[os.persist]\nchannel = \"D:/os/ductei\"\n").unwrap();
    assert_eq!(ok.state, PathBuf::from("D:/os/state"));
    assert_eq!(ok.weighter, "uniform");
    assert!(OsConfig::parse("[os]\nstate = \"D:/x\"\nspol = \"D:/y\"\n").unwrap_err().contains("spol"));
    assert!(OsConfig::parse("[sign]\nscheme = \"none\"\n").is_err(), "no [os] table is an error, not a default");
    let on_c = OsConfig::parse("[os]\nstate = \"C:/Users/x/state\"\n").unwrap();
    assert!(on_c.canon_paths().unwrap_err().contains("state refused"));
}

#[test]
fn health_reports_every_room_and_never_creates_anything() {
    let d = dir("health");
    let mut c = cfg(&d, false);
    c.state = d.join("not-yet");
    let h = atrium_os::health(&c);
    let rooms: Vec<(&str, u8)> = h.iter().map(|x| (x.room.as_str(), x.state)).collect();
    assert_eq!(rooms, vec![("os.state", atrium_os::base::HEALTH_DEGRADED), ("os.limen", atrium_os::base::HEALTH_OK), ("os.persist", atrium_os::base::HEALTH_DEGRADED)]);
    assert!(h.iter().all(|x| x.state == atrium_os::base::HEALTH_OK || x.reason.is_some()), "N5: anything not OK says why");
    assert!(!c.state.exists(), "health is read-only");
    c.spool = Some(d.join("no-spool"));
    assert_eq!(atrium_os::health(&c)[1].state, atrium_os::base::HEALTH_DOWN);
}

/// Signed path: ML-DSA-65 key minted under DPAPI, receipt verified under its
/// own pin, refused under any other.
#[cfg(all(feature = "sign", windows))]
#[test]
fn a_signed_receipt_verifies_under_its_pin_and_fails_under_another() {
    let d = dir("signed");
    std::fs::write(d.join("state").join("sign.toml"), "scheme = \"ml-dsa-65\"\nkey_store = \"dpapi\"\n").unwrap();
    let c = cfg(&d, true);
    let r = req("j-signed", "cpu.sha256", "abc");
    let rc = Os::open(c.clone()).unwrap().submit(&r, &[]).unwrap();
    let fp = rc.signer_fingerprint.clone().expect("a signed receipt names its key");
    assert_eq!((rc.sig_scheme.as_str(), fp.len()), ("ml-dsa-65", 64));

    let pin = VerifyTrust { fingerprint: Some(fp.clone()), ..Default::default() };
    let checked = verify_receipt(&c, &rc, Some(&r), &pin).unwrap();
    assert_eq!(checked.kid.as_deref(), Some(fp.as_str()));

    let other = VerifyTrust { fingerprint: Some("cd".repeat(32)), ..Default::default() };
    assert!(verify_receipt(&c, &rc, Some(&r), &other).is_err());

    // The config pin is enforced when the door opens.
    let mut good = c.clone(); good.pubkey_fingerprint = Some(fp.to_uppercase());
    assert!(Os::open(good).is_ok());
    let mut bad = c.clone(); bad.pubkey_fingerprint = Some("cd".repeat(32));
    assert!(Os::open(bad).err().unwrap().contains("is not the key [os] pins"));
}

fn anchored(d: &Path, peers: &[&str]) -> OsConfig {
    let mut c = cfg(d, false);
    c.anchor = Some(atrium_os::OsAnchorCfg {
        dir: d.join("os").join("anchor"),
        peers: peers.iter().map(|p| p.to_string()).collect(),
        identity: None,
        encrypt: false,
        connect_timeout_ms: 300,
        files: vec![],
        server: "atrium".into(),
    });
    c
}

#[test]
fn every_job_anchors_the_chain_head_and_a_cut_tail_is_caught() {
    let d = dir("anchor");
    let c = anchored(&d, &[]);
    let mut os = Os::open(c.clone()).unwrap();
    let first = os.submit(&req("a-1", "cpu.echo", "one"), &[]).unwrap();
    let second = os.submit(&req("a-2", "cpu.echo", "two"), &[]).unwrap();
    drop(os);
    assert_eq!((first.anchor_seq, second.anchor_seq), (Some(0), Some(1)));
    assert!(second.anchor_reason.as_deref().unwrap().contains("this machine only"), "{:?}", second.anchor_reason);

    let ok = verify_receipt(&c, &first, None, &unpinned()).unwrap();
    assert!(!ok.warnings.iter().any(|w| w.starts_with("no anchor")), "an anchored chain is checked against its anchor: {:?}", ok.warnings);
    verify_receipt(&c, &second, None, &unpinned()).unwrap();

    // Cut the last entry off the chain. The first receipt is still intact, but
    // the anchor proves an entry after it existed.
    let log = d.join("state/verified/receipts.jsonl");
    let text = std::fs::read_to_string(&log).unwrap();
    let kept: Vec<&str> = text.lines().take(1).collect();
    std::fs::write(&log, format!("{}\n", kept[0])).unwrap();
    let errs = verify_receipt(&c, &first, None, &unpinned()).unwrap_err();
    assert!(errs.iter().any(|e| e.contains("TRUNCATED")), "{errs:?}");

    // A receipt that claims an anchor nobody wrote is refused.
    let mut lie = first.clone();
    lie.anchor_seq = Some(7);
    let errs = verify_receipt(&c, &lie, None, &unpinned()).unwrap_err();
    assert!(errs.iter().any(|e| e.contains("no anchor for it")), "{errs:?}");
}

#[test]
fn a_peer_that_is_off_is_named_then_skipped_and_never_blocks_the_job() {
    let d = dir("peerdown");
    // Loopback port 9 (discard): nothing listens, the connect is refused at once.
    let c = anchored(&d, &["127.0.0.1:9"]);
    let mut os = Os::open(c.clone()).unwrap();
    let one = os.submit(&req("p-1", "cpu.echo", "one"), &[]).unwrap();
    assert_eq!((one.verdict.as_str(), one.anchor_seq, one.anchor_peers.as_deref()), ("done", Some(0), None));
    assert!(one.anchor_reason.as_deref().unwrap().starts_with("127.0.0.1:9: "), "{:?}", one.anchor_reason);
    let two = os.submit(&req("p-2", "cpu.echo", "two"), &[]).unwrap();
    assert!(two.anchor_reason.as_deref().unwrap().contains("skipped"), "{:?}", two.anchor_reason);
    verify_receipt(&c, &two, None, &unpinned()).unwrap();
}
