use atrium_ctl::*;
use std::fs;
use std::path::PathBuf;

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("atrium-ctl-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn cfg(state: &std::path::Path, rooms: &str, verify: &str) -> Config {
    let t = format!("state = {:?}\ntick_ms = 10\nbeat_every = 3\n{rooms}\n{verify}", state.to_string_lossy());
    toml::from_str::<Config>(&t).unwrap()
}

#[cfg(windows)]
const SLEEPER: (&str, &[&str]) = ("cmd.exe", &["/c", "ping -n 30 127.0.0.1 > NUL"]);
#[cfg(not(windows))]
const SLEEPER: (&str, &[&str]) = ("sleep", &["30"]);

#[test]
fn config_rejects_bad_rooms() {
    let s = tmp("cfg");
    let bad = format!("state = {:?}\n[[room]]\nname = \"x\"\nkind = \"managed\"\n", s.to_string_lossy());
    assert!(toml::from_str::<Config>(&bad).unwrap().validate().is_err(), "managed without exe");
    let bad = format!("state = {:?}\n[[room]]\nname = \"x\"\n[[room]]\nname = \"x\"\nprocess = \"a\"\n", s.to_string_lossy());
    assert!(toml::from_str::<Config>(&bad).unwrap().validate().is_err(), "duplicate");
    let bad = format!("state = {:?}\n[[room]]\nname = \"x\"\nprocess = \"a\"\n[[room]]\nname = \"y\"\nkind = \"managed\"\nexe = \"a\"\nrequires = [\"nope\"]\n", s.to_string_lossy());
    assert!(toml::from_str::<Config>(&bad).unwrap().validate().is_err(), "unknown dependency");
}

#[test]
fn external_down_then_managed_blocked_then_runs() {
    let s = tmp("run");
    let rooms = format!(
        "[[room]]\nname = \"ghost\"\nprocess = \"no-such-process-xyz.exe\"\n\
         [[room]]\nname = \"child\"\nkind = \"managed\"\nexe = {:?}\nargs = {:?}\nrequires = [\"ghost\"]\n\
         [[room]]\nname = \"free\"\nkind = \"managed\"\nexe = {:?}\nargs = {:?}\n",
        SLEEPER.0, SLEEPER.1, SLEEPER.0, SLEEPER.1);
    let mut sup = Supervisor::open(cfg(&s, &rooms, "")).unwrap();
    sup.tick().unwrap();
    let st = Status::load(&s).unwrap();
    assert_eq!(st.rooms["ghost"].health, Health::Down);
    assert_eq!(st.rooms["child"].health, Health::Blocked, "dependency gate holds");
    assert_eq!(st.rooms["free"].health, Health::Up);
    assert!(st.rooms["free"].pid.is_some());
    assert!(s.join("logs").join("free.log").exists());
    // Beats: three more ticks must add a receipt per room (beat_every = 3).
    let seq0 = Status::load(&s).unwrap().chain_seq;
    for _ in 0..3 { sup.tick().unwrap(); }
    let seq1 = Status::load(&s).unwrap().chain_seq;
    assert!(seq1 >= seq0 + 3, "beats recorded: {seq0} -> {seq1}");
    sup.shutdown().unwrap();
    let st = Status::load(&s).unwrap();
    assert_eq!(st.rooms["free"].health, Health::Down);
    assert!(!s.join("pids.json").exists());
    // The chain verifies with atrium's own scope rule.
    let trust = VerifyTrust { pubkey: None, fingerprint: None, allow_unpinned: true, anchors: Vec::new(), pinned_head: None };
    let rep = verify_own_chain(&s, &trust).unwrap();
    assert!(rep.ok(), "{:?}", rep.errors);
    assert!(rep.receipts >= 5);
}

#[test]
fn managed_restarts_with_backoff() {
    let s = tmp("restart");
    #[cfg(windows)]
    let rooms = "[[room]]\nname = \"flaky\"\nkind = \"managed\"\nexe = \"cmd.exe\"\nargs = [\"/c\", \"exit 7\"]\n";
    #[cfg(not(windows))]
    let rooms = "[[room]]\nname = \"flaky\"\nkind = \"managed\"\nexe = \"sh\"\nargs = [\"-c\", \"exit 7\"]\n";
    let mut sup = Supervisor::open(cfg(&s, rooms, "")).unwrap();
    sup.tick().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(300));
    sup.tick().unwrap();
    let st = Status::load(&s).unwrap();
    assert!(st.rooms["flaky"].note.contains("exit 7"), "{}", st.rooms["flaky"].note);
    assert_eq!(st.rooms["flaky"].health, Health::Down);
    // First spawn is a start (restarts 0); no respawn inside the backoff window.
    assert_eq!(st.rooms["flaky"].restarts, 0, "not respawned inside the backoff window");
    sup.shutdown().unwrap();
}

#[test]
fn verify_steps_chain_and_fail_closed() {
    let s = tmp("verify");
    #[cfg(windows)]
    let v = "[[verify]]\nname = \"ok\"\ncmd = [\"cmd.exe\", \"/c\", \"echo hello\"]\nexpect_text = \"hello\"\n\
             [[verify]]\nname = \"bad\"\ncmd = [\"cmd.exe\", \"/c\", \"exit 3\"]\n";
    #[cfg(not(windows))]
    let v = "[[verify]]\nname = \"ok\"\ncmd = [\"sh\", \"-c\", \"echo hello\"]\nexpect_text = \"hello\"\n\
             [[verify]]\nname = \"bad\"\ncmd = [\"sh\", \"-c\", \"exit 3\"]\n";
    let mut sup = Supervisor::open(cfg(&s, "", v)).unwrap();
    let mut seen = Vec::new();
    let (pass, fail) = sup.run_verify(|n, ok, _| seen.push((n.to_string(), ok))).unwrap();
    assert_eq!((pass, fail), (2, 1));
    assert_eq!(seen, vec![("ok".into(), true), ("bad".into(), false), ("atrium-chain".into(), true)]);
    // Tamper: flip a byte in receipts.jsonl, open must refuse to extend.
    let p = s.join("receipts.jsonl");
    let mut b = fs::read(&p).unwrap();
    let i = b.iter().position(|c| *c == b'"').unwrap() + 20;
    b[i] = if b[i] == b'a' { b'b' } else { b'a' };
    fs::write(&p, b).unwrap();
    assert!(Supervisor::open(cfg(&s, "", v)).is_err(), "damaged chain must not be extended");
}

#[test]
fn status_store_is_atomic_and_live_detection() {
    let s = tmp("status");
    let ten = std::time::Duration::from_secs(10);
    let mut st = Status { unix: now_unix(), supervisor_pid: 0, ..Default::default() };
    st.store(&s).unwrap();
    assert!(!s.join("status.json.tmp").exists());
    assert!(!Status::load(&s).unwrap().live(ten), "pid 0 = clean shutdown");
    st.supervisor_pid = std::process::id();
    st.store(&s).unwrap();
    assert!(!Status::load(&s).unwrap().live(ten), "the caller never counts as another supervisor");
    st.supervisor_pid = 999_999;
    st.store(&s).unwrap();
    assert!(!Status::load(&s).unwrap().live(ten), "dead pid");
    st.unix = now_unix() - 100;
    st.store(&s).unwrap();
    assert!(!Status::load(&s).unwrap().live(ten), "stale status is not live");
}

#[test]
fn shutdown_marks_supervisor_stopped() {
    let s = tmp("down");
    let mut sup = Supervisor::open(cfg(&s, "[[room]]\nname = \"x\"\nfresh_file = \"nope\"\n", "")).unwrap();
    sup.tick().unwrap();
    assert_eq!(Status::load(&s).unwrap().supervisor_pid, std::process::id());
    sup.shutdown().unwrap();
    assert_eq!(Status::load(&s).unwrap().supervisor_pid, 0);
}