//! ductei-verify: the fail-closed gate in front of ATRIUM's self-improvement loop.
//!
//! An agent output (a Candidate) becomes one of three things:
//! - rejected (any reason at all, including an error), or
//! - accepted but not trainable (it used untrusted web input), or
//! - accepted and trainable (goes to brain's adapt/ set).
//!
//! Order: kill switch and breaker, then cheap static checks, then build gates
//! (cargo check, clippy -D warnings, cargo test, extra invariant commands).
//! Build gates run only when everything before them is clean, stop at the
//! first failure, and run with a hidden window and a hard timeout. Every
//! verdict is written to a hash-chained ledger by the caller (see the bin).

pub mod checks;
pub mod ledger;
pub mod policy;
pub mod runner;

pub use checks::{adapter_gate, parse_test_counts, static_checks};
pub use ledger::{sha256_hex, Ledger, Receipt};
pub use policy::Policy;
pub use runner::{RunOut, Runner, SystemRunner};

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    pub task_id: String,
    /// Scratch checkout the change was applied to; build gates run here.
    pub worktree: String,
    #[serde(default)]
    pub changes: Vec<Change>,
    /// Every command the agent ran or asked to run for this task.
    #[serde(default)]
    pub commands: Vec<String>,
    /// Everything the agent read to produce this.
    #[serde(default)]
    pub sources: Vec<Source>,
    #[serde(default)]
    pub jlens_score: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Change {
    pub path: String,
    pub kind: ChangeKind,
    #[serde(default)]
    pub content: String,
    #[serde(default)]
    pub previous: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    Add,
    Modify,
    Delete,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub uri: String,
    pub trust: Trust,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Trust {
    Local,
    Verified,
    /// Web content: may inform retrieval, never training.
    Untrusted,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Stage {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Verdict {
    pub task_id: String,
    pub accepted: bool,
    pub train_eligible: bool,
    pub reasons: Vec<String>,
    pub stages: Vec<Stage>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct History {
    pub attempts_for_task: u32,
    pub accepts_today: u32,
}

fn tail(s: &str, n: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    chars[chars.len().saturating_sub(n)..].iter().collect()
}

pub fn verify(policy: &Policy, c: &Candidate, history: &History, runner: &mut dyn Runner) -> Verdict {
    let mut reasons: Vec<String> = Vec::new();
    let mut stages = Vec::new();

    if Path::new(&policy.breaker.kill_switch).exists() {
        reasons.push("kill switch present".into());
    }
    if history.attempts_for_task >= policy.breaker.max_attempts_per_task {
        reasons.push(format!("task hit {} attempts: needs a human", policy.breaker.max_attempts_per_task));
    }
    if history.accepts_today >= policy.breaker.max_accepts_per_day {
        reasons.push(format!("daily accept limit {} reached", policy.breaker.max_accepts_per_day));
    }
    stages.push(Stage { name: "breaker".into(), ok: reasons.is_empty(), detail: String::new() });

    let s = static_checks(policy, c);
    stages.push(Stage { name: "static".into(), ok: s.is_empty(), detail: format!("{} issue(s)", s.len()) });
    reasons.extend(s);

    if reasons.is_empty() {
        build_gates(policy, c, runner, &mut stages, &mut reasons);
    } else {
        stages.push(Stage { name: "build".into(), ok: false, detail: "skipped: earlier stage failed".into() });
    }

    let accepted = reasons.is_empty();
    let train_eligible = accepted && c.sources.iter().all(|s| s.trust != Trust::Untrusted);
    Verdict { task_id: c.task_id.clone(), accepted, train_eligible, reasons, stages }
}

fn argv(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

fn build_gates(p: &Policy, c: &Candidate, r: &mut dyn Runner, stages: &mut Vec<Stage>, reasons: &mut Vec<String>) {
    let mut plan: Vec<(String, Vec<String>)> = Vec::new();
    if p.gates.require_check {
        plan.push(("cargo_check".into(), argv(&["cargo", "check", "--all-targets"])));
    }
    if p.gates.require_clippy {
        plan.push(("cargo_clippy".into(), argv(&["cargo", "clippy", "--all-targets", "--", "-D", "warnings"])));
    }
    if p.gates.require_tests {
        plan.push(("cargo_test".into(), argv(&["cargo", "test"])));
    }
    for (i, a) in p.gates.extra.iter().enumerate() {
        plan.push((format!("extra_{i}"), a.clone()));
    }
    let cwd = Path::new(&c.worktree);
    let timeout = Duration::from_secs(p.gates.timeout_secs);
    for (name, a) in plan {
        let out = r.run(&a, cwd, timeout);
        let (mut ok, mut detail) = if out.timed_out {
            (false, format!("timed out after {}s", p.gates.timeout_secs))
        } else if out.status != Some(0) {
            (false, format!("exit {:?}: {}", out.status, tail(&out.stderr, 400)))
        } else {
            (true, "ok".into())
        };
        if ok && name == "cargo_test" {
            let (passed, failed) = parse_test_counts(&out.stdout);
            detail = format!("{passed} passed, {failed} failed");
            if failed > 0 || passed < p.gates.min_tests_passed {
                ok = false;
                detail = format!("{detail} (need 0 failed and >= {} passed)", p.gates.min_tests_passed);
            }
        }
        if !ok {
            reasons.push(format!("{name}: {detail}"));
        }
        stages.push(Stage { name, ok, detail });
        if !ok {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn scratch(name: &str) -> PathBuf {
        let d = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("target").join("verify-test").join(name);
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn policy_with(kill: &str, extra: &str) -> Policy {
        let base = include_str!("../verify.toml").replace(r"D:\ATRIUM\private\verify\STOP", kill);
        Policy::from_toml(&format!("{base}{extra}")).unwrap()
    }

    fn policy(name: &str) -> Policy {
        let k = scratch(name).join("STOP");
        policy_with(&k.to_string_lossy(), "")
    }

    fn cand() -> Candidate {
        Candidate {
            task_id: "t1".into(),
            worktree: r"D:\ATRIUM\scratch\t1".into(),
            changes: vec![Change {
                path: r"D:\ATRIUM\scratch\t1\src\lib.rs".into(),
                kind: ChangeKind::Modify,
                content: "pub fn a() -> u8 { 2 }\n#[test]\nfn t() {}\n".into(),
                previous: "pub fn a() -> u8 { 1 }\n#[test]\nfn t() {}\n".into(),
            }],
            commands: vec!["cargo test".into()],
            sources: vec![Source { uri: "file:///D:/ATRIUM".into(), trust: Trust::Local }],
            jlens_score: Some(0.9),
        }
    }

    fn ok(stdout: &str) -> RunOut {
        RunOut { status: Some(0), stdout: stdout.into(), ..Default::default() }
    }

    struct Mock {
        outs: Vec<RunOut>,
        calls: Vec<Vec<String>>,
    }
    impl Mock {
        fn passing() -> Self {
            Mock { outs: vec![ok(""), ok(""), ok("test result: ok. 3 passed; 0 failed; 0 ignored")], calls: vec![] }
        }
    }
    impl Runner for Mock {
        fn run(&mut self, a: &[String], _: &Path, _: Duration) -> RunOut {
            self.calls.push(a.to_vec());
            if self.outs.is_empty() { ok("") } else { self.outs.remove(0) }
        }
    }

    fn run(p: &Policy, c: &Candidate) -> (Verdict, Mock) {
        let mut m = Mock::passing();
        let v = verify(p, c, &History::default(), &mut m);
        (v, m)
    }

    fn has(v: &Verdict, s: &str) -> bool {
        v.reasons.iter().any(|r| r.contains(s))
    }

    #[test]
    fn clean_candidate_is_accepted_and_trainable() {
        let (v, m) = run(&policy("clean"), &cand());
        assert!(v.accepted, "{:?}", v.reasons);
        assert!(v.train_eligible);
        assert_eq!(m.calls.len(), 3);
    }

    #[test]
    fn c_drive_is_rejected_before_any_build() {
        let mut c = cand();
        c.worktree = r"C:\Users\xing\x".into();
        c.changes[0].path = r"C:\Users\xing\x\src\lib.rs".into();
        let (v, m) = run(&policy("cdrive"), &c);
        assert!(!v.accepted && has(&v, "forbidden prefix"));
        assert!(m.calls.is_empty());
    }

    #[test]
    fn traversal_git_ads_and_short_names_rejected() {
        let p = policy("paths");
        for bad in [
            r"D:\ATRIUM\scratch\t1\..\..\x.rs",
            r"D:\ATRIUM\scratch\t1\.git\config",
            r"D:\ATRIUM\scratch\t1\a.rs:evil",
            r"D:\ATRIUM\scratch\t1\PROGRA~1\a.rs",
            r"E:\other\a.rs",
            r"src\relative.rs",
        ] {
            let mut c = cand();
            c.changes[0].path = bad.into();
            assert!(!run(&p, &c).0.accepted, "{bad}");
        }
    }

    #[test]
    fn unsafe_ignore_allow_and_spawn_growth_rejected() {
        let p = policy("growth");
        for add in ["unsafe { core::hint::unreachable_unchecked() }", "#[ignore]", "#[allow(dead_code)]", "std::process::Command::new(\"x\")"] {
            let mut c = cand();
            c.changes[0].content.push_str(add);
            assert!(!run(&p, &c).0.accepted, "{add}");
        }
        let mut c = cand();
        c.changes[0].content.push_str("// not_unsafe_word\n");
        assert!(run(&p, &c).0.accepted, "whole-word unsafe check");
    }

    #[test]
    fn removing_or_deleting_tests_rejected() {
        let p = policy("tests");
        let mut c = cand();
        c.changes[0].content = "pub fn a() -> u8 { 2 }\n".into();
        assert!(has(&run(&p, &c).0, "removes tests"));
        let mut c = cand();
        c.changes[0].kind = ChangeKind::Delete;
        c.changes[0].content.clear();
        let v = run(&p, &c).0;
        assert!(has(&v, "deletion not allowed") && has(&v, "deletes tests"));
    }

    #[test]
    fn secrets_rejected_without_echoing_them() {
        let mut c = cand();
        c.changes[0].content.push_str("const K: &str = \"sk-ant-SECRET123\";");
        let v = run(&policy("secret"), &c).0;
        assert!(has(&v, "forbidden pattern #"));
        assert!(!v.reasons.iter().any(|r| r.contains("SECRET123")));
    }

    #[test]
    fn forbidden_commands_rejected() {
        let p = policy("cmds");
        for cmd in ["git push origin main", "GIT COMMIT -m x", "Remove-Item -Recurse D:\\ATRIUM", "curl http://x"] {
            let mut c = cand();
            c.commands.push(cmd.into());
            assert!(has(&run(&p, &c).0, "forbidden command"), "{cmd}");
        }
    }

    #[test]
    fn untrusted_source_accepted_but_not_trainable() {
        let mut c = cand();
        c.sources.push(Source { uri: "https://example.com".into(), trust: Trust::Untrusted });
        let v = run(&policy("untrusted"), &c).0;
        assert!(v.accepted && !v.train_eligible);
    }

    #[test]
    fn jlens_missing_or_low_or_nan_rejected() {
        let p = policy("jlens");
        for s in [None, Some(0.1), Some(f64::NAN)] {
            let mut c = cand();
            c.jlens_score = s;
            assert!(!run(&p, &c).0.accepted, "{s:?}");
        }
    }

    #[test]
    fn failing_tests_timeouts_and_lint_stop_the_chain() {
        let p = policy("build");
        let mut m = Mock { outs: vec![ok(""), ok(""), ok("test result: FAILED. 2 passed; 1 failed;")], calls: vec![] };
        assert!(!verify(&p, &cand(), &History::default(), &mut m).accepted);

        let mut m = Mock { outs: vec![ok(""), ok(""), ok("no tests ran")], calls: vec![] };
        assert!(!verify(&p, &cand(), &History::default(), &mut m).accepted, "zero tests is a reject");

        let mut m = Mock { outs: vec![RunOut { timed_out: true, ..Default::default() }], calls: vec![] };
        let v = verify(&p, &cand(), &History::default(), &mut m);
        assert!(has(&v, "timed out") && m.calls.len() == 1);

        let mut m = Mock { outs: vec![ok(""), RunOut { status: Some(101), stderr: "warning".into(), ..Default::default() }], calls: vec![] };
        let v = verify(&p, &cand(), &History::default(), &mut m);
        assert!(has(&v, "cargo_clippy") && m.calls.len() == 2);
    }

    #[test]
    fn kill_switch_and_breaker_reject() {
        let d = scratch("kill");
        let k = d.join("STOP");
        let p = policy_with(&k.to_string_lossy(), "");
        std::fs::write(&k, "").unwrap();
        assert!(has(&run(&p, &cand()).0, "kill switch"));
        std::fs::remove_file(&k).unwrap();

        let mut m = Mock::passing();
        let h = History { attempts_for_task: 5, accepts_today: 0 };
        assert!(has(&verify(&p, &cand(), &h, &mut m), "needs a human"));
        let h = History { attempts_for_task: 0, accepts_today: 50 };
        assert!(has(&verify(&p, &cand(), &h, &mut m), "daily accept limit"));
        assert!(m.calls.is_empty());
    }

    #[test]
    fn policy_floors_cannot_be_loosened() {
        let base = include_str!("../verify.toml");
        let no_push = base.replace("\"git push\", ", "");
        assert!(Policy::from_toml(&no_push).is_err());
        let c_root = base.replace(r"allowed_roots = ['D:\ATRIUM'", r"allowed_roots = ['C:\Users'");
        assert!(Policy::from_toml(&c_root).is_err());
        let no_c = base.replace(r"forbidden_prefixes = ['C:\']", "forbidden_prefixes = []");
        assert!(Policy::from_toml(&no_c).is_err());
        let typo = format!("{base}\n[typo]\nx = 1\n");
        assert!(Policy::from_toml(&typo).is_err());
    }

    #[test]
    fn ledger_chain_detects_tampering() {
        let d = scratch("ledger");
        let path = d.join("ledger.jsonl");
        let mut l = Ledger::open(&path).unwrap();
        let mut v = run(&policy("ledger-p"), &cand()).0;
        l.append(&v, "aa", 100).unwrap();
        v.accepted = false;
        l.append(&v, "bb", 200).unwrap();
        assert_eq!(Ledger::open(&path).unwrap().len(), 2);
        assert_eq!(Ledger::open(&path).unwrap().history("t1", 150).attempts_for_task, 2);

        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, text.replacen("\"accepted\":false", "\"accepted\":true", 1)).unwrap();
        assert!(Ledger::open(&path).unwrap_err().contains("tampered"));

        let first = text.lines().next().unwrap();
        std::fs::write(&path, format!("{first}\n")).unwrap();
        assert_eq!(Ledger::open(&path).unwrap().len(), 1);
    }

    #[test]
    fn adapter_gate_keeps_old_unless_better() {
        let p = policy("eval");
        assert!(adapter_gate(&p, 0.50, 0.52).is_ok());
        assert!(adapter_gate(&p, 0.50, 0.505).is_err());
        assert!(adapter_gate(&p, 0.50, f64::NAN).is_err());
    }

    #[test]
    fn parses_cargo_test_summaries() {
        let out = "test result: ok. 11 passed; 0 failed; 0 ignored\n\ntest result: FAILED. 3 passed; 2 failed;";
        assert_eq!(parse_test_counts(out), (14, 2));
    }
}
