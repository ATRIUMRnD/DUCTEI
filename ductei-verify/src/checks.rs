//! Static checks: pure functions, no I/O, run before anything is built.

use crate::{Candidate, ChangeKind, Policy};
use std::collections::HashSet;

/// Lowercase, backslash separators, no trailing separator.
pub fn norm(p: &str) -> String {
    p.trim().replace('/', "\\").trim_end_matches('\\').to_ascii_lowercase()
}

/// Why a path is not allowed, or None if it is.
pub fn path_issue(policy: &Policy, path: &str) -> Option<String> {
    let n = norm(path);
    let b = n.as_bytes();
    if b.len() < 3 || !b[0].is_ascii_alphabetic() || b[1] != b':' || b[2] != b'\\' {
        return Some("not an absolute drive path".into());
    }
    if n[2..].contains(':') {
        return Some("alternate data stream or stray ':'".into());
    }
    if n.contains('~') {
        return Some("8.3 short names are not allowed".into());
    }
    if n.split('\\').any(|s| s == ".." || s == ".") {
        return Some("path traversal".into());
    }
    if n.split('\\').any(|s| s == ".git") {
        return Some("inside .git".into());
    }
    for f in &policy.forbidden_prefixes {
        let f = norm(f);
        if n == f || n.starts_with(&format!("{f}\\")) {
            return Some(format!("under forbidden prefix {f}"));
        }
    }
    let in_root = policy.allowed_roots.iter().any(|r| {
        let r = norm(r);
        n == r || n.starts_with(&format!("{r}\\"))
    });
    if !in_root {
        return Some("outside allowed roots".into());
    }
    None
}

fn is_ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Count `w` as a whole word.
pub fn word_count(h: &str, w: &str) -> usize {
    h.match_indices(w)
        .filter(|(i, _)| {
            let before = h[..*i].chars().next_back();
            let after = h[i + w.len()..].chars().next();
            !before.is_some_and(is_ident) && !after.is_some_and(is_ident)
        })
        .count()
}

pub fn static_checks(p: &Policy, c: &Candidate) -> Vec<String> {
    let mut r = Vec::new();
    let id_ok = !c.task_id.is_empty()
        && c.task_id.len() <= 64
        && c.task_id.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_');
    if !id_ok {
        r.push("invalid task_id".into());
    }
    if let Some(i) = path_issue(p, &c.worktree) {
        r.push(format!("worktree: {i}"));
    }
    if c.changes.is_empty() {
        r.push("no changes".into());
    }
    if c.changes.len() > p.limits.max_files {
        r.push(format!("{} files changed, limit {}", c.changes.len(), p.limits.max_files));
    }
    let wt = norm(&c.worktree);
    let mut seen = HashSet::new();
    let mut total = 0usize;
    for ch in &c.changes {
        let path = &ch.path;
        if !seen.insert(norm(path)) {
            r.push(format!("{path}: listed twice"));
        }
        if let Some(i) = path_issue(p, path) {
            r.push(format!("{path}: {i}"));
            continue;
        }
        if !norm(path).starts_with(&format!("{wt}\\")) {
            r.push(format!("{path}: outside the worktree"));
        }
        total += ch.content.len();
        if ch.content.len() > p.limits.max_file_bytes {
            r.push(format!("{path}: {} bytes, limit {}", ch.content.len(), p.limits.max_file_bytes));
        }
        match ch.kind {
            ChangeKind::Delete => {
                if !p.content.allow_deletions {
                    r.push(format!("{path}: deletion not allowed (rewire, don't destroy)"));
                }
                if !p.content.allow_test_removal && ch.previous.contains("#[test]") {
                    r.push(format!("{path}: deletes tests"));
                }
            }
            ChangeKind::Add | ChangeKind::Modify => {
                if ch.kind == ChangeKind::Add && !ch.previous.is_empty() {
                    r.push(format!("{path}: add with previous content"));
                }
                for (i, pat) in p.content.forbid_patterns.iter().enumerate() {
                    if !pat.is_empty() && ch.content.contains(pat.as_str()) && !ch.previous.contains(pat.as_str()) {
                        // Index only: never echo a secret into the verdict or ledger.
                        r.push(format!("{path}: forbidden pattern #{i}"));
                    }
                }
                for pat in &p.content.forbid_growth {
                    if !pat.is_empty() && ch.content.matches(pat.as_str()).count() > ch.previous.matches(pat.as_str()).count() {
                        r.push(format!("{path}: adds {pat:?}"));
                    }
                }
                if !p.content.allow_unsafe && word_count(&ch.content, "unsafe") > word_count(&ch.previous, "unsafe") {
                    r.push(format!("{path}: adds unsafe"));
                }
                if !p.content.allow_test_removal
                    && ch.content.matches("#[test]").count() < ch.previous.matches("#[test]").count()
                {
                    r.push(format!("{path}: removes tests"));
                }
            }
        }
    }
    if total > p.limits.max_total_bytes {
        r.push(format!("{total} bytes total, limit {}", p.limits.max_total_bytes));
    }
    for cmd in &c.commands {
        let l = cmd.to_ascii_lowercase();
        for f in &p.commands.forbid {
            if l.contains(&f.to_ascii_lowercase()) {
                r.push(format!("forbidden command: {f}"));
            }
        }
    }
    if let Some(min) = p.gates.jlens_min {
        match c.jlens_score {
            Some(s) if s.is_finite() && s >= min => {}
            Some(s) => r.push(format!("j-lens score {s} below {min}")),
            None => r.push("j-lens score missing".into()),
        }
    }
    r
}

/// Sum passed/failed over every `test result:` line cargo printed.
pub fn parse_test_counts(out: &str) -> (u64, u64) {
    let (mut passed, mut failed) = (0, 0);
    for line in out.lines().filter(|l| l.contains("test result:")) {
        for part in line.split(';') {
            let w: Vec<&str> = part.split_whitespace().collect();
            if w.len() >= 2 {
                if let Ok(n) = w[w.len() - 2].parse::<u64>() {
                    match w[w.len() - 1] {
                        "passed" => passed += n,
                        "failed" => failed += n,
                        _ => {}
                    }
                }
            }
        }
    }
    (passed, failed)
}

/// Post-LoRA eval: keep the new adapter only if it beats the old one.
pub fn adapter_gate(p: &Policy, old: f64, new: f64) -> Result<(), String> {
    if !old.is_finite() || !new.is_finite() {
        return Err("eval scores must be finite: keep old adapter".into());
    }
    let need = old + p.gates.eval_min_delta;
    if new >= need {
        Ok(())
    } else {
        Err(format!("new adapter {new} < required {need}: keep old adapter, roll back"))
    }
}
