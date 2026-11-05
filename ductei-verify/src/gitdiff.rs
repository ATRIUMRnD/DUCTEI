//! Build a Candidate from what git actually sees in the worktree, so the
//! verifier never relies on the agent's own description of its changes.
//! Compiled into the binary (see src/bin/ductei-verify.rs).

use ductei_verify::runner::hidden;
use ductei_verify::{Candidate, Change, ChangeKind, Source};
use std::process::Stdio;

fn git(wt: &str, args: &[&str]) -> Result<String, String> {
    let out = hidden("git")
        .arg("-C")
        .arg(wt)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("git: {e}"))?;
    if !out.status.success() {
        return Err(format!("git {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim()));
    }
    String::from_utf8(out.stdout).map_err(|_| "git output is not UTF-8".into())
}

fn change(wt: &str, rel: &str, kind: ChangeKind) -> Result<Change, String> {
    let path = format!("{}\\{}", wt.trim_end_matches(['\\', '/']), rel.replace('/', "\\"));
    let content = if kind == ChangeKind::Delete {
        String::new()
    } else {
        std::fs::read_to_string(&path).map_err(|e| format!("{path}: {e} (binary files are not accepted)"))?
    };
    let previous = if kind == ChangeKind::Add { String::new() } else { git(wt, &["show", &format!("HEAD:{rel}")])? };
    Ok(Change { path, kind, content, previous })
}

/// Every tracked change against HEAD (staged or not) plus untracked files.
/// Renames, copies, type changes and conflicts are refused (fail closed).
pub fn candidate_from_git(
    worktree: &str,
    task_id: &str,
    jlens_score: Option<f64>,
    commands: Vec<String>,
    sources: Vec<Source>,
) -> Result<Candidate, String> {
    let mut changes = Vec::new();
    let diff = git(worktree, &["diff", "--name-status", "-z", "--no-renames", "HEAD"])?;
    let mut it = diff.split('\0').filter(|s| !s.is_empty());
    while let Some(status) = it.next() {
        let rel = it.next().ok_or("git diff output truncated")?;
        let kind = match status.chars().next() {
            Some('A') => ChangeKind::Add,
            Some('M') => ChangeKind::Modify,
            Some('D') => ChangeKind::Delete,
            other => return Err(format!("unsupported git status {other:?} for {rel}")),
        };
        changes.push(change(worktree, rel, kind)?);
    }
    let untracked = git(worktree, &["ls-files", "--others", "--exclude-standard", "-z"])?;
    for rel in untracked.split('\0').filter(|s| !s.is_empty()) {
        changes.push(change(worktree, rel, ChangeKind::Add)?);
    }
    Ok(Candidate {
        task_id: task_id.into(),
        worktree: worktree.into(),
        changes,
        commands,
        sources,
        jlens_score,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn reads_real_changes_from_git() {
        let d = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("target").join("verify-test").join("git");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let wt = d.to_string_lossy().to_string();
        git(&wt, &["init", "-q"]).unwrap();
        std::fs::write(d.join("keep.rs"), "fn a() {}\n").unwrap();
        std::fs::write(d.join("gone.rs"), "fn b() {}\n").unwrap();
        git(&wt, &["add", "."]).unwrap();
        git(&wt, &["-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "base"]).unwrap();

        std::fs::write(d.join("keep.rs"), "fn a() { 1; }\n").unwrap();
        std::fs::remove_file(d.join("gone.rs")).unwrap();
        std::fs::write(d.join("new.rs"), "fn c() {}\n").unwrap();

        let c = candidate_from_git(&wt, "g1", Some(0.9), vec![], vec![]).unwrap();
        let find = |n: &str| c.changes.iter().find(|ch| ch.path.ends_with(n)).unwrap();
        assert_eq!(find("keep.rs").kind, ChangeKind::Modify);
        assert_eq!(find("keep.rs").previous, "fn a() {}\n");
        assert_eq!(find("gone.rs").kind, ChangeKind::Delete);
        assert_eq!(find("new.rs").kind, ChangeKind::Add);
        assert_eq!(c.changes.len(), 3);
    }
}
