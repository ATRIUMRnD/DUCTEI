//! Fix proposals: turn one failing test into a verified patch for Xing to review.
//!
//! The pieces here are pure (no processes, no network) so they are unit tested.
//! The driver is `examples/fix_brain.rs`: it works in a scratch git worktree,
//! asks the brain chain for a whole replacement file, gates the result with
//! ductei-verify, and only ever writes a .patch file plus one outbox line.
//! It never touches the real checkout and never commits.

/// Failing test names from `cargo test` output (`test a::b ... FAILED`), in order, no repeats.
pub fn failing_tests(output: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for l in output.lines() {
        let l = l.trim();
        if let Some(rest) = l.strip_prefix("test ") {
            if let Some(name) = rest.strip_suffix(" ... FAILED") {
                let name = name.trim().to_string();
                if !name.is_empty() && !out.contains(&name) {
                    out.push(name);
                }
            }
        }
    }
    out
}

/// The `---- <name> stdout ----` block for one failing test, capped at `max` chars.
pub fn failure_text(output: &str, name: &str, max: usize) -> String {
    let head = format!("---- {name} stdout ----");
    let Some(i) = output.find(&head) else { return String::new() };
    let rest = &output[i..];
    let end = rest[head.len()..].find("\n---- ").map(|j| j + head.len()).unwrap_or(rest.len());
    let block = rest[..end].trim();
    let mut s: String = block.chars().take(max).collect();
    if block.chars().count() > max {
        s.push_str("\n[...cut]");
    }
    s
}

/// Last path segment of a test name: `budget::tests::x` -> `x`.
pub fn test_fn(name: &str) -> &str {
    name.rsplit("::").next().unwrap_or(name)
}

/// Does this Rust source define `fn <f>(`?
pub fn defines_fn(src: &str, f: &str) -> bool {
    let pat = format!("fn {f}(");
    src.match_indices(&pat).any(|(i, _)| {
        i == 0 || !src[..i].chars().last().is_some_and(|c| c.is_alphanumeric() || c == '_')
    })
}

/// Pull the replacement file out of a model reply: the longest ```rust (or bare ```) fence,
/// else a JSON {"say": "..."} body. None if nothing usable.
pub fn extract_file(reply: &str) -> Option<String> {
    let mut best: Option<String> = None;
    let mut rest = reply;
    while let Some(i) = rest.find("```") {
        let after = &rest[i + 3..];
        let body_start = after.find('\n').map(|n| n + 1)?;
        let lang = after[..body_start].trim();
        let body = &after[body_start..];
        let Some(close) = body.find("```") else { break };
        if lang.is_empty() || lang.eq_ignore_ascii_case("rust") || lang.eq_ignore_ascii_case("rs") {
            let code = body[..close].to_string();
            if best.as_ref().map_or(true, |b| code.len() > b.len()) {
                best = Some(code);
            }
        }
        rest = &body[close + 3..];
    }
    if best.is_none() {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(reply.trim()) {
            if let Some(s) = v["say"].as_str() {
                if s.contains("fn ") {
                    best = Some(s.to_string());
                }
            }
        }
    }
    best.filter(|s| !s.trim().is_empty())
}

/// Cheap pre-checks before the real gate: the file must change, keep the failing test,
/// and not shrink to a stub.
pub fn precheck(old: &str, new: &str, test: &str) -> Result<(), String> {
    if old.trim() == new.trim() {
        return Err("model returned the file unchanged".into());
    }
    if !defines_fn(new, test_fn(test)) {
        return Err(format!("model removed the failing test {}", test_fn(test)));
    }
    if new.len() * 2 < old.len() {
        return Err(format!("model shrank the file from {} to {} bytes", old.len(), new.len()));
    }
    Ok(())
}

/// The one request sent to the model.
pub fn prompt(test: &str, failure: &str, rel_path: &str, src: &str) -> String {
    format!(
        "A Rust test is failing in Xing's brain repo.\n\
         Failing test: {test}\n\nFailure output:\n{failure}\n\n\
         File {rel_path} (contains the test):\n```rust\n{src}```\n\n\
         Fix the bug with the smallest change. Fix the code under test, not the test, unless the test itself is \
         clearly wrong. Do not delete or #[ignore] tests, do not add #[allow(..)], unsafe, todo!() or new process spawning. \
         Reply with the COMPLETE new contents of {rel_path} in one ```rust code block, then one line explaining the fix."
    )
}

/// A short, safe stem for a test name (file names and verifier task ids: 64 chars max with "brain-").
pub fn stem(test: &str) -> String {
    let s: String = test.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect();
    s.chars().take(56).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const OUT: &str = "running 3 tests\n\
test a::tests::ok ... ok\n\
test budget::tests::sums ... FAILED\n\
test b::c ... FAILED\n\n\
failures:\n\n\
---- budget::tests::sums stdout ----\n\
thread 'budget::tests::sums' panicked at src/budget.rs:9:5:\nassertion failed: 1 == 2\n\n\
---- b::c stdout ----\nboom\n\n\
failures:\n    b::c\n    budget::tests::sums\n";

    #[test]
    fn finds_failures_in_order() {
        assert_eq!(failing_tests(OUT), vec!["budget::tests::sums", "b::c"]);
        assert!(failing_tests("test x ... ok\ntest result: ok").is_empty());
    }

    #[test]
    fn failure_block_is_scoped_and_capped() {
        let t = failure_text(OUT, "budget::tests::sums", 1000);
        assert!(t.contains("assertion failed") && !t.contains("boom"), "{t}");
        assert!(failure_text(OUT, "b::c", 4).ends_with("[...cut]"));
        assert_eq!(failure_text(OUT, "nope", 100), "");
    }

    #[test]
    fn fn_detection_is_word_bounded() {
        assert!(defines_fn("    fn sums() {}", "sums"));
        assert!(!defines_fn("fn checksums() {}", "sums"));
        assert_eq!(test_fn("budget::tests::sums"), "sums");
    }

    #[test]
    fn extracts_longest_rust_fence_or_json() {
        let r = "Here:\n```rust\nfn a() {}\nfn b() {}\n```\nand ```text\nnot code\n``` done";
        assert_eq!(extract_file(r).unwrap(), "fn a() {}\nfn b() {}\n");
        assert_eq!(extract_file(r#"{"say":"fn x() {}"}"#).unwrap(), "fn x() {}");
        assert!(extract_file("no code here").is_none());
        assert!(extract_file("```python\nprint(1)\n```").is_none());
    }

    #[test]
    fn precheck_blocks_unchanged_removed_and_stubbed() {
        let old = "fn f() -> u8 { 1 }\n#[test] fn sums() { assert_eq!(f(), 2); }\n";
        assert!(precheck(old, old, "m::sums").is_err());
        assert!(precheck(old, "fn f() -> u8 { 2 }\n", "m::sums").is_err());
        assert!(precheck(old, "#[test] fn sums(){}", "m::sums").is_err());
        assert!(precheck(old, &old.replace("{ 1 }", "{ 2 }"), "m::sums").is_ok());
    }

    #[test]
    fn stems_are_file_safe() {
        assert_eq!(stem("a::b c"), "a__b_c");
    }
}
