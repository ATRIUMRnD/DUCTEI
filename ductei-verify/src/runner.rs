//! Running build gates: hidden window, stdin closed, hard timeout that kills
//! the whole process tree (cargo plus its rustc children).

use std::io::Read;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Default)]
pub struct RunOut {
    pub status: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
}

pub trait Runner {
    fn run(&mut self, argv: &[String], cwd: &Path, timeout: Duration) -> RunOut;
}

pub struct SystemRunner;

const MAX_CAPTURE: u64 = 8 * 1024 * 1024;

/// A command that never opens a console window.
pub fn hidden(prog: &str) -> Command {
    #[allow(unused_mut)]
    let mut cmd = Command::new(prog);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    cmd
}

fn drain<R: Read + Send + 'static>(r: R) -> JoinHandle<String> {
    std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = r.take(MAX_CAPTURE).read_to_end(&mut b);
        String::from_utf8_lossy(&b).into_owned()
    })
}

fn fail(e: String) -> RunOut {
    RunOut { status: None, stdout: String::new(), stderr: e, timed_out: false }
}

/// Kill the child and everything it started.
fn kill_tree(child: &mut Child) {
    #[cfg(windows)]
    {
        let _ = hidden("taskkill")
            .args(["/PID", &child.id().to_string(), "/T", "/F"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    let _ = child.kill();
    let _ = child.wait();
}

impl Runner for SystemRunner {
    fn run(&mut self, argv: &[String], cwd: &Path, timeout: Duration) -> RunOut {
        let Some((prog, args)) = argv.split_first() else {
            return fail("empty argv".into());
        };
        let mut cmd = hidden(prog);
        cmd.args(args)
            .current_dir(cwd)
            .env("CARGO_TERM_COLOR", "never")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => return fail(format!("spawn {prog}: {e}")),
        };
        let out_h = child.stdout.take().map(drain);
        let err_h = child.stderr.take().map(drain);
        let start = Instant::now();
        let mut timed_out = false;
        let status = loop {
            match child.try_wait() {
                Ok(Some(s)) => break s.code(),
                Ok(None) => {
                    if start.elapsed() >= timeout {
                        kill_tree(&mut child);
                        timed_out = true;
                        break None;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(e) => {
                    kill_tree(&mut child);
                    return fail(format!("wait {prog}: {e}"));
                }
            }
        };
        let join = |h: Option<JoinHandle<String>>| h.and_then(|h| h.join().ok()).unwrap_or_default();
        RunOut { status, stdout: join(out_h), stderr: join(err_h), timed_out }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn timeout_kills_the_child() {
        let argv: Vec<String> = ["powershell", "-NoProfile", "-Command", "Start-Sleep -Seconds 30"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let t = Instant::now();
        let out = SystemRunner.run(&argv, Path::new("."), Duration::from_secs(1));
        assert!(out.timed_out);
        assert!(t.elapsed() < Duration::from_secs(15));
    }
}
