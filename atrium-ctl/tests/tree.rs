// Regression: `atrium down` used to kill only the room's root process, leaving
// atrium_up.py's relays and limend running as orphans (four copies of the loop
// writing one LMDB store on Nov 1, 2026). Every room's tree must die with it.
#![cfg(windows)]
use atrium_ctl::*;
use std::fs;

// Both tests count PING.EXE, so they must not overlap.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn count(image: &str) -> usize {
    let o = std::process::Command::new("tasklist").args(["/FO", "CSV", "/NH", "/FI", &format!("IMAGENAME eq {image}")]).output().unwrap();
    String::from_utf8_lossy(&o.stdout).lines().filter(|l| l.to_ascii_lowercase().contains(&image.to_ascii_lowercase())).count()
}

fn wait_for(image: &str, want: usize) -> usize {
    for _ in 0..50 {
        let n = count(image);
        if n == want { return n; }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    count(image)
}

#[test]
fn shutdown_kills_grandchildren() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let s = std::env::temp_dir().join(format!("atrium-ctl-tree-{}", std::process::id()));
    let _ = fs::remove_dir_all(&s);
    fs::create_dir_all(&s).unwrap();
    // cmd (child) starts a background PING (grandchild), then waits on a foreground one.
    let t = format!(
        "state = {:?}\ntick_ms = 10\n[[room]]\nname = \"tree\"\nkind = \"managed\"\nexe = \"cmd.exe\"\n\
         args = [\"/c\", \"start /b PING.EXE -n 120 127.0.0.1 >NUL & PING.EXE -n 120 127.0.0.1 >NUL\"]\n",
        s.to_string_lossy());
    let cfg: Config = toml::from_str(&t).unwrap();
    let before = count("PING.EXE");
    let mut sup = Supervisor::open(cfg).unwrap();
    sup.tick().unwrap();
    let during = wait_for("PING.EXE", before + 2);
    assert_eq!(during, before + 2, "child and grandchild both running");
    sup.shutdown().unwrap();
    let after = wait_for("PING.EXE", before);
    assert_eq!(after, before, "grandchild must not survive shutdown");
}

#[test]
fn dropping_supervisor_kills_tree() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    // Simulates atrium itself dying: the job handles close, the OS kills the trees.
    let s = std::env::temp_dir().join(format!("atrium-ctl-drop-{}", std::process::id()));
    let _ = fs::remove_dir_all(&s);
    fs::create_dir_all(&s).unwrap();
    let t = format!(
        "state = {:?}\ntick_ms = 10\n[[room]]\nname = \"tree\"\nkind = \"managed\"\nexe = \"cmd.exe\"\n\
         args = [\"/c\", \"start /b PING.EXE -n 120 127.0.0.1 >NUL & PING.EXE -n 120 127.0.0.1 >NUL\"]\n",
        s.to_string_lossy());
    let cfg: Config = toml::from_str(&t).unwrap();
    let before = count("PING.EXE");
    {
        let mut sup = Supervisor::open(cfg).unwrap();
        sup.tick().unwrap();
        assert_eq!(wait_for("PING.EXE", before + 2), before + 2);
    }
    assert_eq!(wait_for("PING.EXE", before), before, "tree must die when the supervisor goes away");
}
