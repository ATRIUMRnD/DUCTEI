//! atrium-spec CLI.
//!
//!   atrium-spec gen   <spec.toml> <out-dir>   write generated files
//!   atrium-spec check <spec.toml> <out-dir>   exit 1 if committed files differ
//!   atrium-spec print <spec.toml> <rust|c|python>

use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let usage = || {
        eprintln!("usage: atrium-spec gen|check <spec.toml> <out-dir>\n       atrium-spec print <spec.toml> rust|c|python");
        ExitCode::from(2)
    };
    let (Some(cmd), Some(spec_path)) = (args.first(), args.get(1)) else {
        return usage();
    };
    let text = match std::fs::read_to_string(spec_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("cannot read {spec_path}: {e}");
            return ExitCode::from(2);
        }
    };
    let spec = match atrium_spec::parse(&text) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{spec_path}: {e}");
            return ExitCode::from(2);
        }
    };
    match cmd.as_str() {
        "print" => {
            let out = match args.get(2).map(String::as_str) {
                Some("rust") => atrium_spec::emit_rust(&spec),
                Some("c") => atrium_spec::emit_c(&spec),
                Some("python") => atrium_spec::emit_python(&spec),
                _ => return usage(),
            };
            print!("{out}");
            ExitCode::SUCCESS
        }
        "gen" | "check" => {
            let Some(out_dir) = args.get(2) else { return usage() };
            let dir = Path::new(out_dir);
            let mut drift = 0;
            for (name, body) in atrium_spec::emit_all(&spec) {
                let path = dir.join(&name);
                if cmd == "gen" {
                    if let Err(e) = std::fs::create_dir_all(dir).and_then(|_| std::fs::write(&path, &body)) {
                        eprintln!("cannot write {}: {e}", path.display());
                        return ExitCode::from(2);
                    }
                    println!("wrote {}", path.display());
                } else {
                    let current = std::fs::read_to_string(&path).unwrap_or_default();
                    if current.replace("\r\n", "\n") != body {
                        eprintln!("DRIFT: {} does not match the spec (run `atrium-spec gen`)", path.display());
                        drift += 1;
                    } else {
                        println!("ok    {}", path.display());
                    }
                }
            }
            if drift > 0 {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            }
        }
        _ => usage(),
    }
}
