//! qsw-inspect CLI.
//!   qsw-inspect decode <PATH|-> [--format auto|raw|hex|bits] [--proto 1|2] [--json]
//!   qsw-inspect decode --str "<hex or 0/1 text>" [...]
//!   qsw-inspect diff <A> <B> [--format ...] [--proto 1|2] [--json]
//! Exit codes: 0 clean/identical, 1 problems/different, 2 usage or I/O error.
use qsw_inspect::{diff, inspect, load, Fmt, Report};
use std::io::Read;
use std::process::exit;

const USAGE: &str = "usage:
  qsw-inspect decode <PATH|-> [--format auto|raw|hex|bits] [--proto 1|2] [--json]
  qsw-inspect decode --str \"<hex or 0/1 text>\" [--format ...] [--proto 1|2] [--json]
  qsw-inspect diff <A> <B> [--format auto|raw|hex|bits] [--proto 1|2] [--json]

  --format  input encoding (default auto: 0/1 text -> bits, hex text -> hex, else raw)
  --proto   force QSW v1/v2 for ENVELOPE bodies (default: follow HELLO proto_ver)
  exit: 0 clean/identical, 1 problems/different, 2 usage or I/O error";

fn die(msg: &str) -> ! {
    eprintln!("qsw-inspect: {msg}\n\n{USAGE}");
    exit(2)
}

struct Opts {
    pos: Vec<String>,
    s: Option<String>,
    fmt: Fmt,
    proto: Option<u16>,
    json: bool,
}

fn parse_args(args: &[String]) -> Opts {
    let mut o = Opts { pos: vec![], s: None, fmt: Fmt::Auto, proto: None, json: false };
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        let mut next = || {
            i += 1;
            args.get(i).cloned().unwrap_or_else(|| die(&format!("{a} needs a value")))
        };
        match a {
            "--json" => o.json = true,
            "--str" => o.s = Some(next()),
            "--format" => {
                o.fmt = match next().as_str() {
                    "auto" => Fmt::Auto,
                    "raw" => Fmt::Raw,
                    "hex" => Fmt::Hex,
                    "bits" => Fmt::Bits,
                    f => die(&format!("unknown --format {f}")),
                }
            }
            "--proto" => {
                o.proto = match next().as_str() {
                    "1" => Some(1),
                    "2" => Some(2),
                    p => die(&format!("unknown --proto {p} (1 or 2)")),
                }
            }
            "-h" | "--help" => {
                println!("{USAGE}");
                exit(0)
            }
            _ if a.starts_with("--") => die(&format!("unknown flag {a}")),
            _ => o.pos.push(a.to_string()),
        }
        i += 1;
    }
    o
}

fn read_input(path: &str, fmt: Fmt) -> (Vec<u8>, Fmt) {
    let data = if path == "-" {
        let mut v = Vec::new();
        std::io::stdin().read_to_end(&mut v).unwrap_or_else(|e| die(&format!("stdin: {e}")));
        v
    } else {
        std::fs::read(path).unwrap_or_else(|e| die(&format!("{path}: {e}")))
    };
    load(&data, fmt).unwrap_or_else(|e| die(&format!("{path}: {e}")))
}

fn fmt_name(f: Fmt) -> &'static str {
    match f {
        Fmt::Auto => "auto",
        Fmt::Raw => "raw",
        Fmt::Hex => "hex text",
        Fmt::Bits => "0/1 text",
    }
}

fn clip(s: &str, n: usize) -> String {
    if s.chars().count() <= n { s.to_string() } else { format!("{}..", s.chars().take(n).collect::<String>()) }
}

fn print_report(r: &Report, src: &str, f: Fmt) {
    println!("qsw-inspect: {src}  {} byte(s) ({}), {} frame(s)", r.total_bytes, fmt_name(f), r.frames.len());
    for fr in &r.frames {
        let dec = match fr.decoder_accepts {
            Some(true) => "  decoder: accepts",
            Some(false) => "  decoder: REJECTS",
            None => "",
        };
        println!(
            "\nframe {}  {}  @0x{:04X}  body {} B  proto v{}{}",
            fr.index, fr.type_name, fr.offset, fr.body_len, fr.proto, dec
        );
        println!("  {:<8} {:<38} {:<16} value", "offset", "bytes", "field");
        for fl in &fr.fields {
            println!("  0x{:04X}   {:<38} {:<16} {}", fl.offset, clip(&fl.bytes, 36), fl.name, fl.value);
        }
        for p in &fr.problems {
            println!("  PROBLEM: {p}");
        }
    }
    if let Some(t) = &r.trailing {
        println!("\nPROBLEM: {t}");
    }
    let n: usize = r.frames.iter().map(|f| f.problems.len()).sum::<usize>() + r.trailing.is_some() as usize;
    println!("\n{}", if n == 0 { "OK: stream is clean".to_string() } else { format!("FAIL: {n} problem(s)") });
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first() else { die("missing command") };
    let o = parse_args(&args[1..]);
    match cmd.as_str() {
        "decode" => {
            let (src, (bytes, f)) = match (&o.s, o.pos.first()) {
                (Some(s), None) => ("--str".to_string(), load(s.as_bytes(), o.fmt).unwrap_or_else(|e| die(&e))),
                (None, Some(p)) => (p.clone(), read_input(p, o.fmt)),
                _ => die("decode takes exactly one of <PATH|-> or --str"),
            };
            let r = inspect(&bytes, o.proto);
            if o.json {
                println!("{}", serde_json::to_string_pretty(&r).unwrap());
            } else {
                print_report(&r, &src, f);
            }
            exit(if r.ok() { 0 } else { 1 })
        }
        "diff" => {
            let [a, b] = o.pos.as_slice() else { die("diff takes two inputs: <A> <B>") };
            let (ba, _) = read_input(a, o.fmt);
            let (bb, _) = read_input(b, o.fmt);
            let (d, _, _) = diff(&ba, &bb, o.proto);
            if o.json {
                println!("{}", serde_json::to_string_pretty(&d).unwrap());
            } else if d.identical {
                println!("identical: {} byte(s), {} frame(s)", d.len_a, d.frames_a);
            } else {
                let off = d.first_diff.unwrap();
                println!("DIFFERENT  A={a} ({} B, {} frames)  B={b} ({} B, {} frames)", d.len_a, d.frames_a, d.len_b, d.frames_b);
                println!("first difference at byte 0x{off:04X} ({off})");
                for (tag, s) in [("A", &d.a), ("B", &d.b)] {
                    match s.as_ref().and_then(|s| s.field.as_ref().map(|f| (s, f))) {
                        Some((s, f)) => println!(
                            "  {tag}: frame {} {}  field {}  = {}",
                            s.frame.unwrap(), s.frame_type.unwrap(), f, s.value.as_deref().unwrap_or("")
                        ),
                        None => println!("  {tag}: (stream ends before this byte)"),
                    }
                }
                println!("differing bytes in common prefix: {}", d.differing_bytes);
            }
            exit(if d.identical { 0 } else { 1 })
        }
        "-h" | "--help" | "help" => println!("{USAGE}"),
        c => die(&format!("unknown command {c}")),
    }
}
