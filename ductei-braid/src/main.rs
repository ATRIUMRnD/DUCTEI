//! braid CLI: verify a braid directory and print its heads and root.
//!   braid verify D:\ATRIUM\private\braid

use ductei_braid::{to_hex, verify, Braid, ChainId};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let (Some(cmd), Some(dir)) = (args.get(1), args.get(2)) else {
        eprintln!("usage: braid verify <dir>");
        return ExitCode::from(2);
    };
    if cmd != "verify" {
        eprintln!("unknown command {cmd}; usage: braid verify <dir>");
        return ExitCode::from(2);
    }
    match verify(dir) {
        Err(e) => {
            eprintln!("BROKEN: {e}");
            ExitCode::FAILURE
        }
        Ok(heads) => {
            for c in ChainId::ALL {
                match heads.get(&c) {
                    Some(a) => println!("{:<7} height {:<6} {}", c.name(), a.height, to_hex(&a.hash)),
                    None => println!("{:<7} empty", c.name()),
                }
            }
            match Braid::open(dir) {
                Ok(b) => println!("root    {}", to_hex(&b.braid_root())),
                Err(e) => eprintln!("root unavailable: {e}"),
            }
            println!("OK");
            ExitCode::SUCCESS
        }
    }
}
