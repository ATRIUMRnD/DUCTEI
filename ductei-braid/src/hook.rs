//! Wires a `Braid` into a DUCTEI `Channel` as a post-accept observer.
//!
//! The channel's accepted log stays the source of truth. The braid only
//! sees envelopes that passed scope check, causal gate and fsync. If a
//! braid write fails, the envelope is still accepted and the channel's
//! `observer_faults()` counter goes up.

use crate::{Braid, BraidError};
use ductei_core::{Channel, Envelope};
use std::path::Path;

/// Open the braid at `dir` (refusing tampered history) and attach it to
/// `ch`. Every accepted envelope is recorded on its routed chain.
pub fn attach(ch: &mut Channel, dir: impl AsRef<Path>) -> Result<(), BraidError> {
    let mut braid = Braid::open(dir)?;
    ch.observe(Box::new(move |env: &Envelope| {
        braid.record(env).map(|_| ()).map_err(|e| e.to_string())
    }));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{chain_path, verify, ChainId};
    use ductei_core::{scoped, ChannelError, ScopePolicy};
    use std::path::PathBuf;

    fn tmp(tag: &str) -> PathBuf {
        let n = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let d = std::env::temp_dir().join(format!("braid-hook-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn lines(d: &std::path::Path, c: ChainId) -> usize {
        std::fs::read_to_string(chain_path(d, c)).map(|s| s.lines().count()).unwrap_or(0)
    }

    #[test]
    fn accepted_envelopes_land_on_routed_chains() {
        let d = tmp("ok");
        let pol = ScopePolicy::new().allow("limen").allow("oneiro").allow("qallow");
        let mut ch = Channel::open(pol, d.join("acc.jsonl"), d.join("rej.jsonl")).unwrap();
        attach(&mut ch, d.join("braid")).unwrap();
        ch.send(scoped("limen.run", &["limen"], [1; 16], 1, b"a")).unwrap();
        ch.send(scoped("oneiro.rem", &["oneiro"], [1; 16], 1, b"b")).unwrap();
        ch.send(scoped("qallow.sync", &["qallow"], [1; 16], 1, b"c")).unwrap();
        let b = d.join("braid");
        assert_eq!(lines(&b, ChainId::Limen), 1);
        assert_eq!(lines(&b, ChainId::Oneiro), 1);
        assert_eq!(lines(&b, ChainId::Atrium), 1);
        assert_eq!(verify(&b).unwrap().len(), 3);
        assert_eq!(ch.observer_faults(), 0);
    }

    #[test]
    fn rejected_envelopes_never_reach_the_braid() {
        let d = tmp("rej");
        let pol = ScopePolicy::new().allow("limen");
        let mut ch = Channel::open(pol, d.join("acc.jsonl"), d.join("rej.jsonl")).unwrap();
        attach(&mut ch, d.join("braid")).unwrap();
        // Scope denied.
        assert!(matches!(
            ch.send(scoped("x", &["secret"], [1; 16], 1, b"x")),
            Err(ChannelError::ScopeDenied(_))
        ));
        // Accepted, then a stale replay of the same key.
        ch.send(scoped("limen.k", &["limen"], [1; 16], 5, b"y")).unwrap();
        assert!(ch.send(scoped("limen.k", &["limen"], [1; 16], 4, b"z")).is_err());
        let b = d.join("braid");
        assert_eq!(lines(&b, ChainId::Limen), 1);
        assert_eq!(lines(&b, ChainId::Atrium), 0);
    }

    #[test]
    fn tampered_braid_refuses_to_attach() {
        let d = tmp("tamper");
        let b = d.join("braid");
        {
            let mut br = Braid::open(&b).unwrap();
            br.record(&scoped("limen.a", &["limen"], [1; 16], 1, b"a")).unwrap();
        }
        let p = chain_path(&b, ChainId::Limen);
        let s = std::fs::read_to_string(&p).unwrap().replace("\"lamport\":1", "\"lamport\":2");
        std::fs::write(&p, s).unwrap();
        let mut ch = Channel::open(ScopePolicy::new().allow("limen"), d.join("acc.jsonl"), d.join("rej.jsonl")).unwrap();
        assert!(attach(&mut ch, &b).is_err());
    }
}
