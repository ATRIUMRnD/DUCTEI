//! Test helper, not part of the shipped binary: append ONE envelope this node
//! originated to `<state>/local/accepted.jsonl`, so `ductei-sync push` has
//! something to send in a cross-machine smoke test. Use a throwaway state dir
//! and a throwaway scope; never point it at a real producer's state.
//!
//!   cargo run -p ductei-sync --features net --example emit_test_envelope -- STATE SCOPE KEY TEXT
use ductei_core::{scoped, ScopePolicy};
use ductei_sync::StateDir;

fn main() -> Result<(), String> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let [state, scope, key, text] = a.as_slice() else {
        return Err("usage: emit_test_envelope STATE SCOPE KEY TEXT".into());
    };
    let st = StateDir::open(state).map_err(|e| e.to_string())?;
    let node = st.node_id().map_err(|e| e.to_string())?;
    let clock = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_millis() as u64;
    st.local_channel(ScopePolicy::new().allow(scope))
        .map_err(|e| e.to_string())?
        .send(scoped(key, &[scope.as_str()], node, clock, text.as_bytes()))
        .map_err(|e| format!("{e:?}"))?;
    println!("appended {key} ({scope}) to {}", st.local_log().display());
    Ok(())
}
