// Emits a HELLO / HELLO_ACK / ENVELOPE / BATCH_END / BYE stream for the
// C-side verifier (linked against Qallow's real sync_wire.c).
// Usage: emit <out> [v2]
//   default: QSW v1 (scopes ride the key-prefix shim)
//   v2:      QSW v2 (scopes as a native wire field, proto_ver=2), with
//            a comma inside a scope name -- the exact corruption class
//            v1's shim cannot carry.
use ductei_core::scoped;
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = args.get(1).expect("usage: emit <out> [v2]");
    let v2 = args.get(2).map(|a| a == "v2").unwrap_or(false);
    let node = [7u8; 16];
    let mut out = Vec::new();
    if v2 {
        let env = scoped(
            "limen.cert.j1",
            &["qallow.semantic.cert", "veyn,x"],
            node,
            42,
            br#"{"tier":2}"#,
        );
        out.extend(ductei_qallow::v2::encode_hello(
            ductei_qallow::F_HELLO,
            &node,
            41,
        ));
        out.extend(ductei_qallow::v2::encode_hello(
            ductei_qallow::F_HELLO_ACK,
            &node,
            41,
        ));
        out.extend(ductei_qallow::v2::encode_envelope(&env));
    } else {
        let env = scoped(
            "limen.cert.j1",
            &["qallow.semantic.cert"],
            node,
            42,
            br#"{"tier":2}"#,
        );
        out.extend(ductei_qallow::encode_hello(
            ductei_qallow::F_HELLO,
            &node,
            41,
        ));
        out.extend(ductei_qallow::encode_hello(
            ductei_qallow::F_HELLO_ACK,
            &node,
            41,
        ));
        out.extend(ductei_qallow::encode_envelope(&env));
    }
    // BATCH_END and BYE are identical bytes in v1 and v2 (frame layout
    // unchanged; only the ENVELOPE body and HELLO proto_ver differ).
    out.extend(ductei_qallow::encode_batch_end(43));
    out.extend(ductei_qallow::encode_bye());
    std::fs::write(path, out).unwrap();
}
