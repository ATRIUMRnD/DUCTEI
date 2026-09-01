# DUCTEI v0.1.0 — channel layer for LIMEN / Qallow / VEYN

Licensed under Apache-2.0 (see `LICENSE`).

Governance: ownership map, hard invariants, and build order for this
repo and its siblings (LIMEN, Qallow, VEYN) live in
[ATRIUM](https://github.com/xingxerx/ATRIUM) — read `AGENTS.md` there
first.

Channel, not merger. Per-repo adapters over shared structs.

## Design rules
0. Deny-by-default selective-broadcast scopes, first-class envelope
   fields, checked at the channel boundary at `send()`. One forbidden
   scope poisons the whole envelope. Receivers never filter.
1. Channel-side persistence. Append-only fsynced JSONL log with
   `replay(cursor)`. Nothing is acked before it is in the log.
2. Bounded sessions only (`SessionBound`); unbounded unrepresentable.
3. Causal-delta gate: pre-sync filter on (lamport, node_id) per
   (key, scope-set). Stale/out-of-order deltas rejected, logged to a
   JSONL reject log, never applied or re-broadcast. Ties break
   deterministically by node_id. Gate state rebuilds from the accepted
   log on restart.

## Hard invariants
- LIMEN credentials and quantum link traffic never enter payloads.
  Closed adapter types; serde drops unknown fields (`api_token`,
  `qpu_instance`) before anything reaches the channel.
- Byte-level wire compatibility with Qallow `sync_wire.c` (proto v1).
  Conformance oracle must pass after every change.

## Crates
| crate | role |
|---|---|
| `ductei-core` | Scope, ScopePolicy, Envelope, LogStore, Channel, SessionBound, `gate` (causal-delta), `transport` (TCP), `grpc` (feature), `quic` (feature), `pq` (feature: ML-KEM-768) |
| `ductei-limen` | LIMEN cert JSON -> `qallow.semantic.cert` envelopes (closed type) |
| `ductei-qallow` | Envelope <-> Qallow QSW proto v1/v2 bytes (pure Rust, byte-compatible); `ingest` (Qallow-side merge seam) |
| `ductei-veyn` | VEYN sensor/actuator events -> scoped envelopes. Narrow deny-by-default scopes (`veyn.rem_event`, `veyn.hrv`, `veyn.sensor.*`, `veyn.actuator.watch`); `Adapter` applies a per-scope `CoalescePolicy` (HRV sampled to 1/min) before conversion so raw firehose stays inside VEYN |
| `conformance/` | Rust emitter + C verifier linking Qallow's real `sync_wire.c` |

## Transport
TCP, length-prefixed frames (u32 LE len | JSON envelope), matching the
incremental-decoder pattern, on by default. Vendor-neutral `Transport`
trait so other transports can slot in behind it. Inbound path per frame:
scope policy -> causal gate -> fsynced JSONL append -> ack byte.
Ack is tri-state: 1=applied (new write persisted), 2=stale/already-present
(receipt success), 0=rejected (scope-denied/malformed; never applied).
QSW wire translation for
Qallow ingestion lives in `ductei-qallow` unchanged.

Local-first behavior: if a peer is unreachable (connect fails), delivery
degrades to the local `Channel` (`LocalFallback`). If connect succeeds but a
later write/read/ack I/O error occurs, there is no LocalFallback (receiver
persistence is unknown). Record a durable outbound intent and retry the
identical envelope triple after restart; see `ductei_core::outbox::Outbox`.
Default Outbox path: `DUCTEI_OUTBOX_PATH` when set, else `$XDG_STATE_HOME/ductei/outbox.jsonl`,
else `$HOME/.ductei/outbox.jsonl` (created on first use).

Two more `Transport` impls exist behind opt-in Cargo features, same
persistence-first ack contract, same `Channel` on the receiving side:
- **`grpc`** (`ductei_core::grpc`): `tonic`, envelope JSON rides unchanged
  inside a one-RPC proto service (`ChannelService.SendEnvelope`); gRPC
  supplies framing/multiplexing/TLS only.
- **`quic`** (`ductei_core::quic`): `quinn` + `rustls`. QUIC requires TLS,
  so there's no CA here — the server presents a self-signed cert
  (`generate_self_signed`) that clients pin by DER bytes out-of-band.

## Post-quantum key exchange (feature `pq`)
`ductei_core::pq`: ML-KEM-768 (FIPS 203) via `pqcrypto-mlkem`, for
establishing a session key ahead of the transport layer. This does not
touch the `Envelope` wire format or scope model — it complements LIMEN's
ML-DSA-65 signing with a matching post-quantum key-exchange primitive
instead of only classical TLS.

## QSW proto v2
`ductei_qallow::v2`: scopes as a length-prefixed native wire field instead
of v1's comma-joined key-prefix shim (which corrupts a scope name
containing a comma). Lives alongside v1 unchanged — v1 stays byte-compatible
with Qallow's real `sync_wire.c` and keeps passing the conformance oracle;
v2 has no C-side counterpart yet.

## Qallow-side ingestion seam
`ductei_qallow::ingest`: a `QallowSink` trait shaped exactly like the real
`ql_persist_merge_blob(key, blob)` call, plus `ingest_envelope()` as the one
call site that will point at it. `ql_persist_merge_blob()` itself lives in
the Qallow repo (C) and doesn't exist yet — this is the seam, not the fix.
A `MemorySink` stand-in lets DUCTEI's own tests exercise "envelope decoded
-> merge called" end-to-end without linking Qallow.

## Test status (2026-07-13)
- `cargo test --workspace`: 16/16 pass (default features: TCP transport only)
  - v0.1.1 suite: scope deny-by-default, poisoned envelope, restart
    survival, credential drop, unbounded-session unrepresentable,
    session bound enforced with exit always available
  - Build 0: in-order accept / stale reject, tie-break determinism,
    replay-after-restart consistency
  - Build 1: two-node loopback (accept, stale nack, scope-denied nack,
    persistence-first ack)
  - Build 2: synthetic OSC/EEG event -> VEYN adapter -> gate ->
    transport -> second node log -> QSW bytes roundtrip intact, then
    through the Qallow ingestion seam (`ingest_envelope` -> `MemorySink`)
  - QSW proto v2: multi-scope roundtrip, comma-in-scope-name survival
  - Phase 3: REM/HRV get narrow scopes (`veyn.rem_event`, `veyn.hrv`)
    distinct from the broader per-source scopes; simulated 1 Hz HRV
    stream coalesced to 1/min by `Adapter`; simulated high-frequency
    REM triggers pass through uncoalesced (discrete events, not sampled)
- `cargo test --workspace --all-features`: 19/19 pass, adding:
  - gRPC two-node loopback (accept, scope-denied nack) over `tonic`
  - QUIC two-node loopback (accept, scope-denied nack) over `quinn`,
    self-signed cert pinned by DER bytes
  - ML-KEM-768 encapsulate/decapsulate shared-secret agreement
- Conformance oracle: PASS (Qallow's C `qsw_decode()` fed one byte at a
  time accepts the Rust HELLO/HELLO_ACK/ENVELOPE/BATCH_END/BYE stream) —
  unaffected by any of the above; v1 encode/decode functions untouched

## Run conformance
```
cargo build -p conformance-emitter
./target/debug/emit /tmp/stream.bin
gcc -I<qallow>/include -o conformance/verify conformance/verify.c <qallow>/src/mind/sync_wire.c
./conformance/verify /tmp/stream.bin
```

## Known gaps (v0.1.0)
- **The real Qallow LMDB merge is still outside this repo.**
  `ductei_qallow::ingest` gives DUCTEI's side a `QallowSink` seam and
  proves "envelope decoded -> merge called" against a local stand-in, but
  the actual `ql_persist_merge_blob()` call lives in the Qallow repo (C)
  and doesn't exist yet. VEYN -> DUCTEI -> Qallow is proven at the wire
  level and at the ingestion-seam level, not yet against Qallow's real
  store.
- Outside DUCTEI, blocking the full loop: the LIMEN README patch is
  unapplied, and ML-KEM has no evaluated LIMEN-side counterpart yet
  (DUCTEI's own `pq` feature adds ML-KEM-768 for transport key exchange,
  independent of that).

## Roadmap
- Real Qallow ingestion daemon: an impl of `QallowSink` backed by an FFI
  or cxx bridge into Qallow's `ql_persist_merge_blob()` (lives in the
  Qallow repo, not here)
- QSW proto v2 adoption on the Qallow side once a C decoder exists for it
- gRPC/QUIC used as the default transport for cross-network peers once a
  peer-provisioning story (cert distribution, service discovery) exists
