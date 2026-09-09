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
the C-side counterpart (`qsw_decode_v2` / `qsw_decode_v2_envelope_body`,
`QSW_PROTO_VER_V2 = 2`) now exists in Qallow's `sync_wire.c` (ATRIUM
harness-roadmap/05). The conformance job verifies a Rust-emitted v2 stream
through the real C decoder, including a comma inside a scope name.
`qallow ingest` auto-negotiates the version and rebuilds the v1 shim key
(`scopes.join(",") + "|" + key`) for merge, so a record lands under the
same LMDB key regardless of proto version.

## Qallow-side ingestion (real, and gated)
`ductei-qallow-relay` hands QSW v1 frames to a real `qallow ingest`
process, which calls Qallow's `ql_persist_merge_blob()` into LMDB
(Qallow@0a546b3 onward). Since Qallow@2b0009e (ATRIUM Task 4) that gate
is kernel-level: it refuses, before any write, an envelope with
`schema_ver < 2`, an open/broadcast scope, a zero session id or bound,
a reserved key prefix (`env/ cred/ secret/ token/ password/`), or a
malformed payload. `ductei_qallow::persist` is DUCTEI's side of that
contract: `for_persist()` re-frames an accepted envelope with
`schema_ver = 2` and wraps its blob in the persist-v2 header
(`u16 ver=2 | u16 scope_code | u64 session_id | u64 session_bound |
u32 data_len | data`). The relay's bounded session
(`max_envelopes = 1`) is what gets written as `session_bound`, so
invariant 5 is an on-disk fact, not a relay promise. `qallow get`
returns only `data`, so readers see the producer's bytes unchanged.
The QSW v1 wire frame itself is untouched and still passes the
conformance oracle. `ductei_qallow::ingest` (the `QallowSink` seam and
`MemorySink`) remains for DUCTEI's own tests.

## One app: the closed loop
`scripts/smoke_loop.py` runs the whole ecosystem as one loop with one
shared LMDB store: VEYN REM cue -> `DucteiBridge` -> ductei-qallow-relay
-> LMDB -> `qallow propose` (Qallow reads the cue from durable state and
writes a LIMEN route request) -> limend -> ductei-limen-relay ->
ductei-qallow-relay -> the same LMDB. Four scenarios, 41 checks, five
invariants asserted inline; CI job `e2e-smoke-loop`.
`scripts/atrium_up.py` runs the same loop as long-lived processes from
one command (optionally booting the real VEYN daemon and firing an
�neiro-shaped `/oneiro/watch` OSC cue).

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

## Known gaps
- Outside DUCTEI, blocking the full loop: the LIMEN README patch is
  unapplied, and ML-KEM has no evaluated LIMEN-side counterpart yet
  (DUCTEI's own `pq` feature adds ML-KEM-768 for transport key exchange,
  independent of that).

## Roadmap
- QSW proto v2 adoption on the Qallow side — DONE locally (C decoder +
  ingest negotiation + merge-key parity; ATRIUM harness-roadmap/05);
  CI step lands with this repo's commit, after Qallow's
- gRPC/QUIC used as the default transport for cross-network peers once a
  peer-provisioning story (cert distribution, service discovery) exists
