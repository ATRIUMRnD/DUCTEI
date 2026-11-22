# DUCTEI

**Governed plumbing for AI agents and the systems they touch.** DUCTEI is a Rust workspace that puts a checked, recorded channel between things that should not trust each other by default: an agent and its tools, one machine and another, a job and the hardware that runs it.

Three ideas run through every crate:

- **Deny by default.** Nothing crosses the channel unless a scope policy allows it. A refused call never reaches the other side.
- **Record before you act.** Every message is written to an append-only, fsynced log before it is acknowledged or forwarded.
- **Prove it afterwards.** Actions leave hash-chained receipts, optionally signed with a post-quantum signature (ML-DSA), that anyone holding the public key can re-verify.

About 23,000 lines of Rust across 18 crates, with over 370 tests. Built and run by one person.

---

## Start here: the tool-call gate

`ductei-mcp-gate` sits between any MCP (Model Context Protocol) client and any MCP server. The agent keeps working as before, but every tool call now passes a policy and leaves a receipt.

```
  MCP client  --stdio-->  ductei-mcp-gate  --stdio-->  real MCP server
  (the agent)                   |
                                |-- policy          one scope per tool, deny by default
                                |-- channel.jsonl   call saved before it is forwarded,
                                |                   result saved before it is returned
                                |-- denied.jsonl    calls that never reached the server
                                `-- receipts.jsonl  hash-chained, optionally ML-DSA signed
```

What that buys you:

- **The server never sees a denied call**, and the agent is never shown a tool it may not use.
- **The agent never sees a result the gate could not save.**
- **Every call, result and refusal is one line on a tamper-evident timeline.**
- **A cut-off log is caught too.** The gate signs its latest position every few receipts and sends that to a second machine, so deleting the end of the log is detectable.
- **Whoever can write the log folder cannot rewrite history.** The verifier takes its key from you, not from the folder.

```powershell
cargo build -p ductei-mcp --release --features sign
```

```powershell
.\target\release\ductei-mcp-gate.exe verify .\ductei --fingerprint 0000000000000000000000000000000000000000000000000000000000000000
```

Replace the zeros with the fingerprint the gate prints on its first signed run. Config format, key pinning and anchoring are covered in [ductei-mcp/README.md](ductei-mcp/README.md).

---

## Running in practice

This is not a demo. The author's own machines have run on it daily since October 2026. As of mid November 2026:

- One gate instance has recorded over **150,000 signed receipts** for a live MCP server. The whole chain is re-verified every night against a pinned key.
- A supervisor (`atrium`) watches seven long-running services and records every state change on its own signed chain, currently over **88,000 receipts**.
- Both chains are anchored to a second machine that runs a live witness (`atrium-watch`). It raises an alarm on a rollback, a fork, a bad signature or silence.
- A nightly job takes the stack down, verifies every chain, runs the end-to-end tests and brings it back up. A failed check is a failed night.
- A job door (`atrium-os`) takes one request through policy, routing, execution and storage, and returns a single receipt that can be checked against the signed chain.

---

## Design rules

1. **Scopes are deny by default.** They are first-class fields on every envelope, checked at the channel boundary on send. One forbidden scope rejects the whole envelope. Receivers never filter.
2. **Persistence before acknowledgement.** The log is append-only and fsynced. Nothing is acked before it is in the log.
3. **Bounded sessions only.** A session without a limit cannot be expressed in the types.
4. **Stale updates are refused.** An ordering gate rejects out-of-order or repeated updates, logs the refusal, and rebuilds its state from the log after a restart.
5. **Credentials never enter a payload.** Adapter types are closed. Unknown fields such as API tokens are dropped before anything reaches the channel.
6. **Nothing fails silently.** A missed deadline, a refused call and a lost peer are outcomes with receipts, the same as a success.

---

## What is in the workspace

**Channel and transport**

| Crate | Role |
|---|---|
| `ductei-core` | Scopes, envelopes, the append-only log, the channel, bounded sessions, the ordering gate, TCP transport (gRPC and QUIC behind features) |
| `ductei-sync` | Peer sync between machines over a mutually authenticated, post-quantum (ML-KEM-768) encrypted link |
| `ductei-braid` | Three hash-chained ledgers that anchor each other |

**Gates and receipts**

| Crate | Role |
|---|---|
| `ductei-mcp` | The tool-call gate for MCP servers, the receipt log and its verifier |
| `ductei-router` | Task router: policy gate, deterministic tier choice, receipt. It decides and records, and never executes |
| `ductei-verify` | Fail-closed gate for machine-written code changes: static checks, then build, lint and tests, with a kill switch and a ledger |

**Runtime**

| Crate | Role |
|---|---|
| `atrium-ctl` | Supervisor for long-running services, with a signed heartbeat chain and remote control verbs |
| `atrium-os` | The job door: one request in, one verifiable receipt out |
| `atrium-watch` | Live witness that runs on a second machine and alarms on tampering or silence |
| `ductei-qhr`, `qhr-sched`, `qhr-cell` | Local job runtime: pre-flight checks, deadlines, speculative branches with a verified commit |
| `ductei-agent` | Small agent loop where an idle agent is only its history on disk, and each turn is saved before a tool is dispatched |

**Adapters and tools**

| Crate | Role |
|---|---|
| `ductei-limen` | Carries quantum job certificates from [LIMEN](https://github.com/xingxerx/LIMEN) as scoped envelopes |
| `ductei-qallow` | Byte-compatible wire format for the Qallow C store, with a gated ingest path |
| `ductei-veyn` | Sensor and actuator events as narrowly scoped envelopes |
| `atrium-spec` | Contract compiler: one spec file emits matching Rust, C and Python types, so a renamed field fails the build instead of the nightly run |
| `qsw-inspect` | Decode and diff the wire format from the command line |

---

## How it is checked

- **Unit and integration tests** across the workspace: `cargo test --workspace`.
- **Four end-to-end jobs in CI**, including a closed loop that runs a sensor event through the channel, a C datastore, a quantum routing daemon and back.
- **Model checking.** Nine [Kani](https://github.com/model-checking/kani) proof harnesses cover the core channel and the wire format.
- **A conformance oracle.** The Rust encoder's output is fed one byte at a time through the real C decoder it must interoperate with.
- **The nightly run described above**, against live data rather than fixtures.

```powershell
cargo test --workspace
```

```powershell
cargo clippy --workspace --all-targets -- -D warnings
```

---

## What this does not claim

- **A receipt proves integrity, order and authorship.** It does not prove the tool did the right thing.
- **Anchoring needs the second machine to be online.** While it is off, anchors queue and catch up later, and a cut log is not detectable for that window.
- **One maintainer, one deployment.** It has not been load tested or independently audited.
- **The operations tooling is Windows first.** The core crates are portable and CI runs on Linux.
- **gRPC and QUIC transports are opt-in** and have seen less use than TCP.

---

## More detail

- Transport, wire format versions, the C ingest contract and the closed loop: [docs/DESIGN.md](docs/DESIGN.md)
- The tool-call gate: [ductei-mcp/README.md](ductei-mcp/README.md)
- Reporting a vulnerability: [SECURITY.md](SECURITY.md)

## License

Apache-2.0 (see [LICENSE](LICENSE)), except `atrium-os`, which is under the Elastic License 2.0.

---

*DUCTEI, pronounced DUCK-tay: from Latin ductus and Greek eimai, "the channel that persists".*
