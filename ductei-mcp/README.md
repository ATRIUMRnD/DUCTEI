# ductei-mcp

`ductei-mcp-gate` sits between any MCP (Model Context Protocol) client and any
MCP server over stdio, and makes every tool call pass through a DUCTEI channel.

```
Claude Desktop / Claude Code ──stdio──▶ ductei-mcp-gate ──stdio──▶ real MCP server
                                            │
                                            ├─ ScopePolicy  mcp:{server}:{tool}   deny-by-default
                                            ├─ channel.jsonl  call persisted before forward,
                                            │                 result persisted before return
                                            ├─ denied.jsonl   calls that never reached the server
                                            └─ receipts.jsonl hash-chained, optionally ML-DSA signed
```

The server never sees a denied call. The client never sees a result the gate
could not persist. Every call/result pair (and every refusal) is one receipt
on an append-only, hash-chained timeline that `verify` recomputes.

## Build

```powershell
cargo build -p ductei-mcp --release                   # unsigned receipts (scheme = "none")
cargo build -p ductei-mcp --release --features sign   # ML-DSA-65 / ML-DSA-87 receipts
```

## Config

```toml
[server]
name = "video-watch"            # used in scopes and keys
command = "D:/dev/video-watch/target/release/video-watch-mcp.exe"
args = []

[policy]
allow = ["watch_start", "watch_frame"]   # tool names; empty list blocks every call
max_calls_per_session = 500

[log]
dir = "D:/dev/video-watch/ductei"       # default: ./ductei next to this file

[sign]
scheme = "ml-dsa-65"                     # "none" | "ml-dsa-65" | "ml-dsa-87" (CNSA 2.0)
# key_store = "auto"                     # "auto" (DPAPI on Windows) | "dpapi" | "plaintext"
# insecure_plaintext_key = false         # must be true to allow key_store = "plaintext"
# pubkey_fingerprint = "<sha256 hex>"    # printed on first run; once set, a different key refuses to start

[anchor]
every = 10                               # sign the chain head every N receipts (0 = off); also on exit
peers = ["100.x.y.z:7421"]               # DUCTEI TCP peers; each must allow scope mcp:{server}:anchor
connect_timeout_ms = 2000
```

Point the client at the gate instead of the server, e.g. in `claude_desktop_config.json`:

```json
{ "mcpServers": { "video-watch": {
    "command": "D:/dev/ATRIUM/DUCTEI/target/release/ductei-mcp-gate.exe",
    "args": ["run", "D:/dev/video-watch/ductei-mcp.toml"] } } }
```

## Pin the key

On the first signed run the gate mints a keypair and prints its fingerprint
(SHA-256 of the public key). Copy it somewhere this machine cannot edit and set
`sign.pubkey_fingerprint`. Later:

```powershell
.\target\release\ductei-mcp-gate.exe fingerprint D:\dev\video-watch\ductei
```

## Verify the timeline

```powershell
.\target\release\ductei-mcp-gate.exe verify D:\dev\video-watch\ductei --fingerprint <sha256 hex>
```

or `--pubkey <file>` with a copy of the `.pk` you keep elsewhere. Exit 0 and
`ok: N receipts, chain intact`, or exit 1 with each problem listed. The
verifier does not trust the `.pk` in the log dir (a writer there could re-key
history); `--allow-unpinned` checks integrity and order only.

`verify` checks: seq and `prev` chain, body hash, receipt version, `kid` equals
the trusted key, ML-DSA signature over `"ductei-mcp-receipt-v1\0" || hash`,
and that every accepted call/result hash exists in `channel.jsonl` and every
denied call hash in `denied.jsonl`.

A hash chain cannot see a cut tail, so the gate also **anchors**: every
`anchor.every` receipts (and on exit) it signs `(seq, head)` and pushes that as
a DUCTEI envelope to each peer, with a local copy in `anchors.jsonl`. Hand the
peer's `channel.jsonl` to verify, or type the head you copied down:

```powershell
.\target\release\ductei-mcp-gate.exe verify D:\dev\video-watch\ductei --fingerprint <sha256 hex> --anchor-file \\xing-pc\...\channel.jsonl
```

```powershell
.\target\release\ductei-mcp-gate.exe verify D:\dev\video-watch\ductei --fingerprint <sha256 hex> --anchor 41:<hash>
```

The highest anchor signed by the trusted key must be present with the same
hash; if the file ends before it, verify reports `TRUNCATED`. Anchors from the
log dir itself prove nothing (same writer), which is why they go to a peer.
The pusher runs on its own thread, keeps only the newest unsent anchor, and
retries it on the next anchor and at exit; an unreachable peer never stalls
the relay.

## Launch nonce

The gate starts the server with `DUCTEI_GATE_NONCE=<64 hex>` and
`DUCTEI_GATE_DIR=<log dir>`, and writes `gate-launch.json` (`gate_pid`,
`node_id`, `nonce_sha256`, `server`) to the log dir for the life of the
session. A server built to be gate-only refuses stdio unless the env nonce is
present and hashes to the record. That stops a client configured straight at
the server by mistake; it does not stop a deliberate same-user bypass.

## Files in the log dir

| File | What |
|---|---|
| `channel.jsonl` | ductei-core `LogStore`: accepted call (flags 0) and result (flags 1) envelopes |
| `denied.jsonl` | envelopes refused by policy, bound, or persistence failure |
| `rejected.jsonl` | ductei-core causal-gate stale rejections |
| `receipts.jsonl` | one receipt per closed loop; `prev` links to the previous `hash` |
| `gate-node-id` | this gate's persisted 16-byte node id (one per install) |
| `anchors.jsonl` | local copy of every anchor pushed (same writer as the receipts, so not proof on its own) |
| `outbox.jsonl` | ductei-core outbox: anchor push intents and acks |
| `gate-launch.json` | pid + nonce hash for the running session (removed on exit) |
| `gate-ml-dsa-*.pk` | signing public key (also keep a copy, or its fingerprint, off this machine) |
| `gate-ml-dsa-*.sk.dpapi` | secret key wrapped with DPAPI (user scope); `.sk` plaintext only with `key_store = "plaintext"` |

JSON-RPC errors the gate returns itself: `-32001` scope denied, `-32002`
session bound reached, `-32003` stale delta, `-32004` persistence failed.

## Limits (v1)

- stdio transport only; newline-delimited JSON-RPC as the MCP spec defines it.
- Only `tools/call` is gated. `tools/list` answers are filtered to the
  allowlist (hidden names go to stderr). `initialize`, resources, prompts and
  notifications pass through untouched.
- The session bound is a gate-side counter mirroring `ductei_core::SessionBudget`
  (which borrows the channel for its lifetime and cannot be shared across the
  two relay threads). Same semantics: once reached, closed for good.
- Receipts are written when a loop closes, so a denied call can get a lower
  `seq` than an earlier accepted call whose result arrived later. `lamport_call`
  is the issue order; `seq` is the close order.
- A result that fails to persist is dropped, not returned (invariant 4). The
  client sees a timeout for that id. Logged to stderr.
- DPAPI protects the key file from being copied off the machine; it does not
  protect against code running as the same Windows user.
- The launch nonce needs the server to check it; a server that ignores
  `DUCTEI_GATE_NONCE` can still be launched directly.
- Policy is by tool name only; no argument-level rules yet.
