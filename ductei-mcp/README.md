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
denied call hash in `denied.jsonl`. It cannot detect tail truncation from the
file alone; compare the last `hash` against an anchor you hold elsewhere.

## Files in the log dir

| File | What |
|---|---|
| `channel.jsonl` | ductei-core `LogStore`: accepted call (flags 0) and result (flags 1) envelopes |
| `denied.jsonl` | envelopes refused by policy, bound, or persistence failure |
| `rejected.jsonl` | ductei-core causal-gate stale rejections |
| `receipts.jsonl` | one receipt per closed loop; `prev` links to the previous `hash` |
| `gate-node-id` | this gate's persisted 16-byte node id (one per install) |
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
  protect against code running as the same Windows user. Nothing stops a
  client from launching the real server directly; that is a server-side change
  (launch nonce) and is not in v1.
- Policy is by tool name only; no argument-level rules yet.
