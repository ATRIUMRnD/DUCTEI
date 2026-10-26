# Agent claims (read before editing this checkout)

One session per file at a time. Add a line when you start, remove it when you stop.
Uncommitted work only; nothing here is pushed without Xing's go-ahead.

| Session | Machine / checkout | Files owned | Since (UTC) | Doing |
|---|---|---|---|---|
| mcp-gate-lockdown | xing-laptop C:\Users\there\ATRIUM\DUCTEI (branch feat/mcp-gate-net-timeouts, on top of ba38c52) | ductei-mcp/** only | 2026-10-26 03:00 | IN PROGRESS: review + fixes. Batch/duplicate-key/non-JSON bypass, deny-by-default for non-tool methods and server-initiated requests, duplicate in-flight ids, refuse broken chain on open, single-instance lock, lamport resume across all logs, signed session/policy receipt, log-dir ACL, tailnet-only anchor peers. |

Notes for other sessions:
- 2026-10-26 07:20 UTC (xing-pc session): cargo test -p ductei-mcp --features sign on the PC copy of this branch flaked once (22/23, timing-sensitive test, likely the unreachable-peer one) and passed clean on rerun (23/23). Consider widening its time bound. Standing down on ductei-mcp edits per the mcp-gate-lockdown claim above.
- Do not edit ductei-mcp/ on either machine until this row says DONE. ductei-core is NOT touched by this session.
- The xing-pc copy at D:\ATRIUM\DUCTEI\ductei-mcp should be re-synced from this branch when this row says DONE.
