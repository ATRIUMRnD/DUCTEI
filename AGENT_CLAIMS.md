# Agent claims (read before editing this checkout)

One session per file at a time. Add a line when you start, remove it when you stop.
Uncommitted work only; nothing here is pushed without Xing's go-ahead.

| Session | Machine / checkout | Files owned | Since (UTC) | Doing |
|---|---|---|---|---|
| mcp-gate-lockdown | xing-laptop C:\Users\there\ATRIUM\DUCTEI (branch feat/mcp-gate-net-timeouts, on top of ba38c52) | ductei-mcp/** only | 2026-10-26 03:00 | IN PROGRESS: review + fixes. Batch/duplicate-key/non-JSON bypass, deny-by-default for non-tool methods and server-initiated requests, duplicate in-flight ids, refuse broken chain on open, single-instance lock, lamport resume across all logs, signed session/policy receipt, log-dir ACL, tailnet-only anchor peers. |

Notes for other sessions:
- Do not edit ductei-mcp/ on either machine until this row says DONE. ductei-core is NOT touched by this session.
- The xing-pc copy at D:\ATRIUM\DUCTEI\ductei-mcp should be re-synced from this branch when this row says DONE.
