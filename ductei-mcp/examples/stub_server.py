#!/usr/bin/env python3
"""Minimal newline-delimited MCP stdio server: initialize, tools/list, tools/call(echo|secret)."""
import json, sys
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    m = json.loads(line); mid = m.get("id"); meth = m.get("method")
    if meth == "initialize":
        r = {"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"stub","version":"0"}}
    elif meth == "tools/list":
        r = {"tools":[{"name":"echo","inputSchema":{"type":"object"}},{"name":"secret","inputSchema":{"type":"object"}}]}
    elif meth == "tools/call":
        r = {"content":[{"type":"text","text":"echo:"+json.dumps(m["params"].get("arguments",{}))}]}
    else:
        continue
    sys.stdout.write(json.dumps({"jsonrpc":"2.0","id":mid,"result":r})+"\n"); sys.stdout.flush()
