#!/usr/bin/env python3
# Copyright (C) 2026 xingxerx
#
# Licensed under the Apache License 2.0. See the LICENSE file in the
# repository root for the full terms.

"""End-to-end smoke test for brain correction sync across two nodes:

  node A: brain-adapt add -> brain-adapt sync export -> A/local/accepted.jsonl
          -> ductei-sync push --peer B
  node B: ductei-sync serve -> B/inbound/accepted.jsonl -> brain-adapt sync import
          -> ductei-qallow-relay -> `qallow ingest` -> real LMDB
          (ql_persist_merge_blob) -> `qallow get`

and back again for a delete. Both nodes run on this machine on loopback;
on two machines the only change is --listen/--peer/--allow-ip with
Tailscale addresses.

Scenarios:
  1. add on A reaches B's correction store and B's Qallow store
  2. delete on B reaches A; A's Qallow store holds a tombstone, and an
     older write merged after it does not resurrect the key (Qallow
     persist_lmdb tombstone retention)
  3. restart replicability: re-push and re-import change nothing
  4. deny by default: an unreachable peer leaves the push cursor alone,
     a non-loopback bind with no --allow-ip is refused, a scope the
     receiver did not allow is refused and witnessed on the sender

Invariants asserted inline:
  I2  deny-by-default scopes      receiver allows only brain.correction
  I4  persistence before ack      a delivered envelope is in B's inbound log
  no echo                         nothing in a node's inbound came from itself
  witness                         refusals land in failed/ and sync-refused.jsonl

Usage:
  python scripts/smoke_brain_sync.py --ductei-sync target/debug/ductei-sync \
      --qallow-relay target/debug/ductei-qallow-relay \
      --qallow-cli ../Qallow/target/debug/qallow \
      --brain-adapt ../brain/target/debug/brain-adapt [--workdir DIR]
"""

from __future__ import annotations

import argparse
import json
import shutil
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

PASS = "PASS"
FAIL = "FAIL"
_failures: list[str] = []
SCOPE = "brain.correction"


def check(ok: bool, what: str, detail: str = "") -> None:
    line = f"  [{PASS if ok else FAIL}] {what}"
    if detail and not ok:
        line += f"\n         got: {detail}"
    print(line)
    if not ok:
        _failures.append(what)


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Node:
    def __init__(self, name: str, root: Path, bins: argparse.Namespace):
        self.name = name
        self.root = root
        self.data = root / "brain-data"
        self.state = root / "sync"
        self.store = root / "qallow-store"
        self.bins = bins
        self.data.mkdir(parents=True)
        self.store.mkdir(parents=True)

    def adapt(self, *args: str) -> dict:
        out = subprocess.run(
            [str(self.bins.brain_adapt), "--dir", str(self.data), *args],
            check=True, capture_output=True, text=True,
        ).stdout
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            return {"stdout": out}

    def sync(self, cmd: str) -> dict:
        return self.adapt("sync", "--state", str(self.state), cmd)

    def live_ids(self) -> list[str]:
        out = subprocess.run(
            [str(self.bins.brain_adapt), "--dir", str(self.data), "list", "--json"],
            check=True, capture_output=True, text=True,
        ).stdout
        return [json.loads(l)["id"] for l in out.splitlines() if l.strip().startswith("{")]

    def serve_once(self, port: int, scopes: list[str]) -> subprocess.Popen:
        args = [str(self.bins.ductei_sync), "serve", str(self.state), "--listen", f"127.0.0.1:{port}", "--once"]
        for s in scopes:
            args += ["--scope", s]
        p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        # serve prints its banner only after bind() succeeded
        banner = p.stdout.readline() if p.stdout else ""
        if "ductei-sync serve:" not in banner:
            raise RuntimeError(f"serve did not start: {banner}{p.stderr.read() if p.stderr else ''}")
        return p

    def push(self, port: int) -> str:
        return subprocess.run(
            [str(self.bins.ductei_sync), "push", str(self.state), "--peer", f"127.0.0.1:{port}", "--once"],
            check=True, capture_output=True, text=True,
        ).stdout

    def relay(self, which: str) -> None:
        """Persist one of this node's DUCTEI logs into its Qallow store."""
        subprocess.run(
            [str(self.bins.qallow_relay), str(self.state / which), str(self.root / f"relay-{which}"),
             "--once", "--qallow-cli", str(self.bins.qallow_cli), "--store-dir", str(self.store)],
            check=True, capture_output=True, text=True,
        )

    def qallow_get(self, cid: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [str(self.bins.qallow_cli), "get", str(self.store), f"{SCOPE}|brain/correction/{cid}"],
            capture_output=True, text=True,
        )


def deliver(src: Node, dst: Node, scopes: list[str] | None = None) -> str:
    port = free_port()
    srv = dst.serve_once(port, scopes or [SCOPE])
    out = src.push(port)
    srv.wait(timeout=20)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ductei-sync", type=Path, required=True)
    ap.add_argument("--qallow-relay", type=Path, required=True)
    ap.add_argument("--qallow-cli", type=Path, required=True)
    ap.add_argument("--brain-adapt", type=Path, required=True)
    ap.add_argument("--workdir", type=Path)
    bins = ap.parse_args()
    for b in (bins.ductei_sync, bins.qallow_relay, bins.qallow_cli, bins.brain_adapt):
        if not b.exists():
            print(f"missing binary: {b}")
            return 2

    work = bins.workdir or Path(tempfile.mkdtemp(prefix="smoke-brain-sync-"))
    if work.exists():
        shutil.rmtree(work)
    a = Node("A", work / "A", bins)
    b = Node("B", work / "B", bins)
    na = a.sync("status")["node"]
    nb = b.sync("status")["node"]

    print("1. add on A reaches B (brain store + Qallow LMDB)")
    a.adapt("add", "--prompt", "delete every file in the repo",
            "--model-output", '{"decision":"act"}', "--correction", '{"decision":"ask"}',
            "--kind", "decision", "--check-decision", "ask")
    cid = a.live_ids()[0]
    exp = a.sync("export")["export"]
    check(exp["corrections"] == 1, "A exports 1 correction", str(exp))
    out = deliver(a, b)
    check("delivered=1" in out, "push A->B delivered 1", out)
    inbound_b = read_jsonl(b.state / "inbound" / "accepted.jsonl")
    check(len(inbound_b) == 1 and inbound_b[0]["key"] == f"brain/correction/{cid}",
          "I4: delivered envelope is persisted in B/inbound", str(inbound_b))
    imp = b.sync("import")["import"]
    check(imp["added"] == 1 and b.live_ids() == [cid], "B imports it as a live correction", str(imp))
    verify = subprocess.run([str(bins.brain_adapt), "--dir", str(b.data), "verify"],
                            capture_output=True, text=True)
    check(verify.returncode == 0, "B's hash chain verifies after import", verify.stderr)
    b.relay("inbound")
    got = b.qallow_get(cid)
    check(got.returncode == 0 and cid in got.stdout and "NOT_FOUND" not in got.stdout,
          "B's Qallow store holds the correction", got.stdout + got.stderr)

    print("2. delete on B reaches A; Qallow keeps the tombstone")
    subprocess.run([str(bins.brain_adapt), "--dir", str(b.data), "delete", cid, "--reason", "wrong lesson"],
                   check=True, capture_output=True)
    exp = b.sync("export")["export"]
    check(exp == {"corrections": 0, "deletes": 1, "skipped_imported": 1}, "B exports the delete, not the import", str(exp))
    out = deliver(b, a)
    check("delivered=1" in out, "push B->A delivered 1", out)
    imp = a.sync("import")["import"]
    check(imp["deleted"] == 1 and a.live_ids() == [], "A applies the delete", str(imp))
    # Worst order for A's Qallow store: the newer delete merges before the older add.
    a.relay("inbound")
    a.relay("local")
    got = a.qallow_get(cid)
    check(got.returncode == 0 and got.stdout.strip() == "NOT_FOUND",
          "older add merged after the delete does not resurrect it in Qallow",
          got.stdout + got.stderr)

    print("3. restart replicability")
    for f in (a.state / "cursors").glob("push-*"):
        f.unlink()
    out = deliver(a, b)
    check(len(read_jsonl(b.state / "inbound" / "accepted.jsonl")) == 1, "re-push after cursor loss adds nothing", out)
    st = json.loads((b.data / "sync-state.json").read_text())
    st["import_cursor"] = 0
    (b.data / "sync-state.json").write_text(json.dumps(st))
    imp = b.sync("import")["import"]
    check(imp["added"] == 0 and b.live_ids() == [], "re-import from line 0 does not resurrect", str(imp))

    print("4. deny by default and witnessing")
    a.adapt("add", "--prompt", "format the disk", "--model-output", '{"decision":"act"}',
            "--correction", '{"decision":"ask"}', "--kind", "decision", "--check-decision", "ask")
    a.sync("export")
    dead = free_port()
    out = a.push(dead)
    check("unreachable" in out, "unreachable peer: push stops and will retry", out)
    out = deliver(a, b, scopes=["some.other.scope"])
    failed = list((a.state / "failed").glob("push-*.jsonl"))
    check("delivered=0" in out and "refused=0" not in out and failed and read_jsonl(failed[0]),
          "I2: scope B did not allow is refused (ack 0) and witnessed on A", out)
    # --plaintext gets past the no-qfltl-build gate (which refuses first) so this
    # exercises the --allow-ip deny-by-default rule it names.
    bad = subprocess.run([str(bins.ductei_sync), "serve", str(b.state), "--listen", "0.0.0.0:0", "--scope", SCOPE, "--plaintext"],
                         capture_output=True, text=True, timeout=10)
    check(bad.returncode != 0 and "allow-ip" in bad.stderr, "non-loopback bind without --allow-ip is refused", bad.stderr)
    for n, me in ((a, na), (b, nb)):
        echoes = [e for e in read_jsonl(n.state / "inbound" / "accepted.jsonl") if bytes(e["node_id"]).hex() == me]
        check(not echoes, f"no echo: node {n.name} never received its own envelopes")

    print()
    if _failures:
        print(f"FAILED: {len(_failures)} check(s): {_failures}")
        return 1
    print(f"all checks passed (workdir {work})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
