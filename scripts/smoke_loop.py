#!/usr/bin/env python3
# Copyright (C) 2026 xingxerx
#
# Licensed under the Apache License 2.0. See the LICENSE file in the
# repository root for the full terms.

"""One-app smoke: the whole ecosystem as a single closed loop.

    BODY            NERVOUS SYSTEM         MIND                 HANDS
    VEYN bridge ->  ductei-qallow-relay -> qallow ingest/LMDB -> qallow propose
      (rem cue)       (VEYN hop)             (one shared store)     |
                                                                    v
    LMDB <- qallow ingest <- ductei-qallow-relay <- ductei-limen-relay <- limend
     (same store)              (LIMEN hop)                             (certifies)

Every hop is the real production binary (ductei_bridge_smoke drives the
exact DucteiBridge path veyn-core's dispatcher uses; both relay hops are
the unmodified ductei-qallow-relay; `qallow propose` reads the real LMDB
store; limend runs LIMEN's real router on the offline simulator path).
The two relay hops share ONE `--store-dir`, so the sensor cue and the
certificate it caused live in the same durable state -- that is what
"one app" means at the persistence layer.

Scenarios (the standard four, over the full loop):
  1. good cue            REM cue -> LMDB -> proposal -> limend cert ->
                          LMDB; both records readable via `qallow get`
  2. restart replicability every process is fresh per step; a second
                          cue flows through with all node ids / cursors
                          intact and no re-proposal of the first cue
  3. malformed / non-cue  an HRV sample never proposes; an unpersisted
                          key never proposes (exit 1, nothing written);
                          a malformed spool request is witnessed in
                          failed/ and never reaches the store
  4. invariants           I1 credential sentinel absent from every log,
                          frame, spool file and LMDB value; I2 scopes
                          exact per hop; I4 sent/ implies gettable;
                          I5 exactly one accepted line per hop per cue

Usage:
  python scripts/smoke_loop.py --limen <LIMEN checkout> --veyn <VEYN checkout> \
      --qallow-cli <built qallow binary> \
      [--relay <ductei-limen-relay>] [--qallow-relay <ductei-qallow-relay>] \
      [--workdir DIR]
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

PASS = "PASS"
FAIL = "FAIL"
TOKEN_SENTINEL = "SMOKE-LOOP-SECRET-TOKEN-do-not-leak"
CERT_SCOPE = "qallow.semantic.cert"
REM_SCOPE = "veyn.rem_event"
FORWARD_SCOPE = "qallow.ingest.forwarded"
_failures: list[str] = []


def check(ok: bool, what: str, detail: str = "") -> None:
    tag = PASS if ok else FAIL
    line = f"  [{tag}] {what}"
    if detail and not ok:
        line += f"\n         expected: {detail}"
    print(line)
    if not ok:
        _failures.append(what)


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run([str(c) for c in cmd], capture_output=True, text=True, **kw)


class Loop:
    """All the binaries and directories of one loop instance."""

    def __init__(self, args: argparse.Namespace, root: Path, smoke_bin: Path):
        self.limen_dir = args.limen
        self.qallow = args.qallow_cli
        self.relay = args.relay
        self.qrelay = args.qallow_relay
        self.smoke_bin = smoke_bin
        self.veyn = root / "veyn"            # VEYN's own DUCTEI channel log
        self.veyn_out = root / "veyn-out"    # VEYN-hop relay state
        self.spool = root / "spool"          # limend's tree
        self.limen_ductei = root / "ductei"  # ductei-limen-relay state (sibling of spool)
        self.limen_out = root / "limen-out"  # LIMEN-hop relay state
        self.store = root / "store"          # THE shared LMDB store
        for d in ("pending", "done", "certs", "failed"):
            (self.spool / d).mkdir(parents=True, exist_ok=True)
        self.veyn.mkdir(parents=True, exist_ok=True)
        self.store.mkdir(parents=True, exist_ok=True)

    # --- body: VEYN bridge --------------------------------------------
    def sense(self, events: list[dict]) -> subprocess.CompletedProcess:
        f = self.veyn / "events.json"
        f.write_text(json.dumps(events))
        return run([self.smoke_bin, self.veyn / "accepted.jsonl", self.veyn / "rejected.jsonl", f])

    # --- nervous system: relays ------------------------------------------
    def relay_veyn_hop(self) -> None:
        r = run([self.qrelay, self.veyn, self.veyn_out, "--once", "--qallow-cli", self.qallow,
                 "--store-dir", self.store])
        r.check_returncode()

    def relay_limen_hop(self) -> None:
        r = run([self.relay, self.spool, "--once"])
        r.check_returncode()
        r = run([self.qrelay, self.limen_ductei, self.limen_out, "--once", "--qallow-cli", self.qallow,
                 "--store-dir", self.store])
        r.check_returncode()

    # --- mind: Qallow ----------------------------------------------------
    def get(self, key: str) -> str | None:
        out = run([self.qallow, "get", self.store, key])
        out.check_returncode()
        text = out.stdout.strip()
        if text == "NOT_FOUND":
            return None
        assert text.startswith("FOUND:"), text
        return text[len("FOUND:"):]

    def propose(self, key: str) -> subprocess.CompletedProcess:
        return run([self.qallow, "propose", self.store, key, self.spool])

    # --- hands: LIMEN ----------------------------------------------------
    def think(self) -> None:
        env = dict(os.environ)
        env["LIMEN_QPU_TOKEN"] = TOKEN_SENTINEL  # I1: must never leave limend's env
        r = run([sys.executable, "-m", "limen.limend", self.spool, "--once"], cwd=self.limen_dir, env=env)
        r.check_returncode()

    # --- helpers ---------------------------------------------------------
    def rem_keys(self) -> list[str]:
        return [e["key"] for e in read_jsonl(self.veyn / "accepted.jsonl") if e["scopes"] == [REM_SCOPE]]

    def job_id_for(self, store_key: str) -> str:
        body = "".join(c if c.isalnum() or c in "-_" else "_" for c in store_key)[:72]
        return f"qallow-{body}"


def full_cycle(loop: Loop, device: str) -> tuple[str, str]:
    """Runs one REM cue around the whole loop. Returns (store_key, job_id)."""
    r = loop.sense([{"device_id": device, "source": "watch", "metric": "rem_detected", "value": 1.0, "unit": "bool"}])
    check(r.returncode == 0, f"VEYN bridge accepted the REM cue from {device}", r.stderr)
    loop.relay_veyn_hop()
    key = loop.rem_keys()[-1]
    store_key = f"{REM_SCOPE}|{key}"
    check(loop.get(store_key) is not None, "REM cue persisted in the shared LMDB store", "FOUND")

    p = loop.propose(store_key)
    check(p.returncode == 0 and "proposed:" in p.stdout, "`qallow propose` wrote a LIMEN request from durable state",
          p.stdout + p.stderr)
    job_id = loop.job_id_for(store_key)
    req = loop.spool / "pending" / f"{job_id}.json"
    check(req.exists(), "request landed in limend's spool/pending/", str(req))
    if req.exists():
        data = json.loads(req.read_text())
        check(data.get("offline") is True and "token" not in req.read_text().lower(),
              "request is offline and carries no credential-shaped field (I1)", "offline true, no token")

    loop.think()
    cert = loop.spool / "certs" / f"{job_id}.json"
    check(cert.exists(), "limend certified the proposed job", str(cert))
    loop.relay_limen_hop()
    cert_val = loop.get(f"{CERT_SCOPE}|limen.cert.{job_id}")
    check(cert_val is not None, "certificate persisted in the SAME store as the cue that caused it", "FOUND")
    if cert_val:
        c = json.loads(cert_val)
        check(c.get("job_id") == job_id and "backend" in c and "tier" in c,
              "stored certificate is LIMEN's real CertSummary for that job", "job_id/backend/tier")
    return store_key, job_id


def scenario_good(loop: Loop) -> tuple[str, str]:
    print("scenario 1: good cue, full loop")
    return full_cycle(loop, "oneiro-watch-1")


def scenario_restart(loop: Loop, first: tuple[str, str]) -> None:
    print("scenario 2: restart replicability (every process fresh)")
    veyn_node = (loop.veyn_out / "ductei" / "relay-node-id").read_text().strip()
    limen_node = (loop.limen_out / "ductei" / "relay-node-id").read_text().strip()
    v_before = len(read_jsonl(loop.veyn_out / "ductei" / "accepted.jsonl"))
    l_before = len(read_jsonl(loop.limen_out / "ductei" / "accepted.jsonl"))

    _, job2 = full_cycle(loop, "oneiro-watch-2")

    check((loop.veyn_out / "ductei" / "relay-node-id").read_text().strip() == veyn_node,
          "VEYN-hop relay node id survives restart", veyn_node)
    check((loop.limen_out / "ductei" / "relay-node-id").read_text().strip() == limen_node,
          "LIMEN-hop relay node id survives restart", limen_node)
    check(len(read_jsonl(loop.veyn_out / "ductei" / "accepted.jsonl")) == v_before + 1,
          "VEYN hop appended exactly one line for the second cue (I5)", f"{v_before + 1}")
    check(len(read_jsonl(loop.limen_out / "ductei" / "accepted.jsonl")) == l_before + 1,
          "LIMEN hop appended exactly one line for the second job (I5)", f"{l_before + 1}")

    # No re-proposal of the first cue after restart: idempotent by job id.
    p = loop.propose(first[0])
    check(p.returncode == 0 and "already proposed" in p.stdout,
          "re-running propose on the first cue after restart writes nothing", p.stdout)
    check(loop.get(f"{CERT_SCOPE}|limen.cert.{first[1]}") is not None
          and loop.get(f"{CERT_SCOPE}|limen.cert.{job2}") is not None,
          "both certificates reachable in the shared store after restart", "FOUND x2")


def scenario_malformed(loop: Loop) -> None:
    print("scenario 3: malformed input and non-cues")
    pending_before = sorted(p.name for p in (loop.spool / "pending").glob("*.json"))

    r = loop.sense([{"device_id": "oneiro-watch-1", "source": "healthkit", "metric": "hrv", "value": 55.0, "unit": "ms"}])
    check(r.returncode == 0, "an HRV sample flows through VEYN (not an error)", r.stderr)
    loop.relay_veyn_hop()
    hrv_key = [e["key"] for e in read_jsonl(loop.veyn / "accepted.jsonl") if e["scopes"] == ["veyn.hrv"]][-1]
    p = loop.propose(f"veyn.hrv|{hrv_key}")
    check(p.returncode == 0 and "no proposal" in p.stdout, "an HRV sample never becomes a LIMEN job", p.stdout)

    p = loop.propose(f"{REM_SCOPE}|veyn.watch.rem_detected.never-persisted")
    check(p.returncode != 0, "an unpersisted key never proposes (persistence before proposal)", "exit 1")
    check(sorted(p.name for p in (loop.spool / "pending").glob("*.json")) == pending_before,
          "nothing new in spool/pending/ after the non-cue and the unpersisted key", str(pending_before))

    bad = loop.spool / "pending" / "loop-badreq.json"
    bad.write_text("{this is not json")
    loop.think()
    check(not bad.exists() and (loop.spool / "failed" / "loop-badreq.json").exists(),
          "malformed request witnessed in spool/failed/", "failed/loop-badreq.json")
    failed = loop.spool / "failed" / "loop-badreq.json"
    if failed.exists():
        check(bool(json.loads(failed.read_text()).get("error")), "failure record is human-readable", "error field")
    loop.relay_limen_hop()
    check(loop.get(f"{CERT_SCOPE}|limen.cert.loop-badreq") is None, "malformed request never reaches the store", "NOT_FOUND")

    r = loop.sense([{"device_id": "bad", "source": "watch", "metric": "rem_detected", "unit": "bool"}])
    check(r.returncode != 0, "VEYN bridge aborts on a malformed event spec", "nonzero exit")


def scenario_invariants(loop: Loop, jobs: list[str]) -> None:
    print("scenario 4: invariants across the whole loop")
    artifacts = list(loop.veyn.glob("*.jsonl")) + list((loop.veyn_out / "ductei").glob("*.jsonl")) \
        + list(loop.limen_ductei.glob("*.jsonl")) + list((loop.limen_out / "ductei").glob("*.jsonl")) \
        + list(loop.spool.rglob("*.json")) + list(loop.veyn_out.rglob("*.qsw")) + list(loop.limen_out.rglob("*.qsw"))
    leaked = [a for a in artifacts if TOKEN_SENTINEL.encode() in a.read_bytes()]
    check(not leaked, "credential sentinel absent from every log, spool file and frame (I1)", str(leaked))
    for job in jobs:
        v = loop.get(f"{CERT_SCOPE}|limen.cert.{job}") or ""
        check(TOKEN_SENTINEL not in v, f"credential sentinel absent from LMDB value for {job} (I1)", "absent")

    veyn_scopes = {tuple(e["scopes"]) for e in read_jsonl(loop.veyn / "accepted.jsonl")}
    check(veyn_scopes <= {(REM_SCOPE,), ("veyn.hrv",)}, "VEYN channel carries only the narrow scopes it emitted (I2)",
          str(veyn_scopes))
    for hop in (loop.veyn_out, loop.limen_out):
        scopes = {tuple(e["scopes"]) for e in read_jsonl(hop / "ductei" / "accepted.jsonl")}
        check(scopes == {(FORWARD_SCOPE,)}, f"{hop.name} relay log carries exactly [{FORWARD_SCOPE}] (I2)", str(scopes))
    limen_scopes = {tuple(e["scopes"]) for e in read_jsonl(loop.limen_ductei / "accepted.jsonl")}
    check(limen_scopes == {(CERT_SCOPE,)}, f"LIMEN channel carries exactly [{CERT_SCOPE}] (I2)", str(limen_scopes))

    for hop in (loop.veyn_out, loop.limen_out):
        sent_count = len(list((hop / "sent").glob("*.qsw")))
        failed_count = len(list((hop / "failed").glob("*.qsw")))
        check(failed_count == 0, f"{hop.name}: no frame rejected by Qallow's persist gate", "0 failed")
        check(sent_count == len(read_jsonl(hop / "ductei" / "accepted.jsonl")),
              f"{hop.name}: every accepted line has a sent/ frame and vice versa (I4/I5)", "equal counts")


def build_relays(ductei_root: Path) -> tuple[Path, Path]:
    subprocess.run(["cargo", "build", "-p", "ductei-limen", "-p", "ductei-qallow"],
                   check=True, cwd=ductei_root, capture_output=True, text=True)
    exe = ".exe" if os.name == "nt" else ""
    return (ductei_root / "target" / "debug" / f"ductei-limen-relay{exe}",
            ductei_root / "target" / "debug" / f"ductei-qallow-relay{exe}")


def build_bridge_smoke(veyn: Path) -> Path:
    b = subprocess.run(["cargo", "build", "-p", "veyn-core", "--example", "ductei_bridge_smoke"],
                       cwd=veyn, capture_output=True, text=True)
    if b.returncode != 0:
        print(b.stdout)
        print(b.stderr)
        raise SystemExit(f"smoke-loop: VEYN build failed with exit {b.returncode}")
    exe = ".exe" if os.name == "nt" else ""
    return veyn / "target" / "debug" / "examples" / f"ductei_bridge_smoke{exe}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--limen", type=Path, required=True)
    parser.add_argument("--veyn", type=Path, required=True)
    parser.add_argument("--qallow-cli", type=Path, required=True)
    parser.add_argument("--relay", type=Path, default=None)
    parser.add_argument("--qallow-relay", type=Path, default=None)
    parser.add_argument("--workdir", type=Path, default=None)
    args = parser.parse_args()

    ductei_root = Path(__file__).resolve().parent.parent
    if args.relay is None or args.qallow_relay is None:
        r, q = build_relays(ductei_root)
        args.relay = args.relay or r
        args.qallow_relay = args.qallow_relay or q
    if not args.qallow_cli.exists():
        print(f"qallow_cli binary not found: {args.qallow_cli}")
        return 2
    smoke_bin = build_bridge_smoke(args.veyn)

    workdir = args.workdir or Path(tempfile.mkdtemp(prefix="ductei-smoke-loop-"))
    root = workdir / "loop"
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    loop = Loop(args, root, smoke_bin)
    print(f"smoke-loop: root={root}")
    print(f"smoke-loop: shared store={loop.store}\n")

    first = scenario_good(loop)
    scenario_restart(loop, first)
    scenario_malformed(loop)
    jobs = [p.stem for p in (loop.spool / "certs" / "sent").glob("*.json")]
    scenario_invariants(loop, jobs)

    print()
    if _failures:
        print(f"smoke-loop: {len(_failures)} check(s) failed:")
        for f in _failures:
            print(f"  - {f}")
        return 1
    print("smoke-loop: all four scenarios passed, the loop closed, invariants held")
    return 0


if __name__ == "__main__":
    sys.exit(main())
