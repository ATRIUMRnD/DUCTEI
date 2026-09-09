#!/usr/bin/env python3
# Copyright (C) 2026 xingxerx
#
# Licensed under the Apache License 2.0. See the LICENSE file in the
# repository root for the full terms.

"""atrium_up: run the whole ecosystem as one app, from one command.

Boots every long-running room process against a single root directory
and one shared Qallow LMDB store, then keeps the loop closed:

    VEYN daemon (or injected cues) -> VEYN's DUCTEI channel
      -> ductei-qallow-relay [VEYN hop]  -> shared LMDB store
      -> `qallow propose` (this supervisor, from durable state only)
      -> limend spool -> limend (certifies, offline simulator by default)
      -> ductei-limen-relay -> ductei-qallow-relay [LIMEN hop] -> shared store

Processes supervised (all real binaries, all polling, none modified):
  limend                    python -m limen.limend <root>/spool
  ductei-limen-relay        <root>/spool           (state: <root>/ductei)
  ductei-qallow-relay       <root>/ductei -> <root>/limen-out   --store-dir <root>/store
  ductei-qallow-relay       <root>/veyn   -> <root>/veyn-out    --store-dir <root>/store
  veyn-core (optional)      --veyn-daemon: real daemon, mock adapter + OSC
                            9000, DUCTEI bridge logging to <root>/veyn/

The proposer runs in this process: it tails <root>/veyn/accepted.jsonl,
and for every `veyn.rem_event` envelope calls `qallow propose` until the
cue is persisted (persistence before proposal; a not-yet-ingested cue is
retried on the next tick, never skipped). Its cursor is persisted, so a
restarted supervisor never re-proposes -- and `qallow propose` is
idempotent by job id anyway.

Cues:
  --inject          push one REM cue through the exact production
                    DucteiBridge path (ductei_bridge_smoke) at startup
  --osc-cue         send an Øneiro-shaped /oneiro/watch OSC packet
                    (stage "REM") to the VEYN daemon's OSC port; needs
                    --veyn-daemon

Credentials: none are read or written here. limend takes LIMEN_QPU_TOKEN
from its own environment only; every proposal is `offline: true`.

Usage:
  python scripts/atrium_up.py --root <dir> --limen <LIMEN checkout> \
      --qallow-cli <qallow binary> [--veyn <VEYN checkout>] \
      [--veyn-daemon] [--inject] [--osc-cue] [--poll-ms 1000] [--once]
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

REM_SCOPE = "veyn.rem_event"
EXE = ".exe" if os.name == "nt" else ""


def log(msg: str) -> None:
    print(f"[atrium] {time.strftime('%H:%M:%S')} {msg}", flush=True)


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]


# --- OSC (hand-encoded; the only Øneiro-shaped input VEYN needs) ----------
def _osc_str(s: str) -> bytes:
    b = s.encode() + b"\0"
    return b + b"\0" * ((4 - len(b) % 4) % 4)


def osc_watch_packet(heart_rate: float, stage: str, baseline_hr: float, elapsed_min: float,
                     cue_count: int, device_id: str) -> bytes:
    # /oneiro/watch: Float hr, String stage, Float baseline, Float elapsed, Int cue_count, String device
    return (_osc_str("/oneiro/watch") + _osc_str(",fsffis")
            + struct.pack(">f", heart_rate) + _osc_str(stage) + struct.pack(">f", baseline_hr)
            + struct.pack(">f", elapsed_min) + struct.pack(">i", cue_count) + _osc_str(device_id))


def send_osc_cue(port: int, device_id: str) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        # Two packets: a non-REM stage first so the second is a rising edge.
        s.sendto(osc_watch_packet(58.0, "N2", 60.0, 120.0, 0, device_id), ("127.0.0.1", port))
        time.sleep(0.2)
        s.sendto(osc_watch_packet(64.0, "REM", 60.0, 121.0, 1, device_id), ("127.0.0.1", port))
    log(f"OSC cue sent to udp/{port}: /oneiro/watch stage N2 -> REM ({device_id})")


# --- Proposer ---------------------------------------------------------------
class Proposer:
    def __init__(self, qallow: Path, store: Path, spool: Path, veyn_log: Path, state_dir: Path):
        self.qallow, self.store, self.spool, self.veyn_log = qallow, store, spool, veyn_log
        self.cursor_file = state_dir / "propose-cursor"
        self.cursor = int(self.cursor_file.read_text().strip()) if self.cursor_file.exists() else 0
        self.retry: dict[str, int] = {}

    def tick(self) -> None:
        entries = read_jsonl(self.veyn_log)
        for i in range(self.cursor, len(entries)):
            e = entries[i]
            if e.get("scopes") == [REM_SCOPE]:
                key = f"{REM_SCOPE}|{e['key']}"
                r = subprocess.run([str(self.qallow), "propose", str(self.store), key, str(self.spool)],
                                   capture_output=True, text=True)
                if r.returncode != 0:
                    # Not persisted yet (VEYN hop still in flight): retry next tick, keep the cursor here.
                    n = self.retry.get(key, 0) + 1
                    self.retry[key] = n
                    if n in (1, 10, 100):
                        log(f"propose deferred ({n}x): {r.stderr.strip() or r.stdout.strip()}")
                    return
                log(r.stdout.strip())
            self.cursor = i + 1
            self.cursor_file.write_text(str(self.cursor))


# --- Supervisor ------------------------------------------------------------
class Supervisor:
    def __init__(self) -> None:
        self.procs: list[tuple[str, subprocess.Popen]] = []
        self.reported: set[str] = set()

    def start(self, name: str, cmd: list[str], **kw) -> None:
        p = subprocess.Popen([str(c) for c in cmd], **kw)
        self.procs.append((name, p))
        log(f"started {name} (pid {p.pid})")

    def check(self) -> None:
        for name, p in self.procs:
            rc = p.poll()
            if rc is not None and name not in self.reported:
                self.reported.add(name)
                log(f"{name} exited with {rc} -- witnessed, not restarted punitively; stop with Ctrl+C and inspect")

    def stop(self) -> None:
        for name, p in reversed(self.procs):
            if p.poll() is None:
                p.terminate()
        for name, p in reversed(self.procs):
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
            log(f"stopped {name}")


def write_veyn_config(root: Path, osc_port: int, api_port: int) -> Path:
    cfg = root / "veyn.toml"
    cfg.write_text(f"""# generated by atrium_up.py -- one-app run
[server]
port = {api_port}

[security]
require_auth = true
token_path = "{(root / 'veyn' / 'token').as_posix()}"
audit_log_path = "{(root / 'veyn' / 'audit.log').as_posix()}"

[adapters]
mock = true
eeg = true
osc_port = {osc_port}

[logging]
level = "info"
jsonl_path = "{(root / 'veyn' / 'veyn-events.jsonl').as_posix()}"
db_path = "{(root / 'veyn' / 'veyn.db').as_posix()}"

[ductei]
enabled = true
log_path = "{(root / 'veyn' / 'accepted.jsonl').as_posix()}"
reject_log_path = "{(root / 'veyn' / 'rejected.jsonl').as_posix()}"

[evolve]
enabled = false
""")
    return cfg


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", type=Path, required=True, help="state root for this one-app instance")
    ap.add_argument("--limen", type=Path, required=True, help="LIMEN checkout (limen importable)")
    ap.add_argument("--qallow-cli", type=Path, required=True)
    ap.add_argument("--veyn", type=Path, default=None, help="VEYN checkout (for --veyn-daemon / --inject)")
    ap.add_argument("--relay", type=Path, default=None)
    ap.add_argument("--qallow-relay", type=Path, default=None)
    ap.add_argument("--veyn-daemon", action="store_true", help="boot the real veyn-core daemon")
    ap.add_argument("--inject", action="store_true", help="push one REM cue through DucteiBridge at startup")
    ap.add_argument("--osc-cue", action="store_true", help="send an /oneiro/watch REM cue over OSC after boot")
    ap.add_argument("--osc-port", type=int, default=9000)
    ap.add_argument("--veyn-port", type=int, default=7700)
    ap.add_argument("--poll-ms", type=int, default=1000)
    ap.add_argument("--once", action="store_true", help="run every hop once in order, then exit (no daemons)")
    args = ap.parse_args()

    ductei_root = Path(__file__).resolve().parent.parent
    relay = args.relay or ductei_root / "target" / "debug" / f"ductei-limen-relay{EXE}"
    qrelay = args.qallow_relay or ductei_root / "target" / "debug" / f"ductei-qallow-relay{EXE}"
    for b in (relay, qrelay, args.qallow_cli):
        if not Path(b).exists():
            print(f"missing binary: {b}")
            return 2

    root = args.root.resolve()
    spool, veyn, store = root / "spool", root / "veyn", root / "store"
    limen_ductei, limen_out, veyn_out = root / "ductei", root / "limen-out", root / "veyn-out"
    for d in ("pending", "done", "certs", "failed"):
        (spool / d).mkdir(parents=True, exist_ok=True)
    for d in (veyn, store, root / "state"):
        d.mkdir(parents=True, exist_ok=True)
    log(f"root={root}")
    log(f"shared store={store}")

    smoke_bin = None
    if args.inject or args.veyn_daemon:
        if args.veyn is None:
            print("--inject / --veyn-daemon need --veyn <VEYN checkout>")
            return 2
        smoke_bin = args.veyn / "target" / "debug" / "examples" / f"ductei_bridge_smoke{EXE}"

    def inject_cue(device: str) -> None:
        assert smoke_bin is not None
        if not smoke_bin.exists():
            subprocess.run(["cargo", "build", "-p", "veyn-core", "--example", "ductei_bridge_smoke"],
                           check=True, cwd=args.veyn)
        f = veyn / "inject.json"
        f.write_text(json.dumps([{"device_id": device, "source": "watch", "metric": "rem_detected",
                                  "value": 1.0, "unit": "bool", "ts": int(time.time() * 1000)}]))
        subprocess.run([str(smoke_bin), str(veyn / "accepted.jsonl"), str(veyn / "rejected.jsonl"), str(f)], check=True)
        log(f"injected REM cue from {device} through DucteiBridge")

    proposer = Proposer(args.qallow_cli, store, spool, veyn / "accepted.jsonl", root / "state")
    limend_env = dict(os.environ)

    if args.once:
        if args.inject:
            inject_cue("oneiro-watch-once")
        subprocess.run([str(qrelay), str(veyn), str(veyn_out), "--once", "--qallow-cli", str(args.qallow_cli),
                        "--store-dir", str(store)], check=True)
        proposer.tick()
        subprocess.run([sys.executable, "-m", "limen.limend", str(spool), "--once"], check=True,
                       cwd=args.limen, env=limend_env)
        subprocess.run([str(relay), str(spool), "--once"], check=True)
        subprocess.run([str(qrelay), str(limen_ductei), str(limen_out), "--once", "--qallow-cli", str(args.qallow_cli),
                        "--store-dir", str(store)], check=True)
        certs = sorted(p.stem for p in (spool / "certs" / "sent").glob("*.json"))
        log(f"one pass complete; certified jobs in store: {certs}")
        return 0

    sup = Supervisor()
    poll = str(args.poll_ms)
    try:
        sup.start("limend", [sys.executable, "-m", "limen.limend", spool, "--poll-interval", str(args.poll_ms / 1000)],
                  cwd=args.limen, env=limend_env)
        sup.start("ductei-limen-relay", [relay, spool, "--poll-interval-ms", poll])
        sup.start("ductei-qallow-relay[limen]", [qrelay, limen_ductei, limen_out, "--poll-interval-ms", poll,
                                                "--qallow-cli", args.qallow_cli, "--store-dir", store])
        sup.start("ductei-qallow-relay[veyn]", [qrelay, veyn, veyn_out, "--poll-interval-ms", poll,
                                               "--qallow-cli", args.qallow_cli, "--store-dir", store])
        if args.veyn_daemon:
            veyn_bin = args.veyn / "target" / "debug" / f"veyn-core{EXE}"
            if not veyn_bin.exists():
                subprocess.run(["cargo", "build", "-p", "veyn-core"], check=True, cwd=args.veyn)
            cfg = write_veyn_config(root, args.osc_port, args.veyn_port)
            env = dict(os.environ, VEYN_NO_BROWSER="1")
            sup.start("veyn-core", [veyn_bin, "--config", cfg], cwd=args.veyn, env=env)
            time.sleep(2.0)
        if args.inject:
            inject_cue("oneiro-watch-injected")
        if args.osc_cue:
            if not args.veyn_daemon:
                log("--osc-cue ignored: needs --veyn-daemon")
            else:
                send_osc_cue(args.osc_port, "oneiro-watch-osc")

        log("loop running -- Ctrl+C to stop")
        seen_certs: set[str] = set()
        while True:
            proposer.tick()
            for c in (spool / "certs" / "sent").glob("*.json"):
                if c.stem not in seen_certs:
                    seen_certs.add(c.stem)
                    log(f"certificate landed for {c.stem}")
            sup.check()
            time.sleep(args.poll_ms / 1000)
    except KeyboardInterrupt:
        log("shutting down")
    finally:
        sup.stop()
    return 0


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal.default_int_handler)
    sys.exit(main())
