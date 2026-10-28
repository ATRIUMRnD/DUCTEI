#!/usr/bin/env python3
# Copyright (C) 2026 xingxerx
#
# Licensed under the Apache License 2.0. See the LICENSE file in the
# repository root for the full terms.

"""End-to-end smoke test for the limend -> ductei-limen-relay loop.

Replays the four scenarios from the first verified harness loop
(ATRIUM ROADMAP.md, status baseline July 22 2026), with the DUCTEI hard
invariants asserted inline rather than checked by hand:

  1. good job              request -> limend -> cert -> relay -> accepted
  2. restart replicability a second relay process over the same state
                           keeps node id, gate state, and prior log
  3. malformed request     limend witnesses it in spool/failed/, nothing
                           reaches certs/ or the channel
  4. malformed cert        relay witnesses it in spool/failed/, nothing
                           reaches sent/ or accepted.jsonl

Invariant coverage (AGENTS.md section 2):
  I1  credentials never in sync payloads  scenario 1 (env sentinel +
                                          closed-type field drop)
  I2  scopes deny-by-default              every accepted envelope carries
                                          exactly the cert scope
  I3  wire compat with Qallow             covered by the separate
                                          conformance job in ci.yml
  I4  persistence before ack              cert archived to sent/ implies
                                          a line in accepted.jsonl
  I5  bounded sessions                    exactly one accepted line per job

Usage:
  python scripts/smoke_e2e.py --limen <path-to-LIMEN-checkout> \
      [--relay <path-to-ductei-limen-relay-binary>] [--workdir DIR]

Requires: the LIMEN package importable by the current python (pip
install <limen checkout>), and a built ductei-limen-relay (the script
runs `cargo build -p ductei-limen` itself if --relay is not given).

Exit code 0 iff all scenarios and invariant assertions pass. Output is
plain English per the witness requirement: every scenario prints what it
proved, every failure prints what was expected and what was found.
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

CERT_SCOPE = "qallow.semantic.cert"
# Sentinel that must never appear in any channel artifact. Set as the QPU
# token for the limend process: if it ever shows up in a cert, an
# envelope, or the accepted log, invariant 1 is broken.
TOKEN_SENTINEL = "SMOKE-CREDENTIAL-SENTINEL-DO-NOT-SYNC"

PASS = "PASS"
FAIL = "FAIL"

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
    out = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


def run_limend(spool: Path, limen_dir: Path) -> None:
    """One --once pass of limend over the spool, offline, with the
    credential sentinel in its environment."""
    env = dict(os.environ)
    env["LIMEN_QPU_TOKEN"] = TOKEN_SENTINEL
    subprocess.run(
        [sys.executable, "-m", "limen.limend", str(spool), "--once"],
        check=True,
        cwd=limen_dir,
        env=env,
        capture_output=True,
        text=True,
    )


def run_relay(relay: Path, spool: Path) -> None:
    """One --once pass of the relay over spool/certs/."""
    subprocess.run(
        [str(relay), str(spool), "--once"],
        check=True,
        capture_output=True,
        text=True,
    )


def write_request(spool: Path, job_id: str) -> None:
    """A small valid QUBO request forced onto the offline simulator path
    (tier 0, no network, no credentials needed)."""
    request = {
        "job_id": job_id,
        "qubo": [[["a", "a"], -1.0], [["b", "b"], -1.0], [["a", "b"], 2.0]],
        "fidelity_target": 0.9,
        "credit_budget": 10.0,
        "offline": True,
    }
    (spool / "pending" / f"{job_id}.json").write_text(json.dumps(request))


def scenario_good_job(spool: Path, ductei: Path, limen_dir: Path, relay: Path) -> None:
    print("scenario 1: good job")
    write_request(spool, "smoke-good-1")
    run_limend(spool, limen_dir)

    cert_path = spool / "certs" / "smoke-good-1.json"
    check(cert_path.exists(), "limend wrote a cert for the good job",
          f"{cert_path} to exist")
    if cert_path.exists():
        cert = json.loads(cert_path.read_text())
        # LIMEN #37 (2026-10-24) widened the cert summary: success_probability,
        # fidelity_target, target_met were added and fidelity_estimate kept as
        # a deprecated alias for one release. The relay's CertSummary is a
        # closed type that drops unknown fields, so the contract to hold here
        # is "required fields present, nothing outside the known set", not an
        # exact match that breaks on every additive change.
        required = {"job_id", "backend", "tier", "success_probability", "lamport"}
        allowed = required | {"fidelity_estimate", "fidelity_target", "target_met"}
        check(required <= set(cert) <= allowed,
              "cert carries the CertSummary fields and nothing outside the known set",
              f"required {sorted(required)}, allowed extras {sorted(allowed - required)}; "
              f"got {sorted(cert)}")
        check(not any("token" in k.lower() or "secret" in k.lower() or "crn" in k.lower()
                      for k in cert),
              "cert carries no credential-shaped field (I1)",
              f"no token/secret/crn keys; got {sorted(cert)}")
        # I1, closed type: inject a credential-shaped field into the cert
        # before the relay sees it. serde must drop it on deserialize.
        cert["api_token"] = TOKEN_SENTINEL
        cert_path.write_text(json.dumps(cert))

    run_relay(relay, spool)

    accepted = read_jsonl(ductei / "accepted.jsonl")
    ours = [e for e in accepted if e.get("key") == "limen.cert.smoke-good-1"]
    check(len(ours) == 1, "exactly one accepted envelope for the good job (I5)",
          "one accepted.jsonl line with key limen.cert.smoke-good-1")
    if ours:
        check(ours[0].get("scopes") == [CERT_SCOPE],
              f"accepted envelope carries exactly [{CERT_SCOPE}] (I2)",
              str([CERT_SCOPE]))
    check((spool / "certs" / "sent" / "smoke-good-1.json").exists(),
          "cert archived to certs/sent/ after send",
          "certs/sent/smoke-good-1.json to exist")

    # I4: archived-to-sent implies logged-to-accepted (persist before ack).
    sent = {p.stem for p in (spool / "certs" / "sent").glob("*.json")}
    logged = {e["key"].removeprefix("limen.cert.") for e in accepted}
    check(sent <= logged,
          "everything in certs/sent/ has a line in accepted.jsonl (I4)",
          f"sent {sorted(sent)} subset of logged {sorted(logged)}")

    # I1: the credential sentinel appears nowhere in channel artifacts.
    for artifact in [ductei / "accepted.jsonl", ductei / "rejected.jsonl"]:
        text = artifact.read_text() if artifact.exists() else ""
        check(TOKEN_SENTINEL not in text,
              f"credential sentinel absent from {artifact.name} (I1)",
              "sentinel string not present")


def scenario_restart(spool: Path, ductei: Path, limen_dir: Path, relay: Path) -> None:
    print("scenario 2: restart replicability")
    node_id_before = (ductei / "relay-node-id").read_text().strip()
    accepted_before = len(read_jsonl(ductei / "accepted.jsonl"))

    write_request(spool, "smoke-restart-2")
    run_limend(spool, limen_dir)
    run_relay(relay, spool)  # a fresh relay process: restart by construction

    node_id_after = (ductei / "relay-node-id").read_text().strip()
    check(node_id_after == node_id_before,
          "relay node id survives restart",
          f"{node_id_before} (got {node_id_after})")

    accepted = read_jsonl(ductei / "accepted.jsonl")
    check(len(accepted) == accepted_before + 1,
          "restarted relay appended exactly one envelope, prior log intact",
          f"{accepted_before + 1} lines (got {len(accepted)})")
    keys = [e["key"] for e in accepted]
    check("limen.cert.smoke-good-1" in keys and "limen.cert.smoke-restart-2" in keys,
          "log still holds pre-restart and post-restart envelopes",
          "both smoke-good-1 and smoke-restart-2 keys present")


def scenario_malformed_request(spool: Path, ductei: Path, limen_dir: Path) -> None:
    print("scenario 3: malformed request")
    bad = spool / "pending" / "smoke-badreq-3.json"
    bad.write_text("{this is not json")
    run_limend(spool, limen_dir)

    check(not bad.exists(), "malformed request removed from pending/",
          "pending/smoke-badreq-3.json gone")
    failed = spool / "failed" / "smoke-badreq-3.json"
    check(failed.exists(), "malformed request witnessed in spool/failed/",
          f"{failed} to exist")
    if failed.exists():
        record = json.loads(failed.read_text())
        check(bool(record.get("error")),
              "failure record is human-readable (has an error field)",
              "non-empty 'error' key")
    check(not (spool / "certs" / "smoke-badreq-3.json").exists(),
          "no cert produced for the malformed request",
          "certs/smoke-badreq-3.json absent")
    keys = [e["key"] for e in read_jsonl(ductei / "accepted.jsonl")]
    check("limen.cert.smoke-badreq-3" not in keys,
          "nothing from the malformed request reached the channel",
          "no accepted envelope for smoke-badreq-3")


def scenario_malformed_cert(spool: Path, ductei: Path, relay: Path) -> None:
    print("scenario 4: malformed cert")
    bad = spool / "certs" / "smoke-badcert-4.json"
    bad.write_text('{"job_id": "smoke-badcert-4", "backend": 42}')  # wrong types, missing fields
    run_relay(relay, spool)

    check(not bad.exists(), "malformed cert removed from certs/",
          "certs/smoke-badcert-4.json gone")
    failed = spool / "failed" / "smoke-badcert-4.json"
    check(failed.exists(), "malformed cert witnessed in spool/failed/",
          f"{failed} to exist")
    if failed.exists():
        record = json.loads(failed.read_text())
        check(bool(record.get("error")),
              "failure record is human-readable (has an error field)",
              "non-empty 'error' key")
    check(not (spool / "certs" / "sent" / "smoke-badcert-4.json").exists(),
          "malformed cert never archived to sent/",
          "certs/sent/smoke-badcert-4.json absent")
    keys = [e["key"] for e in read_jsonl(ductei / "accepted.jsonl")]
    check("limen.cert.smoke-badcert-4" not in keys,
          "malformed cert never reached accepted.jsonl",
          "no accepted envelope for smoke-badcert-4")


def build_relay(repo_root: Path) -> Path:
    subprocess.run(
        ["cargo", "build", "-p", "ductei-limen"],
        check=True, cwd=repo_root, capture_output=True, text=True,
    )
    exe = ".exe" if os.name == "nt" else ""
    return repo_root / "target" / "debug" / f"ductei-limen-relay{exe}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limen", type=Path, required=True,
                        help="path to a LIMEN checkout (limen package must be importable)")
    parser.add_argument("--relay", type=Path, default=None,
                        help="prebuilt ductei-limen-relay; built via cargo if omitted")
    parser.add_argument("--workdir", type=Path, default=None,
                        help="scratch dir for spool/ductei state (temp dir if omitted)")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    relay = args.relay or build_relay(repo_root)
    if not relay.exists():
        print(f"relay binary not found: {relay}")
        return 2

    workdir = args.workdir or Path(tempfile.mkdtemp(prefix="ductei-smoke-"))
    root = workdir / "loop"
    if root.exists():
        shutil.rmtree(root)
    spool = root / "spool"
    ductei = root / "ductei"
    for d in ("pending", "done", "certs", "failed"):
        (spool / d).mkdir(parents=True)

    print(f"smoke: spool={spool}")
    print(f"smoke: relay={relay}\n")

    scenario_good_job(spool, ductei, args.limen, relay)
    scenario_restart(spool, ductei, args.limen, relay)
    scenario_malformed_request(spool, ductei, args.limen)
    scenario_malformed_cert(spool, ductei, relay)

    print()
    if _failures:
        print(f"smoke: {len(_failures)} check(s) failed:")
        for f in _failures:
            print(f"  - {f}")
        return 1
    print("smoke: all four scenarios passed, invariants held")
    return 0


if __name__ == "__main__":
    sys.exit(main())
