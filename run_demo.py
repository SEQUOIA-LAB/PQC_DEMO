"""End-to-end Phase 1 demo orchestrator (local, two processes on one host).

Starts the server role, then the client role, feeds an operator message through a
REAL X25519MLKEM768 + ML-DSA-65 TLS 1.3 channel, and collects the schema events
from both sides into runs/events.jsonl for the dashboard / replay.

This is the local dev loop from PROJECT_PLAN.md §9.4 (two processes on the Mac).
On the Pis, server and client run on the two boxes over the ethernet link; this
orchestrator is a convenience for local testing only.

Usage:
    .venv/bin/python run_demo.py --message "hello quantum world"
"""
from __future__ import annotations

import argparse
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
RUNS = REPO_ROOT / "runs"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--message", default="hello quantum world")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=4433)
    ap.add_argument("--sig-alg", default=None,
                    help="certificate signature algorithm (app/algorithms.py); "
                         "defaults to the suite default. Generates the cert if needed.")
    args = ap.parse_args()

    RUNS.mkdir(exist_ok=True)
    salt = secrets.token_hex(16)
    py = sys.executable
    env = {**os.environ, "PYTHONPATH": str(REPO_ROOT)}

    # Resolve the certificate for the chosen signature algorithm (cached on disk).
    sig_args: list[str] = []
    if args.sig_alg:
        from app.gen_certs import ensure_cert
        ensure_cert(args.sig_alg)  # generate if first time for this algorithm
        sig_args = ["--sig-alg", args.sig_alg]
        print(f"[run_demo] certificate signature algorithm: {args.sig_alg}")

    server_events = RUNS / "server.jsonl"
    client_events = RUNS / "client.jsonl"
    combined = RUNS / "events.jsonl"
    for f in (server_events, client_events, combined):
        f.unlink(missing_ok=True)

    print(f"[run_demo] salt={salt} message={args.message!r}")
    print(f"[run_demo] starting server on {args.host}:{args.port} ...")
    server = subprocess.Popen(
        [py, "-m", "server", "--salt", salt, "--host", args.host,
         "--port", str(args.port), "--events-file", str(server_events),
         "--keylog", str(RUNS / "server.keylog"), *sig_args],
        env=env, cwd=REPO_ROOT,
    )
    time.sleep(1.0)  # let s_server bind

    print("[run_demo] starting client ...")
    client = subprocess.run(
        [py, "-m", "client", "--salt", salt, "--message", args.message,
         "--host", args.host, "--port", str(args.port),
         "--events-file", str(client_events),
         "--keylog", str(RUNS / "client.keylog"), *sig_args],
        env=env, cwd=REPO_ROOT,
    )

    rc_server = server.wait(timeout=10)
    print(f"[run_demo] server rc={rc_server} client rc={client.returncode}")

    # Merge events in seq order for the dashboard / replay.
    lines: list[tuple[int, str]] = []
    import json
    for f in (server_events, client_events):
        if f.exists():
            for ln in f.read_text().splitlines():
                if ln.strip():
                    lines.append((json.loads(ln).get("seq", 0), ln))
    lines.sort(key=lambda t: t[0])
    combined.write_text("\n".join(ln for _, ln in lines) + ("\n" if lines else ""))
    print(f"[run_demo] wrote {len(lines)} events -> {combined}")

    return 0 if (rc_server == 0 and client.returncode == 0) else 1


if __name__ == "__main__":
    raise SystemExit(main())
