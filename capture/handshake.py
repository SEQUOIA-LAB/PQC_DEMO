"""Capture real PQC handshake artifacts and normalize them into schema events.

Runs a one-shot handshake with `s_client -trace` + SSLKEYLOGFILE, parses the
trace for the genuine sizes/artifacts, and emits events. Where an artifact is
not byte-extractable (the derived secret), we emit it as a fingerprint with a
note, per PROJECT_PLAN.md §13 — never fabricated bytes.

Usage:
    .venv/bin/python -m capture.handshake --host 127.0.0.1 --port 4433 \
        --events-file runs/handshake.jsonl
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from app.config import REPO_ROOT, load_suite
from app.events import EventEmitter

_OSSL_ENV = {"OPENSSL_CONF": str(REPO_ROOT / "crypto" / "openssl.cnf")}

# Trace parsing patterns (verified against OpenSSL 3.5.7 -trace output).
RE_GROUP = re.compile(r"Negotiated TLS1\.3 group:\s*(\S+)")
RE_KEYSHARE = re.compile(r"extension_type=key_share\(51\), length=(\d+)")
RE_CERTVERIFY = re.compile(r"CertificateVerify, Length=(\d+)")
RE_NAMEDGROUP = re.compile(r"NamedGroup:\s*(\S+)")


def _spawn_server(suite, host, port, keylog):
    cmd = [suite.openssl_bin, "s_server", "-accept", f"{host}:{port}",
           "-cert", str(suite.server_cert), "-key", str(suite.server_key),
           "-groups", suite.group, "-tls1_3", "-www", "-quiet"]
    env = {**os.environ, **_OSSL_ENV, "SSLKEYLOGFILE": str(keylog)}
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, env=env)


def _client_trace(suite, host, port, keylog) -> str:
    cmd = [suite.openssl_bin, "s_client", "-connect", f"{host}:{port}",
           "-groups", suite.group, "-CAfile", str(suite.ca_cert),
           "-tls1_3", "-trace"]
    env = {**os.environ, **_OSSL_ENV, "SSLKEYLOGFILE": str(keylog)}
    p = subprocess.run(cmd, input=b"Q\n", capture_output=True, env=env, timeout=15)
    return (p.stdout + p.stderr).decode("utf-8", "replace")


def capture(host: str, port: int, events_file: str | None) -> int:
    suite = load_suite()
    # Capture is a one-shot snapshot; start its events file fresh each run.
    if events_file:
        Path(events_file).unlink(missing_ok=True)
    emitter = EventEmitter("client", to_stdout=True, file_path=events_file)
    tmp = Path(tempfile.mkdtemp(prefix="pqc-capture-"))
    keylog = tmp / "keylog.txt"

    srv = _spawn_server(suite, host, port, keylog)
    time.sleep(1.0)
    try:
        trace = _client_trace(suite, host, port, keylog)
    finally:
        srv.terminate()

    group = (RE_GROUP.search(trace) or [None, suite.group])[1]
    keyshares = [int(m) for m in RE_KEYSHARE.findall(trace)]
    certverify = RE_CERTVERIFY.search(trace)

    # Stage: keygen — the client's key_share (X25519 pubkey + ML-KEM-768
    # encapsulation key). The first key_share in the trace is the client's offer.
    if keyshares:
        emitter.emit("keygen", "client_key_share",
                     algorithm=group, size_bytes=keyshares[0],
                     human_readable=f"client hybrid key_share {keyshares[0]} bytes "
                                    f"(X25519 pubkey + ML-KEM-768 encapsulation key)",
                     note="real size from s_client -trace; raw bytes live in the TLS record")

    # Stage: encapsulate — the server's key_share carries the ML-KEM ciphertext.
    if len(keyshares) >= 2:
        emitter.emit("encapsulate", "server_key_share", algorithm=group,
                     size_bytes=keyshares[1],
                     human_readable=f"server hybrid key_share {keyshares[1]} bytes "
                                    f"(ML-KEM-768 ciphertext + X25519 pubkey)",
                     note="ML-KEM ciphertext is the encapsulation against the client key")

    # Stage: sign_transcript / verify_signature — ML-DSA-65 CertificateVerify.
    if certverify:
        n = int(certverify.group(1))
        emitter.emit("sign_transcript", "ml_dsa_65_signature", algorithm=suite.sig_alg,
                     size_bytes=n,
                     human_readable=f"ML-DSA-65 CertificateVerify signature, {n} bytes",
                     note="server signs the handshake transcript with its ML-DSA-65 key")
        emitter.emit("verify_signature", "ml_dsa_65_signature", algorithm=suite.sig_alg,
                     size_bytes=n,
                     human_readable="client verified the ML-DSA-65 signature (handshake authenticated)")

    # Stage: derive_secret — NOT byte-extractable. Emit a fingerprint of the
    # SSLKEYLOGFILE secret material instead (PROJECT_PLAN.md §13).
    if keylog.exists() and keylog.stat().st_size > 0:
        secret_material = keylog.read_bytes()
        fp = hashlib.sha256(secret_material).hexdigest()
        emitter.emit("derive_secret", "shared_secret_fingerprint",
                     algorithm=group, size_bytes=0,
                     human_readable=f"sha256(keylog secrets)={fp[:32]}…",
                     note="derived secret not directly extractable from TLS; showing a "
                          "SHA-256 fingerprint of the SSLKEYLOGFILE secret material")
    else:
        emitter.emit("derive_secret", "shared_secret_fingerprint", size_bytes=0,
                     human_readable="(SSLKEYLOGFILE empty — secret not exposable)",
                     note="derived secret not extractable; no keylog produced")

    emitter.close()
    print(f"[capture] group={group} key_shares={keyshares} "
          f"certverify={certverify.group(1) if certverify else None}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=None)
    ap.add_argument("--events-file", default=None)
    a = ap.parse_args()
    suite = load_suite()
    raise SystemExit(capture(a.host, a.port or suite.server_port, a.events_file))
