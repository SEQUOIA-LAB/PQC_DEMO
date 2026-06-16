"""Drive the pinned OpenSSL s_server / s_client to get a real PQC-TLS 1.3 pipe.

Why not Python's `ssl` module: it links the SYSTEM OpenSSL, which on most boxes
lacks X25519MLKEM768 / ML-DSA. Our pinned 3.5.7 build (crypto/setup-openssl.sh)
has them natively. So the REAL crypto is done by the pinned `s_server`/`s_client`
(PROJECT_PLAN.md §4.4), and our Python app frame rides over their stdin/stdout —
a genuine PQC-TLS channel, full speed, no faked handshake.

The handshake also writes SSLKEYLOGFILE (consumed by capture/ in Phase 2).
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

from app.config import Suite, REPO_ROOT

_OSSL_ENV_BASE = {"OPENSSL_CONF": str(REPO_ROOT / "crypto" / "openssl.cnf")}


def _env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = {**os.environ, **_OSSL_ENV_BASE}
    if extra:
        env.update(extra)
    return env


def spawn_server(suite: Suite, *, host: str, port: int,
                 keylog: Path | None = None,
                 cert: Path | None = None, key: Path | None = None,
                 group: str | None = None) -> subprocess.Popen:
    """Spawn `s_server` in raw byte-relay mode (no -www): stdin->TLS, TLS->stdout.

    With -quiet and no -www, s_server pipes its stdin to the client and the
    client's bytes to its stdout, giving us a clean bidirectional app channel.

    cert/key override the suite default so the operator can pick the certificate
    signature algorithm; group overrides the key-exchange group (app/algorithms.py).
    """
    cmd = [
        suite.openssl_bin, "s_server",
        "-accept", f"{host}:{port}",
        "-cert", str(cert or suite.server_cert),
        "-key", str(key or suite.server_key),
        "-groups", group or suite.group,
        "-tls1_3",
        "-quiet",
    ]
    extra = {"SSLKEYLOGFILE": str(keylog)} if keylog else None
    return subprocess.Popen(
        cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, env=_env(extra),
    )


def spawn_client(suite: Suite, *, host: str, port: int,
                 keylog: Path | None = None,
                 ca: Path | None = None, group: str | None = None) -> subprocess.Popen:
    """Spawn `s_client` in raw byte-relay mode (-quiet): stdin->TLS, TLS->stdout.

    ca overrides the suite default CA so the client trusts the CA matching the
    server's chosen signature algorithm; group overrides the key-exchange group.
    """
    cmd = [
        suite.openssl_bin, "s_client",
        "-connect", f"{host}:{port}",
        "-groups", group or suite.group,
        "-CAfile", str(ca or suite.ca_cert),
        "-tls1_3",
        "-quiet",
    ]
    extra = {"SSLKEYLOGFILE": str(keylog)} if keylog else None
    return subprocess.Popen(
        cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, env=_env(extra),
    )


def channel_binding(suite: Suite, run_salt: bytes) -> bytes:
    """A value both ends compute identically, to seed the app-layer AEAD key.

    Not the RFC 8446 exporter (not reachable via the CLI path — see
    app/aead.derive_app_key and protocol/message_format.md). Both roles get the
    SAME run_salt out-of-band (passed on the command line for the demo) plus the
    negotiated suite parameters, so derive_app_key yields identical key/nonce on
    both sides. The TLS channel itself provides confidentiality/authentication;
    this layer is for instrumentation, and it must be symmetric byte-for-byte.
    """
    return b"|".join([
        run_salt,
        suite.group.encode(),
        suite.sig_alg.encode(),
        suite.app_aead.encode(),
    ])
