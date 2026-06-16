"""Load protocol/suite.conf — the single source of truth for the wire contract.

Both the server and client roles import this. Neither role defines crypto
parameters independently (PROJECT_PLAN.md §4.2). Changing the demo's crypto is a
one-file edit (protocol/suite.conf).
"""
from __future__ import annotations

import configparser
import os
from dataclasses import dataclass
from pathlib import Path

# Repo root = parent of this app/ package.
REPO_ROOT = Path(__file__).resolve().parent.parent
SUITE_CONF = REPO_ROOT / "protocol" / "suite.conf"


@dataclass(frozen=True)
class Suite:
    tls_version: str
    group: str
    sig_alg: str
    ciphersuite: str
    app_aead: str
    app_aead_key_bits: int
    app_aead_nonce_bytes: int
    app_aead_tag_bytes: int

    server_addr: str
    server_port: int

    demo_salt: str
    default_message: str

    ca_cert: Path
    server_cert: Path
    server_key: Path

    # Resolved path to the pinned OpenSSL binary (see openssl_bin()).
    openssl_bin: str


def openssl_bin() -> str:
    """Resolve the pinned OpenSSL 3.5.x binary.

    Priority: $PQC_OPENSSL -> ~/opt/openssl-3.5/bin/openssl -> "openssl" on PATH.
    The default prefix matches crypto/setup-openssl.sh.
    """
    env = os.environ.get("PQC_OPENSSL")
    if env and Path(env).exists():
        return env
    default = Path.home() / "opt" / "openssl-3.5" / "bin" / "openssl"
    if default.exists():
        return str(default)
    return "openssl"


def load_suite(path: Path | str = SUITE_CONF) -> Suite:
    cp = configparser.ConfigParser()
    read = cp.read(path)
    if not read:
        raise FileNotFoundError(f"could not read suite config: {path}")

    demo = cp["demo"]
    net = cp["net"]
    certs = cp["certs"]
    # [demo_run] is optional; fall back to safe defaults if a config predates it.
    demo_run = cp["demo_run"] if cp.has_section("demo_run") else {}

    return Suite(
        tls_version=demo["tls_version"].strip(),
        group=demo["group"].strip(),
        sig_alg=demo["sig_alg"].strip(),
        ciphersuite=demo["ciphersuite"].strip(),
        app_aead=demo["app_aead"].strip(),
        app_aead_key_bits=int(demo["app_aead_key_bits"]),
        app_aead_nonce_bytes=int(demo["app_aead_nonce_bytes"]),
        app_aead_tag_bytes=int(demo["app_aead_tag_bytes"]),
        server_addr=net["server_addr"].strip(),
        server_port=int(net["server_port"]),
        demo_salt=str(demo_run.get("salt", "504f5143444d4f2d44454d4f2d76312d73616c74")).strip(),
        default_message=str(demo_run.get("default_message", "hello from a post-quantum world")).strip(),
        ca_cert=REPO_ROOT / certs["ca_cert"].strip(),
        server_cert=REPO_ROOT / certs["server_cert"].strip(),
        server_key=REPO_ROOT / certs["server_key"].strip(),
        openssl_bin=openssl_bin(),
    )


# Convenience singleton for the common case.
SUITE = load_suite()
