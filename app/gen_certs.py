"""Generate an ML-DSA-65 CA + server certificate using the pinned OpenSSL.

We do NOT implement crypto (PROJECT_PLAN.md §4.4) — we drive the OpenSSL CLI.
The signature algorithm comes from protocol/suite.conf (sig_alg = ML-DSA-65).

Usage:
    python -m app.gen_certs            # writes certs/ under repo root
    python -m app.gen_certs --force    # regenerate even if present
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

from app.config import SUITE, REPO_ROOT

# Our locally-built OpenSSL has no installed default openssl.cnf (install_sw),
# so point every CLI call at the minimal one we ship.
_OSSL_ENV = {**os.environ, "OPENSSL_CONF": str(REPO_ROOT / "crypto" / "openssl.cnf")}


def _run(cmd: list[str]) -> None:
    print("    $", " ".join(cmd))
    subprocess.run(cmd, check=True, env=_OSSL_ENV)


def generate(force: bool = False) -> None:
    ossl = SUITE.openssl_bin
    certs_dir = REPO_ROOT / "certs"
    certs_dir.mkdir(exist_ok=True)

    ca_key = certs_dir / "ca.key"
    ca_crt = SUITE.ca_cert
    srv_key = SUITE.server_key
    srv_csr = certs_dir / "server.csr"
    srv_crt = SUITE.server_cert

    if srv_crt.exists() and ca_crt.exists() and not force:
        print(f"[gen_certs] certs already present in {certs_dir} (use --force to regenerate)")
        return

    sig = SUITE.sig_alg  # ML-DSA-65 — passed directly as the key algorithm.
    print(f"[gen_certs] Generating {sig} CA + server cert with {ossl}")

    # 1) CA: self-signed ML-DSA-65 root.
    _run([ossl, "genpkey", "-algorithm", sig, "-out", str(ca_key)])
    # For `req -x509`, CA extensions must be passed via -addext (-extfile is
    # only honoured by `x509 -req`). Without these the chain fails purpose
    # checks (sslserver) at the CA depth.
    _run([
        ossl, "req", "-x509", "-new", "-key", str(ca_key),
        "-subj", "/CN=PQC-DEMO Root CA/O=UC Merced EECS",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        "-days", "365", "-out", str(ca_crt),
    ])

    # 2) Server: ML-DSA-65 key + CSR, signed by the CA. SANs cover the demo
    #    static IPs (deploy plane) and localhost (local dev).
    _run([ossl, "genpkey", "-algorithm", sig, "-out", str(srv_key)])
    _run([
        ossl, "req", "-new", "-key", str(srv_key),
        "-subj", "/CN=pqc-demo-server/O=UC Merced EECS",
        "-out", str(srv_csr),
    ])

    ext = certs_dir / "server.ext"
    ext.write_text(
        "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:10.0.0.2,IP:10.0.0.1\n"
        "basicConstraints=CA:FALSE\n"
        "keyUsage=digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
    )
    _run([
        ossl, "x509", "-req", "-in", str(srv_csr),
        "-CA", str(ca_crt), "-CAkey", str(ca_key), "-CAcreateserial",
        "-days", "365", "-extfile", str(ext), "-out", str(srv_crt),
    ])

    print(f"[gen_certs] DONE. CA={ca_crt.name} server={srv_crt.name} in {certs_dir}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true", help="regenerate even if certs exist")
    args = ap.parse_args()
    try:
        generate(force=args.force)
    except subprocess.CalledProcessError as e:
        print(f"[gen_certs] OpenSSL command failed: {e}", file=sys.stderr)
        sys.exit(1)
