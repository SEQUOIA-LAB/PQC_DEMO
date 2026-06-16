"""Generate CA + server certificates for the demo's selectable signature algs.

We do NOT implement crypto (PROJECT_PLAN.md §4.4) — we drive the OpenSSL CLI.
The default signature algorithm comes from protocol/suite.conf (sig_alg), but the
dashboard can request any algorithm in app/algorithms.py; each gets its own
cached CA+server cert under certs/algs/<id>/.

Usage:
    python -m app.gen_certs                 # default suite cert -> certs/
    python -m app.gen_certs --force         # regenerate default
    python -m app.gen_certs --sig ML-DSA-87 # one algorithm -> certs/algs/ML-DSA-87/
    python -m app.gen_certs --all           # pre-generate every selectable algorithm
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

from app.algorithms import SIG_ALGS, get
from app.config import SUITE, REPO_ROOT

# Our locally-built OpenSSL has no installed default openssl.cnf (install_sw),
# so point every CLI call at the minimal one we ship.
_OSSL_ENV = {**os.environ, "OPENSSL_CONF": str(REPO_ROOT / "crypto" / "openssl.cnf")}

_SAN_EXT = (
    "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:10.0.0.2,IP:10.0.0.1\n"
    "basicConstraints=CA:FALSE\n"
    "keyUsage=digitalSignature,keyEncipherment\n"
    "extendedKeyUsage=serverAuth\n"
)


def _run(cmd: list[str]) -> None:
    print("    $", " ".join(cmd))
    subprocess.run(cmd, check=True, env=_OSSL_ENV)


def _genkey(ossl: str, sig_id: str, out: Path) -> None:
    """Create a private key for the signature algorithm (form varies by kind)."""
    spec = get(sig_id)
    if spec.keygen == "ec":          # classical ECDSA P-256
        _run([ossl, "ecparam", "-name", "prime256v1", "-genkey", "-out", str(out)])
    elif spec.keygen == "ed25519":   # classical Ed25519
        _run([ossl, "genpkey", "-algorithm", "ED25519", "-out", str(out)])
    else:                            # PQC: the id IS the -algorithm name
        _run([ossl, "genpkey", "-algorithm", spec.id, "-out", str(out)])


def _generate_pair(ossl: str, sig_id: str, ca_key: Path, ca_crt: Path,
                   srv_key: Path, srv_crt: Path, out_dir: Path) -> None:
    """Generate a self-signed CA + a server cert, both using sig_id."""
    print(f"[gen_certs] generating {sig_id} CA + server cert -> {out_dir}")
    # CA (self-signed). For `req -x509`, CA extensions go via -addext.
    _genkey(ossl, sig_id, ca_key)
    _run([ossl, "req", "-x509", "-new", "-key", str(ca_key),
          "-subj", f"/CN=PQC-DEMO {sig_id} Root CA/O=UC Merced EECS",
          "-addext", "basicConstraints=critical,CA:TRUE",
          "-addext", "keyUsage=critical,keyCertSign,cRLSign",
          "-days", "365", "-out", str(ca_crt)])
    # Server cert signed by that CA.
    srv_csr = out_dir / "server.csr"
    _genkey(ossl, sig_id, srv_key)
    _run([ossl, "req", "-new", "-key", str(srv_key),
          "-subj", "/CN=pqc-demo-server/O=UC Merced EECS", "-out", str(srv_csr)])
    ext = out_dir / "server.ext"
    ext.write_text(_SAN_EXT)
    _run([ossl, "x509", "-req", "-in", str(srv_csr),
          "-CA", str(ca_crt), "-CAkey", str(ca_key), "-CAcreateserial",
          "-days", "365", "-extfile", str(ext), "-out", str(srv_crt)])


def generate_default(force: bool = False) -> None:
    """Generate the default suite cert into certs/ (the canonical demo cert)."""
    ossl = SUITE.openssl_bin
    d = REPO_ROOT / "certs"
    d.mkdir(exist_ok=True)
    if SUITE.server_cert.exists() and SUITE.ca_cert.exists() and not force:
        print(f"[gen_certs] default certs already present in {d} (use --force)")
        return
    _generate_pair(ossl, SUITE.sig_alg, d / "ca.key", SUITE.ca_cert,
                   SUITE.server_key, SUITE.server_cert, d)
    print(f"[gen_certs] DONE default ({SUITE.sig_alg}).")


def cert_paths_for(sig_id: str) -> tuple[Path, Path, Path]:
    """Return (ca_crt, server_crt, server_key) for a per-algorithm cert.

    The suite-default algorithm maps to the canonical certs/ files so the default
    path and committed certs are reused; others live under certs/algs/<id>/.
    """
    if sig_id == SUITE.sig_alg:
        return SUITE.ca_cert, SUITE.server_cert, SUITE.server_key
    d = REPO_ROOT / "certs" / "algs" / sig_id
    return d / "ca.crt", d / "server.crt", d / "server.key"


def ensure_cert(sig_id: str, force: bool = False) -> tuple[Path, Path, Path]:
    """Generate (if needed) and return the cert paths for sig_id. Cached on disk."""
    get(sig_id)  # validate
    ca_crt, srv_crt, srv_key = cert_paths_for(sig_id)
    if sig_id == SUITE.sig_alg:
        generate_default(force=force)
        return ca_crt, srv_crt, srv_key
    out_dir = srv_crt.parent
    if srv_crt.exists() and ca_crt.exists() and not force:
        return ca_crt, srv_crt, srv_key
    out_dir.mkdir(parents=True, exist_ok=True)
    _generate_pair(SUITE.openssl_bin, sig_id, out_dir / "ca.key", ca_crt,
                   srv_key, srv_crt, out_dir)
    return ca_crt, srv_crt, srv_key


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true", help="regenerate even if present")
    ap.add_argument("--sig", default=None, help="generate certs for one signature algorithm")
    ap.add_argument("--all", action="store_true", help="pre-generate all selectable algorithms")
    args = ap.parse_args()
    try:
        if args.all:
            for spec in SIG_ALGS:
                ensure_cert(spec.id, force=args.force)
            print("[gen_certs] DONE all selectable algorithms.")
        elif args.sig:
            ca, crt, key = ensure_cert(args.sig, force=args.force)
            print(f"[gen_certs] DONE {args.sig}: {crt}")
        else:
            generate_default(force=args.force)
    except subprocess.CalledProcessError as e:
        print(f"[gen_certs] OpenSSL command failed: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyError as e:
        print(f"[gen_certs] {e}", file=sys.stderr)
        sys.exit(2)
