"""PQC-vs-classical TLS 1.3 benchmark harness.

Drives the pinned OpenSSL s_server / s_time / speed to produce credible numbers.
Run on the PI for meaningful Cortex-A72 results (PROJECT_PLAN.md §10 Phase 4).

Three measurements, each for PQC and classical:
  1. handshake latency  — wall-clock of N sequential full handshakes (s_client).
  2. throughput         — connections/sec via `openssl s_time` (new conns, no reuse).
  3. primitives         — `openssl speed` for the KEM and the signature algorithm.

Suites:
  PQC       : group=X25519MLKEM768, cert=ML-DSA-65        (certs/server.*)
  classical : group=X25519,         cert=ECDSA P-256      (certs/classical.*)

Usage (on the server Pi):
    .venv/bin/python -m metrics.bench --iters 50 --time 5 \
        --out runs/metrics.json
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import time
from dataclasses import dataclass, asdict
from pathlib import Path

from app.config import REPO_ROOT, load_suite

_OSSL_ENV = {**os.environ, "OPENSSL_CONF": str(REPO_ROOT / "crypto" / "openssl.cnf")}

CLASSICAL_GROUP = "x25519"
CLASSICAL_SIG = "ECDSA-P256"      # label; key generated as EC prime256v1
PQC_KEM = "ML-KEM-768"
PQC_SIG = "ML-DSA-65"


@dataclass
class SuiteResult:
    label: str
    group: str
    cert_sig: str
    handshakes: int
    handshake_total_s: float
    handshake_mean_ms: float
    handshake_p50_ms: float
    handshake_p95_ms: float
    conns_per_sec: float | None  # from s_time, may be None if unavailable


def _ossl(suite, *args, **kw):
    return subprocess.run([suite.openssl_bin, *args], env=_OSSL_ENV, **kw)


def ensure_classical_cert(suite) -> tuple[Path, Path]:
    """Generate an ECDSA P-256 CA+server cert for the classical comparison."""
    d = REPO_ROOT / "certs"
    ca_key, ca_crt = d / "classical-ca.key", d / "classical-ca.crt"
    key, csr, crt = d / "classical.key", d / "classical.csr", d / "classical.crt"
    if crt.exists():
        return crt, key
    print("[metrics] generating classical ECDSA P-256 cert for comparison")
    _ossl(suite, "ecparam", "-name", "prime256v1", "-genkey", "-out", str(ca_key), check=True)
    _ossl(suite, "req", "-x509", "-new", "-key", str(ca_key),
          "-subj", "/CN=PQC-DEMO Classical CA", "-days", "365",
          "-addext", "basicConstraints=critical,CA:TRUE",
          "-addext", "keyUsage=critical,keyCertSign,cRLSign",
          "-out", str(ca_crt), check=True)
    _ossl(suite, "ecparam", "-name", "prime256v1", "-genkey", "-out", str(key), check=True)
    _ossl(suite, "req", "-new", "-key", str(key), "-subj", "/CN=pqc-demo-server",
          "-out", str(csr), check=True)
    ext = d / "classical.ext"
    ext.write_text("subjectAltName=DNS:localhost,IP:127.0.0.1,IP:10.0.0.2,IP:10.0.0.1\n"
                   "extendedKeyUsage=serverAuth\n")
    _ossl(suite, "x509", "-req", "-in", str(csr), "-CA", str(ca_crt),
          "-CAkey", str(ca_key), "-CAcreateserial", "-days", "365",
          "-extfile", str(ext), "-out", str(crt), check=True)
    return crt, key


def _spawn_server(suite, port, group, cert, key):
    cmd = [suite.openssl_bin, "s_server", "-accept", f"127.0.0.1:{port}",
           "-cert", str(cert), "-key", str(key), "-groups", group,
           "-tls1_3", "-www", "-quiet", "-naccept", "100000"]
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, env=_OSSL_ENV)


def _one_handshake(suite, port, group, ca) -> float:
    """Time a single full TLS 1.3 handshake (connect + close). Returns ms."""
    t0 = time.perf_counter()
    subprocess.run([suite.openssl_bin, "s_client", "-connect", f"127.0.0.1:{port}",
                    "-groups", group, "-CAfile", str(ca), "-tls1_3"],
                   input=b"Q\n", stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, env=_OSSL_ENV, timeout=20)
    return (time.perf_counter() - t0) * 1000.0


# s_time prints e.g. "2083 connections in 1.06s; 1965.09 connections/user sec".
RE_CONNS = re.compile(r"([\d.]+)\s+connections/user sec")


def _s_time_conns(suite, port, group, ca, seconds) -> float | None:
    """connections/sec via s_time (new connections, no session reuse).

    Note: do NOT pass -cipher here — that is a TLS 1.2 option and makes s_time
    fail silently on a TLS 1.3-only handshake. The ciphersuite is fixed by
    suite.conf at the server anyway.
    """
    # s_time -time wants an INTEGER number of seconds; "2.0" fails to parse.
    p = subprocess.run(
        [suite.openssl_bin, "s_time", "-connect", f"127.0.0.1:{port}",
         "-CAfile", str(ca), "-new", "-time", str(int(seconds)), "-tls1_3"],
        capture_output=True, env={**_OSSL_ENV}, timeout=int(seconds) + 30, text=True,
    )
    out = p.stdout + p.stderr
    m = RE_CONNS.search(out)
    return float(m.group(1)) if m else None


def _pctl(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    i = min(len(s) - 1, int(q * (len(s) - 1) + 0.5))
    return s[i]


def bench_suite(suite, *, label, group, cert, key, ca, port, iters, s_time_s) -> SuiteResult:
    srv = _spawn_server(suite, port, group, cert, key)
    time.sleep(1.0)
    try:
        # Warm-up handshake (excluded) to avoid first-connection skew.
        _one_handshake(suite, port, group, ca)
        lat = [_one_handshake(suite, port, group, ca) for _ in range(iters)]
        conns = _s_time_conns(suite, port, group, ca, s_time_s) if s_time_s else None
    finally:
        srv.terminate()
    cert_sig = PQC_SIG if "MLKEM" in group else CLASSICAL_SIG
    return SuiteResult(
        label=label, group=group, cert_sig=cert_sig,
        handshakes=len(lat),
        handshake_total_s=round(sum(lat) / 1000.0, 4),
        handshake_mean_ms=round(sum(lat) / len(lat), 3),
        handshake_p50_ms=round(_pctl(lat, 0.50), 3),
        handshake_p95_ms=round(_pctl(lat, 0.95), 3),
        conns_per_sec=round(conns, 1) if conns else None,
    )


def primitive_speed(suite, seconds: float) -> dict:
    """`openssl speed` for the KEMs + signatures across all levels vs classical.

    Covers the full PQC progression so the dashboard can show how cost scales with
    security level: ML-KEM-512/768/1024 and ML-DSA-44/65/87, each against a
    classical baseline (X25519, ECDSA-P256).
    """
    out: dict = {}
    secs = str(max(1, int(seconds)))  # `speed -seconds` wants an integer
    # KEM: ML-KEM levels vs classical X25519 (all valid in -kem-algorithms).
    # Signature: ML-DSA levels. (`speed -signature-algorithms` does not accept the
    # "ECDSA-P256" name; the classical signature contrast is already covered by
    # the handshake-level PQC-vs-classical comparison above.)
    for kind, args in [
        ("kem", ["speed", "-kem-algorithms", "-seconds", secs,
                 "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "X25519"]),
        ("signature", ["speed", "-signature-algorithms", "-seconds", secs,
                       "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]),
    ]:
        p = _ossl(suite, *args, capture_output=True, text=True, timeout=900)
        # Keep the "Doing <alg> <op> ops ... in <t>s" result lines verbatim; the
        # dashboard renders them as a compact table.
        rows = [ln.strip() for ln in (p.stdout + p.stderr).splitlines()
                if " ops in " in ln and ("ML-KEM" in ln or "ML-DSA" in ln or "X25519" in ln)]
        out[kind] = rows
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="PQC-vs-classical TLS benchmark (run on the Pi)")
    ap.add_argument("--iters", type=int, default=50, help="timed handshakes per suite")
    ap.add_argument("--time", type=float, default=5.0, help="s_time duration (seconds) per suite; 0 to skip")
    ap.add_argument("--speed-seconds", type=float, default=2.0, help="openssl speed duration per algorithm; 0 to skip")
    ap.add_argument("--port", type=int, default=14500)
    ap.add_argument("--out", default=str(REPO_ROOT / "runs" / "metrics.json"))
    a = ap.parse_args()

    suite = load_suite()
    ca = suite.ca_cert
    classical_crt, classical_key = ensure_classical_cert(suite)
    classical_ca = REPO_ROOT / "certs" / "classical-ca.crt"

    print(f"[metrics] PQC suite: {suite.group} + {PQC_SIG}")
    pqc = bench_suite(suite, label="PQC", group=suite.group,
                      cert=suite.server_cert, key=suite.server_key, ca=ca,
                      port=a.port, iters=a.iters, s_time_s=a.time)

    print(f"[metrics] classical suite: {CLASSICAL_GROUP} + {CLASSICAL_SIG}")
    classical = bench_suite(suite, label="classical", group=CLASSICAL_GROUP,
                            cert=classical_crt, key=classical_key, ca=classical_ca,
                            port=a.port + 1, iters=a.iters, s_time_s=a.time)

    speed = primitive_speed(suite, a.speed_seconds) if a.speed_seconds else {}

    # Derived comparison the demo cares about.
    overhead_ms = round(pqc.handshake_mean_ms - classical.handshake_mean_ms, 3)
    overhead_pct = (round(100.0 * overhead_ms / classical.handshake_mean_ms, 1)
                    if classical.handshake_mean_ms else None)

    result = {
        "measured_on": _platform(),
        "openssl": _ossl_version(suite),
        "timestamp": time.time(),
        "pqc": asdict(pqc),
        "classical": asdict(classical),
        "comparison": {
            "handshake_overhead_ms": overhead_ms,
            "handshake_overhead_pct": overhead_pct,
            "note": "PQC adds handshake cost from larger ML-KEM key shares and the "
                    "ML-DSA-65 signature; throughput is connections/sec from s_time.",
        },
        "primitives": speed,
    }
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2))
    print(f"[metrics] wrote {out}")
    print(f"  PQC      handshake mean {pqc.handshake_mean_ms} ms, conns/s {pqc.conns_per_sec}")
    print(f"  classical handshake mean {classical.handshake_mean_ms} ms, conns/s {classical.conns_per_sec}")
    print(f"  PQC overhead: {overhead_ms} ms ({overhead_pct}%)")
    return 0


def _platform() -> str:
    import platform
    return f"{platform.system()} {platform.machine()} ({platform.processor() or 'unknown cpu'})"


def _ossl_version(suite) -> str:
    p = _ossl(suite, "version", capture_output=True, text=True)
    return p.stdout.strip()


if __name__ == "__main__":
    raise SystemExit(main())
