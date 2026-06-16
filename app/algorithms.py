"""Registry of selectable signature (certificate) algorithms for the demo.

Each entry is a cert signature algorithm the operator can pick at the dashboard.
All are verified present in the pinned OpenSSL 3.5.7 build and confirmed to
generate a working cert + complete a TLS 1.3 handshake. FIPS names only
(PROJECT_PLAN.md §2) — no legacy Kyber/Dilithium/SPHINCS+ labels.

The selectable set is the algorithms that actually authenticate a TLS 1.3
handshake in this build: the three ML-DSA security levels (FIPS 204) and the
classical baselines (ECDSA P-256, Ed25519) for contrast.

NOTE on SLH-DSA (FIPS 205): OpenSSL 3.5 signs *certificates* with SLH-DSA, but
SLH-DSA is NOT an enabled TLS 1.3 signature scheme here — `openssl list
-tls-signature-algorithms` ends at `mldsa44:mldsa65:mldsa87`, and loading an
SLH-DSA cert into s_server fails with "unknown certificate type". So SLH-DSA
cannot complete a handshake and is intentionally excluded from this live
selector. (It still appears in the capture/metrics primitive comparisons, which
exercise the signature itself rather than a TLS handshake.)

The key-exchange group is held fixed at the suite default (X25519MLKEM768); only
the certificate signature varies in this selector.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SigAlg:
    id: str            # canonical id (also the OpenSSL -algorithm name for PQC)
    label: str         # human label for the dashboard
    fips: str          # standard / family
    kind: str          # "lattice" | "hash-based" | "classical"
    keygen: str        # how gen_certs creates the key: "genpkey" | "ec" | "ed25519"
    note: str = ""


# Order = dashboard dropdown order. ML-DSA-65 first = the demo default.
SIG_ALGS: list[SigAlg] = [
    SigAlg("ML-DSA-65", "ML-DSA-65 (lattice, NIST L3)", "FIPS 204", "lattice", "genpkey",
           "demo default; balanced security/size"),
    SigAlg("ML-DSA-44", "ML-DSA-44 (lattice, NIST L2)", "FIPS 204", "lattice", "genpkey",
           "smallest ML-DSA signature"),
    SigAlg("ML-DSA-87", "ML-DSA-87 (lattice, NIST L5)", "FIPS 204", "lattice", "genpkey",
           "highest ML-DSA security level"),
    SigAlg("ECDSA-P256", "ECDSA P-256 (classical)", "SEC1 / FIPS 186", "classical", "ec",
           "classical baseline for contrast (not quantum-safe)"),
    SigAlg("ED25519", "Ed25519 (classical)", "RFC 8032", "classical", "ed25519",
           "classical baseline for contrast (not quantum-safe)"),
]

_BY_ID = {a.id: a for a in SIG_ALGS}
DEFAULT_SIG = "ML-DSA-65"


def get(sig_id: str) -> SigAlg:
    if sig_id not in _BY_ID:
        raise KeyError(f"unknown signature algorithm {sig_id!r}; "
                       f"choose one of {sorted(_BY_ID)}")
    return _BY_ID[sig_id]


def all_ids() -> list[str]:
    return [a.id for a in SIG_ALGS]
