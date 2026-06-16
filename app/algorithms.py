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
from pathlib import Path


@dataclass(frozen=True)
class SigAlg:
    id: str            # canonical id (also the OpenSSL -algorithm name for PQC)
    label: str         # human label for the dashboard (FIPS name)
    fips: str          # standard / family
    kind: str          # "lattice" | "hash-based" | "classical"
    keygen: str        # how gen_certs creates the key: "genpkey" | "ec" | "ed25519"
    note: str = ""
    legacy: str = ""   # informal pre-standardization name shown as a hint, e.g.
                       # "≈ Dilithium3". NOT a synonym: ML-DSA is the modified,
                       # standardized successor of CRYSTALS-Dilithium, so we show
                       # it as an approximate correspondence, never an equality.
    provider: str = "" # extra OpenSSL provider this alg needs, e.g. "oqsprovider"
                       # for Falcon. Empty = native (default provider only).


# Order = dashboard dropdown order. ML-DSA-65 first = the demo default.
# legacy hints use the exact NIST parameter-set correspondence (ML-DSA-65 is the
# standardized successor of Dilithium3, ML-DSA-44 of Dilithium2, ML-DSA-87 of
# Dilithium5). Phrased "≈" because FIPS 204 modified the scheme; they are not
# identical to the round-3 CRYSTALS-Dilithium submissions.
SIG_ALGS: list[SigAlg] = [
    SigAlg("ML-DSA-65", "ML-DSA-65 (lattice, NIST L3)", "FIPS 204", "lattice", "genpkey",
           "demo default; balanced security/size", legacy="≈ Dilithium3"),
    SigAlg("ML-DSA-44", "ML-DSA-44 (lattice, NIST L2)", "FIPS 204", "lattice", "genpkey",
           "smallest ML-DSA signature", legacy="≈ Dilithium2"),
    SigAlg("ML-DSA-87", "ML-DSA-87 (lattice, NIST L5)", "FIPS 204", "lattice", "genpkey",
           "highest ML-DSA security level", legacy="≈ Dilithium5"),
    SigAlg("ECDSA-P256", "ECDSA P-256 (classical)", "SEC1 / FIPS 186", "classical", "ec",
           "classical baseline for contrast (not quantum-safe)"),
    SigAlg("ED25519", "Ed25519 (classical)", "RFC 8032", "classical", "ed25519",
           "classical baseline for contrast (not quantum-safe)"),
]

# --- Optional: Falcon / FN-DSA via the OQS provider ---------------------------
# Falcon is NOT native to OpenSSL 3.5 (PROJECT_PLAN.md §2, §5). If the operator
# has run crypto/setup-oqs.sh, the oqs-provider exposes Falcon and we add it to
# the selector; otherwise it never appears. Detection is cached (one subprocess).
import functools
import os
import subprocess


@functools.lru_cache(maxsize=1)
def oqs_falcon_algs() -> list[SigAlg]:
    """Return Falcon SigAlg entries if the OQS provider is present, else []."""
    from app.config import openssl_bin
    modules = oqs_modules_dir()  # ~/opt/openssl-3.5/lib/ossl-modules by default
    try:
        env = {**os.environ, "OPENSSL_MODULES": modules}
        p = subprocess.run(
            [openssl_bin(), "list", "-signature-algorithms",
             "-provider", "oqsprovider", "-provider", "default"],
            capture_output=True, text=True, env=env, timeout=10,
        )
        out = (p.stdout + p.stderr).lower()
    except Exception:
        return []
    algs: list[SigAlg] = []
    # oqs-provider names: "falcon512" / "falcon1024" (FN-DSA is FIPS 206 draft).
    if "falcon512" in out:
        algs.append(SigAlg("falcon512", "Falcon-512 (FN-DSA, lattice, NIST L1)",
                           "FIPS 206 draft (via OQS)", "lattice", "genpkey",
                           "compact lattice signature; needs oqs-provider",
                           legacy="Falcon-512", provider="oqsprovider"))
    if "falcon1024" in out:
        algs.append(SigAlg("falcon1024", "Falcon-1024 (FN-DSA, lattice, NIST L5)",
                           "FIPS 206 draft (via OQS)", "lattice", "genpkey",
                           "compact lattice signature, high security; needs oqs-provider",
                           legacy="Falcon-1024", provider="oqsprovider"))
    return algs


def oqs_modules_dir() -> str:
    """Path to the OpenSSL modules dir holding oqsprovider (env override allowed)."""
    return os.environ.get(
        "OPENSSL_MODULES",
        str(Path.home() / "opt" / "openssl-3.5" / "lib" / "ossl-modules"))


def provider_env(sig_id: str | None = None, group: str | None = None) -> dict:
    """Extra environment (OPENSSL_MODULES) needed to run sig_id/group, if any."""
    needs = bool(sig_id and get(sig_id).provider) if sig_id else False
    return {"OPENSSL_MODULES": oqs_modules_dir()} if needs else {}


def provider_args(sig_id: str | None = None, group: str | None = None) -> list[str]:
    """Extra OpenSSL CLI args (-provider ...) needed to run sig_id/group, if any.

    When an algorithm needs oqsprovider we must load BOTH it and the default
    provider (default still supplies X25519, AES, the native ML-KEM group, etc.).
    """
    needs = bool(sig_id and get(sig_id).provider) if sig_id else False
    return ["-provider", "oqsprovider", "-provider", "default"] if needs else []


def active_sig_algs() -> list[SigAlg]:
    """The selectable signature algorithms, including Falcon if OQS is installed."""
    return SIG_ALGS + oqs_falcon_algs()


_BY_ID = {a.id: a for a in SIG_ALGS}
DEFAULT_SIG = "ML-DSA-65"


def get(sig_id: str) -> SigAlg:
    table = {a.id: a for a in active_sig_algs()}
    if sig_id not in table:
        raise KeyError(f"unknown signature algorithm {sig_id!r}; "
                       f"choose one of {sorted(table)}")
    return table[sig_id]


def all_ids() -> list[str]:
    return [a.id for a in active_sig_algs()]


# --- Key-exchange (KEM) groups ------------------------------------------------
# These are TLS 1.3 group names valid in the pinned OpenSSL 3.5.7 build (verified
# via `openssl list -tls-groups`). Only the group changes; no cert is needed, so
# switching groups is cheaper than switching signatures. legacy hint follows the
# same "≈" convention (ML-KEM is the standardized successor of CRYSTALS-Kyber).

@dataclass(frozen=True)
class KemGroup:
    id: str            # OpenSSL TLS group name (passed to -groups)
    label: str
    fips: str
    kind: str          # "hybrid" | "pure-pqc" | "classical"
    note: str = ""
    legacy: str = ""


# Order = dropdown order; X25519MLKEM768 first = the demo/suite default.
KEM_GROUPS: list[KemGroup] = [
    KemGroup("X25519MLKEM768", "X25519MLKEM768 (hybrid)", "FIPS 203 + RFC", "hybrid",
             "demo default; X25519 ⊕ ML-KEM-768. OpenSSL 3.5 default group.",
             legacy="X25519 ⊕ ≈Kyber-768"),
    KemGroup("SecP256r1MLKEM768", "SecP256r1MLKEM768 (hybrid)", "FIPS 203 + RFC", "hybrid",
             "P-256 ⊕ ML-KEM-768 hybrid", legacy="P-256 ⊕ ≈Kyber-768"),
    KemGroup("SecP384r1MLKEM1024", "SecP384r1MLKEM1024 (hybrid, L5)", "FIPS 203 + RFC", "hybrid",
             "P-384 ⊕ ML-KEM-1024, highest level hybrid", legacy="P-384 ⊕ ≈Kyber-1024"),
    KemGroup("MLKEM512", "ML-KEM-512 (pure PQC, L1)", "FIPS 203", "pure-pqc",
             "pure ML-KEM, no classical hybrid; smallest", legacy="≈ Kyber-512"),
    KemGroup("MLKEM768", "ML-KEM-768 (pure PQC, L3)", "FIPS 203", "pure-pqc",
             "pure ML-KEM-768, no classical hybrid", legacy="≈ Kyber-768"),
    KemGroup("MLKEM1024", "ML-KEM-1024 (pure PQC, L5)", "FIPS 203", "pure-pqc",
             "pure ML-KEM-1024, no classical hybrid", legacy="≈ Kyber-1024"),
    KemGroup("x25519", "X25519 (classical)", "RFC 7748", "classical",
             "classical baseline for contrast (not quantum-safe)"),
    KemGroup("secp256r1", "secp256r1 / P-256 (classical)", "SEC1", "classical",
             "classical baseline for contrast (not quantum-safe)"),
]

_GROUP_BY_ID = {g.id: g for g in KEM_GROUPS}
DEFAULT_GROUP = "X25519MLKEM768"


def get_group(group_id: str) -> KemGroup:
    if group_id not in _GROUP_BY_ID:
        raise KeyError(f"unknown KEM group {group_id!r}; "
                       f"choose one of {sorted(_GROUP_BY_ID)}")
    return _GROUP_BY_ID[group_id]


def all_group_ids() -> list[str]:
    return [g.id for g in KEM_GROUPS]
