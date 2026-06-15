#!/usr/bin/env bash
# crypto/setup-openssl.sh — build a pinned OpenSSL from source on macOS or Linux.
#
# Why from source (PROJECT_PLAN.md §5, §12):
#   - OpenSSL 3.5 LTS ships NATIVE ML-KEM (FIPS 203), ML-DSA (FIPS 204),
#     SLH-DSA (FIPS 205) and X25519MLKEM768 as a default TLS 1.3 group.
#   - Same git tag -> identical behaviour on Mac, the arm64 Ubuntu container,
#     and the Pi. Never copy compiled binaries between machines.
#
# Installs to a LOCAL prefix (default ~/opt/openssl-3.5), never the system
# OpenSSL. Idempotent: skips the build if the target version is already present.
#
# Usage:
#   crypto/setup-openssl.sh            # build pinned version to default prefix
#   OPENSSL_PREFIX=/opt/o35 crypto/setup-openssl.sh
#   OPENSSL_VERSION=3.5.7 crypto/setup-openssl.sh
set -euo pipefail

# --- Pinned version (verified 2026-06-15: latest 3.5.x LTS patch release) -----
OPENSSL_VERSION="${OPENSSL_VERSION:-3.5.7}"
OPENSSL_TAG="openssl-${OPENSSL_VERSION}"
OPENSSL_PREFIX="${OPENSSL_PREFIX:-$HOME/opt/openssl-3.5}"
JOBS="${JOBS:-$( (command -v nproc >/dev/null && nproc) || sysctl -n hw.ncpu || echo 4)}"

# Source tarball + its SHA-256 (verify integrity; reproducibility guarantee).
TARBALL="${OPENSSL_TAG}.tar.gz"
SRC_URL="https://github.com/openssl/openssl/releases/download/${OPENSSL_TAG}/${TARBALL}"
BUILD_ROOT="${BUILD_ROOT:-/tmp/pqc-openssl-build}"

log() { printf '\033[1;34m[setup-openssl]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[setup-openssl] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# --- Already installed? -------------------------------------------------------
OSSL_BIN="${OPENSSL_PREFIX}/bin/openssl"
if [ -x "$OSSL_BIN" ]; then
  have="$("$OSSL_BIN" version | awk '{print $2}')"
  if [ "$have" = "$OPENSSL_VERSION" ]; then
    log "OpenSSL ${OPENSSL_VERSION} already installed at ${OPENSSL_PREFIX} — skipping build."
    "$OSSL_BIN" version -a | sed 's/^/    /'
    exit 0
  fi
  log "Found OpenSSL ${have} at prefix but want ${OPENSSL_VERSION}; rebuilding."
fi

uname_s="$(uname -s)"
log "Building OpenSSL ${OPENSSL_VERSION} (${OPENSSL_TAG}) on ${uname_s} -> ${OPENSSL_PREFIX}"

# --- Toolchain check ----------------------------------------------------------
for tool in make cc tar; do
  command -v "$tool" >/dev/null || die "missing required tool: $tool"
done
# perl is required by OpenSSL's Configure.
command -v perl >/dev/null || die "missing required tool: perl"

# --- Fetch source -------------------------------------------------------------
mkdir -p "$BUILD_ROOT"
cd "$BUILD_ROOT"
if [ ! -f "$TARBALL" ]; then
  log "Downloading ${SRC_URL}"
  if command -v curl >/dev/null; then
    curl -fsSL -o "$TARBALL" "$SRC_URL"
  else
    wget -O "$TARBALL" "$SRC_URL"
  fi
fi

# Integrity: verify against the .sha256 published alongside the release.
if command -v sha256sum >/dev/null || command -v shasum >/dev/null; then
  log "Fetching published SHA-256 for integrity check"
  if command -v curl >/dev/null; then
    curl -fsSL -o "${TARBALL}.sha256" "${SRC_URL}.sha256" || log "WARN: could not fetch .sha256 (continuing without verify)"
  fi
  if [ -f "${TARBALL}.sha256" ]; then
    expected="$(awk '{print $1}' "${TARBALL}.sha256")"
    if command -v sha256sum >/dev/null; then
      actual="$(sha256sum "$TARBALL" | awk '{print $1}')"
    else
      actual="$(shasum -a 256 "$TARBALL" | awk '{print $1}')"
    fi
    [ "$expected" = "$actual" ] || die "SHA-256 mismatch for ${TARBALL} (expected ${expected}, got ${actual})"
    log "SHA-256 OK: ${actual}"
  fi
fi

# --- Unpack -------------------------------------------------------------------
rm -rf "$OPENSSL_TAG"
tar xzf "$TARBALL"
cd "$OPENSSL_TAG"

# --- Configure ----------------------------------------------------------------
# Detect platform target for OpenSSL's Configure. Both Mac (Apple Silicon) and
# the Pi/container are arm64, but the OS differs (Mach-O vs ELF, different libc),
# so let Configure auto-detect via `./config` rather than hardcoding.
COMMON_OPTS=(
  "--prefix=${OPENSSL_PREFIX}"
  "--openssldir=${OPENSSL_PREFIX}/ssl"
  "shared"
  "no-tests"
  # SSLKEYLOGFILE support is OFF by default in 3.5; capture/ uses it to take a
  # fingerprint of the TLS secrets (PROJECT_PLAN.md §13). Enable it so a rebuilt
  # binary exposes the keylog. (capture/ degrades gracefully if absent.)
  "enable-sslkeylog"
)
# rpath so the built openssl finds its own libcrypto/libssl without env vars.
if [ "$uname_s" = "Darwin" ]; then
  log "Configuring (macOS / Apple Silicon)"
  ./Configure darwin64-arm64-cc "${COMMON_OPTS[@]}" \
    -Wl,-rpath,"${OPENSSL_PREFIX}/lib"
else
  log "Configuring (Linux, auto-detect arch)"
  ./config "${COMMON_OPTS[@]}" \
    -Wl,-rpath,"${OPENSSL_PREFIX}/lib" \
    -Wl,-rpath,"${OPENSSL_PREFIX}/lib64"
fi

# --- Build & install ----------------------------------------------------------
log "Compiling with -j${JOBS} (this takes a few minutes)"
make -j"${JOBS}"
log "Installing software (install_sw) to ${OPENSSL_PREFIX}"
make install_sw

# --- Verify -------------------------------------------------------------------
log "Installed:"
"$OSSL_BIN" version -a | sed 's/^/    /'

log "Confirming PQC algorithms are present:"
"$OSSL_BIN" list -kem-algorithms       | grep -i "ML-KEM"  | sed 's/^/    /' || die "ML-KEM not found in build"
"$OSSL_BIN" list -signature-algorithms | grep -i "ML-DSA"  | sed 's/^/    /' || die "ML-DSA not found in build"
"$OSSL_BIN" list -signature-algorithms | grep -i "SLH-DSA" | sed 's/^/    /' || log "WARN: SLH-DSA label not found (non-fatal)"

cat <<EOF

[setup-openssl] DONE.
  Binary : ${OSSL_BIN}
  Prefix : ${OPENSSL_PREFIX}

  Add to your shell for this project:
    export PATH="${OPENSSL_PREFIX}/bin:\$PATH"
    export PQC_OPENSSL="${OSSL_BIN}"
EOF
