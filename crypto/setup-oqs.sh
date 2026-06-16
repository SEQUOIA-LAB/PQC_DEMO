#!/usr/bin/env bash
# crypto/setup-oqs.sh — OPTIONAL: build liboqs + oqs-provider against our pinned
# OpenSSL, to add Falcon / FN-DSA (FIPS 206 draft) to the demo.
#
# This is intentionally OFF the default path (PROJECT_PLAN.md §5): the core demo
# uses only native OpenSSL 3.5 algorithms. Falcon is NOT native to OpenSSL — it
# needs the Open Quantum Safe provider. Run this only if you want Falcon at the
# demo table.
#
# After running this, app/algorithms.py auto-detects the provider and adds the
# Falcon options to the signature dropdown; without it, they simply don't appear.
#
# Usage:
#   crypto/setup-oqs.sh                 # build against ~/opt/openssl-3.5
#   OPENSSL_PREFIX=/path crypto/setup-oqs.sh
#
# Requires: cmake, ninja or make, a C compiler, git. On Ubuntu:
#   sudo apt-get install -y cmake ninja-build build-essential git
set -euo pipefail

OPENSSL_PREFIX="${OPENSSL_PREFIX:-$HOME/opt/openssl-3.5}"
OQS_PREFIX="${OQS_PREFIX:-$HOME/opt/oqs}"
BUILD_ROOT="${BUILD_ROOT:-/tmp/pqc-oqs-build}"
JOBS="${JOBS:-$( (command -v nproc >/dev/null && nproc) || sysctl -n hw.ncpu || echo 4)}"

# Pin versions for reproducibility (PROJECT_PLAN.md §12).
LIBOQS_TAG="${LIBOQS_TAG:-0.12.0}"
OQS_PROVIDER_TAG="${OQS_PROVIDER_TAG:-0.8.0}"

log() { printf '\033[1;34m[setup-oqs]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[setup-oqs] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[ -x "$OPENSSL_PREFIX/bin/openssl" ] || die "pinned OpenSSL not found at $OPENSSL_PREFIX (run crypto/setup-openssl.sh first)"
for t in cmake git cc; do command -v "$t" >/dev/null || die "missing required tool: $t"; done

mkdir -p "$BUILD_ROOT"; cd "$BUILD_ROOT"

# 1) liboqs (the algorithm implementations, incl. Falcon).
if [ ! -d liboqs ]; then
  log "cloning liboqs $LIBOQS_TAG"
  git clone --depth 1 --branch "$LIBOQS_TAG" https://github.com/open-quantum-safe/liboqs.git
fi
log "building liboqs -> $OQS_PREFIX"
cmake -S liboqs -B liboqs/build -DCMAKE_INSTALL_PREFIX="$OQS_PREFIX" \
  -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON \
  -DCMAKE_BUILD_TYPE=Release ${CMAKE_GENERATOR:+-G "$CMAKE_GENERATOR"}
cmake --build liboqs/build --parallel "$JOBS"
cmake --install liboqs/build

# 2) oqs-provider (exposes liboqs algorithms to OpenSSL 3.x as a provider).
if [ ! -d oqs-provider ]; then
  log "cloning oqs-provider $OQS_PROVIDER_TAG"
  git clone --depth 1 --branch "$OQS_PROVIDER_TAG" https://github.com/open-quantum-safe/oqs-provider.git
fi
log "building oqs-provider against $OPENSSL_PREFIX"
cmake -S oqs-provider -B oqs-provider/build \
  -DCMAKE_PREFIX_PATH="$OQS_PREFIX;$OPENSSL_PREFIX" \
  -DOPENSSL_ROOT_DIR="$OPENSSL_PREFIX" \
  -DCMAKE_BUILD_TYPE=Release ${CMAKE_GENERATOR:+-G "$CMAKE_GENERATOR"}
cmake --build oqs-provider/build --parallel "$JOBS"

# Install the provider module into the OpenSSL modules dir.
MODULES_DIR="$($OPENSSL_PREFIX/bin/openssl version -m | sed 's/.*: *"//; s/"//')"
[ -d "$MODULES_DIR" ] || MODULES_DIR="$OPENSSL_PREFIX/lib/ossl-modules"
mkdir -p "$MODULES_DIR"
PROV_LIB="$(find oqs-provider/build -name 'oqsprovider.*' \( -name '*.so' -o -name '*.dylib' \) | head -1)"
[ -n "$PROV_LIB" ] || die "could not find built oqsprovider module"
cp "$PROV_LIB" "$MODULES_DIR/"
log "installed provider: $MODULES_DIR/$(basename "$PROV_LIB")"

cat <<EOF

[setup-oqs] DONE.
  To activate the provider, the demo's OpenSSL must load it. Add to
  crypto/openssl.cnf under [provider_sect]:
      oqsprovider = oqs_sect
  and a section:
      [oqs_sect]
      activate = 1
  (or run with: -provider oqsprovider -provider default)

  Then verify Falcon is present:
    OPENSSL_MODULES=$MODULES_DIR $OPENSSL_PREFIX/bin/openssl list -signature-algorithms -provider oqsprovider | grep -i falcon

  app/algorithms.py auto-detects the provider and adds Falcon to the dropdown.
EOF
