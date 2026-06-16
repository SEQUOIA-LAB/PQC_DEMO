#!/usr/bin/env bash
# deploy/deploy.sh — git-pull based deploy to a Pi (PROJECT_PLAN.md §11).
#
# Run this ON the Pi (via Remote-SSH). The repo is canonical on the Mac and
# pushed to a git remote; the Pi is a deploy target, never edited directly.
#
# Steps: pull, build pinned OpenSSL if needed, sync pinned Python deps into a
# venv, regenerate certs if absent, then (optionally) start the role.
#
# Usage (on the Pi):
#   deploy/deploy.sh server     # or: client
#   deploy/deploy.sh server --no-start   # prepare only, don't launch
set -euo pipefail

ROLE="${1:-}"
shift || true
NO_START=0
for arg in "$@"; do [ "$arg" = "--no-start" ] && NO_START=1; done

[ "$ROLE" = "server" ] || [ "$ROLE" = "client" ] || {
  echo "usage: deploy/deploy.sh <server|client> [--no-start]" >&2; exit 2; }

cd "$(dirname "$0")/.."
REPO="$(pwd)"
export PQC_OPENSSL="$HOME/opt/openssl-3.5/bin/openssl"

echo "[deploy] role=$ROLE repo=$REPO"

# 1) Pull canonical source.
echo "[deploy] git pull"
git pull --ff-only

# 2) Build pinned OpenSSL on this machine if missing/wrong version.
if [ ! -x "$PQC_OPENSSL" ]; then
  echo "[deploy] building pinned OpenSSL (first run on this Pi)"
  crypto/setup-openssl.sh
fi

# 3) Python venv + pinned deps.
#    On Ubuntu the venv module is a SEPARATE apt package (python3-venv /
#    python3.NN-venv). If it is missing, `python3 -m venv` half-fails and leaves
#    a .venv with no bin/pip — the confusing "no such file or directory" error.
#    Detect it up front, try to install it, and fail loud if we can't.
if [ ! -x .venv/bin/pip ]; then
  rm -rf .venv  # clear any half-created venv from a previous failed run
  echo "[deploy] creating venv"
  if ! python3 -m venv .venv 2>/tmp/venv-err; then
    cat /tmp/venv-err >&2 || true
    PYVER="$(python3 -c 'import sys;print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
    echo "[deploy] venv creation failed. The python venv package is likely missing." >&2
    echo "[deploy] attempting: sudo apt-get install -y python3-venv python${PYVER}-venv" >&2
    if command -v sudo >/dev/null && sudo apt-get install -y "python3-venv" "python${PYVER}-venv"; then
      python3 -m venv .venv
    else
      echo "[deploy] ERROR: install the venv package and re-run, e.g.:" >&2
      echo "          sudo apt-get install -y python${PYVER}-venv" >&2
      exit 4
    fi
  fi
  # Verify the venv is actually usable before relying on it.
  [ -x .venv/bin/pip ] || { echo "[deploy] ERROR: .venv/bin/pip still missing after venv creation." >&2; exit 4; }
fi
echo "[deploy] syncing pinned Python deps"
.venv/bin/pip install -q -r requirements.txt

# 4) Certs. The CA is self-signed, so BOTH Pis must trust the SAME CA. We
#    generate the CA + server cert ON THE SERVER PI only, then ship ca.crt to
#    the client out-of-band (deploy/sync-ca.sh). The client must NOT generate
#    its own CA — that would produce a different root and the handshake fails.
if [ "$ROLE" = "server" ]; then
  if [ ! -f certs/server.crt ]; then
    echo "[deploy] generating ML-DSA-65 CA + server cert (server is the cert authority)"
    .venv/bin/python -m app.gen_certs
  fi
  echo "[deploy] NEXT: copy certs/ca.crt to the CLIENT Pi, e.g. from the Mac:"
  echo "  deploy/sync-ca.sh <server-pi-host> <client-pi-host>"
else  # client
  if [ ! -f certs/ca.crt ]; then
    echo "[deploy] ERROR: certs/ca.crt missing on the client." >&2
    echo "  The client must NOT generate its own CA. Copy the server's ca.crt here:" >&2
    echo "  (from the Mac)  deploy/sync-ca.sh <server-pi-host> <client-pi-host>" >&2
    echo "  (or manually)   scp <server-pi>:$REPO/certs/ca.crt $REPO/certs/ca.crt" >&2
    exit 3
  fi
  echo "[deploy] client using shipped ca.crt (CA fingerprint below):"
  "$PQC_OPENSSL" x509 -in certs/ca.crt -noout -fingerprint -sha256 2>/dev/null | sed 's/^/  /' || true
fi

if [ "$NO_START" = "1" ]; then
  echo "[deploy] prepared (--no-start). Start manually with: python -m $ROLE ..."
  exit 0
fi

# 5) Launch the role on the demo-plane address from protocol/suite.conf.
#    The salt must match the other Pi; pass the same --salt to both.
echo "[deploy] starting role '$ROLE'. Provide --salt (shared) and role args:"
echo "  server: .venv/bin/python -m server --salt <hex> --host 10.0.0.1 --keylog runs/server.keylog --events-file runs/server.jsonl"
echo "  client: .venv/bin/python -m client --salt <hex> --message '...' --host 10.0.0.1 --events-file runs/client.jsonl"
