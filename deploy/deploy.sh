#!/usr/bin/env bash
# deploy/deploy.sh — one-command demo-day deploy + launch on a Pi.
#
# Run this ON the Pi. The repo is canonical on the Mac and pushed to a git
# remote; the Pi is a deploy target, never edited directly (PROJECT_PLAN.md §11).
#
# DEMO DAY (zero manual steps — salt, message, addresses, certs all come from
# the committed repo + protocol/suite.conf):
#   On the SERVER Pi (qianpi, 10.0.0.2):   cd ~/PQC_DEMO && ./deploy/deploy.sh server
#       -> pulls, builds if needed, starts the dashboard + opens the browser,
#          and listens for the client's message.
#   On the CLIENT Pi (ben, 10.0.0.1):      cd ~/PQC_DEMO && ./deploy/deploy.sh client
#       -> pulls, builds if needed, waits for the server, connects and sends the
#          default message. Watch it traverse the stages on the server's dashboard.
#
#   Order does not matter: the client waits for the server's port to open.
#
# Usage:
#   deploy/deploy.sh server | client
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

# 4) Certs. The demo CA + server cert are COMMITTED to the repo (throwaway demo
#    certs), so a `git pull` gives BOTH Pis the same CA with zero coordination.
#    If they are somehow missing (e.g. a fresh gen), the server regenerates and
#    you must re-commit; the client just needs the committed ca.crt.
if [ ! -f certs/ca.crt ] || [ ! -f certs/server.crt ]; then
  if [ "$ROLE" = "server" ]; then
    echo "[deploy] certs missing — generating ML-DSA-65 CA + server cert"
    .venv/bin/python -m app.gen_certs
    echo "[deploy] NOTE: commit the regenerated certs/ so the client gets this CA."
  else
    echo "[deploy] ERROR: certs/ca.crt missing on the client and not in the repo." >&2
    echo "  Pull a commit that includes certs/, or copy ca.crt from the server Pi." >&2
    exit 3
  fi
fi
echo "[deploy] CA fingerprint (must match on both Pis):"
"$PQC_OPENSSL" x509 -in certs/ca.crt -noout -fingerprint -sha256 2>/dev/null | sed 's/^/  /' || true

# Read the demo-plane server address + port from suite.conf (single source).
SRV_ADDR="$(.venv/bin/python -c 'from app.config import SUITE; print(SUITE.server_addr)')"
SRV_PORT="$(.venv/bin/python -c 'from app.config import SUITE; print(SUITE.server_port)')"
mkdir -p runs

if [ "$NO_START" = "1" ]; then
  echo "[deploy] prepared (--no-start)."
  echo "  server: .venv/bin/python -m server --host $SRV_ADDR --events-file runs/server.jsonl"
  echo "  client: .venv/bin/python -m client --host $SRV_ADDR --events-file runs/client.jsonl"
  exit 0
fi

# 5) Demo-day launch. Salt + message default from suite.conf, so no args needed.
if [ "$ROLE" = "server" ]; then
  # Start the dashboard (reachable on the link) and open the browser, then run
  # the TLS server role listening for the client's message. The dashboard keeps
  # running; the server role processes one message per invocation.
  DASH_PORT=8080
  echo "[deploy] starting dashboard on 0.0.0.0:$DASH_PORT (open http://$SRV_ADDR:$DASH_PORT)"
  .venv/bin/python -m dashboard.server --host 0.0.0.0 --port "$DASH_PORT" \
      --open --open-url "http://$SRV_ADDR:$DASH_PORT" >runs/dashboard.log 2>&1 &
  DASH_PID=$!
  trap 'kill $DASH_PID 2>/dev/null || true' EXIT

  echo "[deploy] server listening on $SRV_ADDR:$SRV_PORT for the client's message…"
  echo "[deploy] (the client Pi: cd ~/PQC_DEMO && ./deploy/deploy.sh client)"
  .venv/bin/python -m server --host "$SRV_ADDR" \
      --keylog runs/server.keylog --events-file runs/server.jsonl

  echo "[deploy] message received. Dashboard still running at http://$SRV_ADDR:$DASH_PORT"
  echo "[deploy] press Ctrl-C to stop the dashboard."
  wait "$DASH_PID"
else
  # Client: wait for the server to be up, then connect + send the default message.
  echo "[deploy] client connecting to $SRV_ADDR:$SRV_PORT (waits for the server)…"
  .venv/bin/python -m client --host "$SRV_ADDR" \
      --events-file runs/client.jsonl
  echo "[deploy] client done. Watch the dashboard on the server Pi to see the stages."
fi
