#!/usr/bin/env bash
# deploy/two-pi-run.sh — generate a shared salt and print the exact role commands
# for a two-Pi run over the demo ethernet link.
#
# Both roles derive the app-layer AEAD key from the SAME --salt (see
# app/aead.py / protocol/message_format.md). If the salts differ, the message
# will not decrypt. This helper makes one salt and prints both commands so you
# paste each on the right Pi.
#
# Run FROM THE MAC (or anywhere); it only prints commands, it does not connect.
#
# Usage:
#   deploy/two-pi-run.sh "your message here"
set -euo pipefail

MSG="${1:-hello quantum world}"
SALT="$(openssl rand -hex 16 2>/dev/null || head -c16 /dev/urandom | xxd -p)"

HOST="10.0.0.1"   # server's demo-plane address (deploy/netplan-server.yaml)

cat <<EOF
Shared salt for this run:
  $SALT

────────────────────────────────────────────────────────────
ON THE SERVER PI (Pi-A, 10.0.0.1) — start this FIRST:
────────────────────────────────────────────────────────────
  cd <repo> && export PQC_OPENSSL="\$HOME/opt/openssl-3.5/bin/openssl"
  .venv/bin/python -m server \\
    --salt $SALT \\
    --host $HOST \\
    --keylog runs/server.keylog \\
    --events-file runs/server.jsonl

────────────────────────────────────────────────────────────
ON THE CLIENT PI (Pi-B, 10.0.0.2) — start this SECOND:
────────────────────────────────────────────────────────────
  cd <repo> && export PQC_OPENSSL="\$HOME/opt/openssl-3.5/bin/openssl"
  .venv/bin/python -m client \\
    --salt $SALT \\
    --message "$MSG" \\
    --host $HOST \\
    --events-file runs/client.jsonl

The salt MUST be identical on both ends (it is, above). Server first, then client.
EOF
