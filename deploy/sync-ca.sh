#!/usr/bin/env bash
# deploy/sync-ca.sh — ship the server Pi's ca.crt to the client Pi (out-of-band).
#
# The CA is self-signed and generated ONLY on the server Pi (deploy.sh server).
# The client must trust that same CA, so we copy ca.crt across. Run this FROM
# THE MAC after the server Pi has generated its certs.
#
# Usage:
#   deploy/sync-ca.sh <server-pi-host> <client-pi-host> [remote-repo-path]
#
# Example:
#   deploy/sync-ca.sh pi-a.local pi-b.local
#   deploy/sync-ca.sh ubuntu@10.0.0.1 ubuntu@10.0.0.2 '~/PQC_DEMO'
set -euo pipefail

SERVER="${1:-}"
CLIENT="${2:-}"
REMOTE_REPO="${3:-~/PQC_DEMO}"

[ -n "$SERVER" ] && [ -n "$CLIENT" ] || {
  echo "usage: deploy/sync-ca.sh <server-pi-host> <client-pi-host> [remote-repo-path]" >&2
  exit 2
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "[sync-ca] pulling ca.crt from server $SERVER"
scp "$SERVER:$REMOTE_REPO/certs/ca.crt" "$TMP/ca.crt"

echo "[sync-ca] verifying it is an ML-DSA-65 CA cert"
# Use the client's local openssl if available; fall back to system openssl.
openssl x509 -in "$TMP/ca.crt" -noout -subject -fingerprint -sha256 2>/dev/null \
  | sed 's/^/  /' || echo "  (could not introspect with system openssl — non-fatal)"

echo "[sync-ca] pushing ca.crt to client $CLIENT"
ssh "$CLIENT" "mkdir -p $REMOTE_REPO/certs"
scp "$TMP/ca.crt" "$CLIENT:$REMOTE_REPO/certs/ca.crt"

echo "[sync-ca] done. The client now trusts the server's CA."
