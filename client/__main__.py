"""Client role (runs on Pi-B). Same codebase as the server, different entrypoint.

Spawns the pinned PQC-TLS s_client, takes an operator-supplied plaintext message,
AEAD-seals it into the app frame, sends it over the established channel, and
emits schema events for the dashboard (stages: aead_encrypt, transmit).
See PROJECT_PLAN.md §4.1, §10 Phase 1.

Usage:
    python -m client --salt <hex> --message "hello quantum world" \
        [--host 127.0.0.1] [--port 4433] [--events-file runs/client.jsonl]
"""
from __future__ import annotations

import argparse
import socket
import sys
import time
from pathlib import Path

from app.aead import derive_app_key, seal
from app.config import load_suite
from app.events import EventEmitter, hex_preview
from app.tls_pipe import channel_binding, spawn_client


def _wait_for_port(host: str, port: int, timeout_s: float, interval: float = 0.5) -> bool:
    """Poll until host:port accepts a TCP connection, or timeout. Returns success."""
    deadline = time.time() + timeout_s
    announced = False
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return True
        except OSError:
            if not announced:
                print(f"[client] waiting for server at {host}:{port} …", file=sys.stderr)
                announced = True
            time.sleep(interval)
    return False


def main() -> int:
    suite = load_suite()
    ap = argparse.ArgumentParser()
    ap.add_argument("--salt", default=suite.demo_salt,
                    help="shared run salt (hex); must match server. Defaults to the "
                         "fixed demo salt in suite.conf so both Pis agree from a git pull.")
    ap.add_argument("--message", default=suite.default_message,
                    help="operator plaintext to send (defaults to suite.conf default_message)")
    ap.add_argument("--host", default=None,
                    help="server address (defaults to suite.conf server_addr)")
    ap.add_argument("--port", type=int, default=None)
    ap.add_argument("--events-file", default=None)
    ap.add_argument("--keylog", default=None)
    ap.add_argument("--connect-wait", type=float, default=1.0,
                    help="seconds to wait for the TLS handshake before sending")
    ap.add_argument("--wait-for-server", type=float, default=60.0,
                    help="seconds to keep retrying until the server's port is open "
                         "(survives starting the client before the server)")
    ap.add_argument("--sig-alg", default=None,
                    help="certificate signature algorithm (must match the server)")
    ap.add_argument("--group", default=None,
                    help="key-exchange group (must match the server)")
    args = ap.parse_args()

    host = args.host or suite.server_addr
    args.host = host
    port = args.port or suite.server_port
    run_salt = bytes.fromhex(args.salt)
    key, nonce_seed = derive_app_key(channel_binding(suite, run_salt))

    emitter = EventEmitter("client", to_stdout=True, file_path=args.events_file)
    keylog = Path(args.keylog) if args.keylog else None

    # Wait for the server's TCP port to be open before opening s_client. This is
    # what makes "start client before server" safe on demo day — we retry the
    # cheap TCP probe rather than failing on a refused connection.
    if not _wait_for_port(args.host, port, args.wait_for_server):
        print(f"[client] ERROR: server {args.host}:{port} not reachable after "
              f"{args.wait_for_server}s", file=sys.stderr)
        emitter.close()
        return 1

    # Use the CA matching the server's chosen signature algorithm.
    sig_alg = args.sig_alg or suite.sig_alg
    from app.gen_certs import ensure_cert
    ca, _crt, _key = ensure_cert(sig_alg)

    group = args.group or suite.group
    proc = spawn_client(suite, host=args.host, port=port, keylog=keylog, ca=ca, group=group)
    print(f"[client] connecting to {args.host}:{port} group={group} "
          f"sig={sig_alg}", file=sys.stderr)
    # Let the handshake complete (it is milliseconds; we wait conservatively).
    time.sleep(args.connect_wait)

    plaintext = args.message.encode("utf-8")
    seq = 0
    parts = seal(plaintext, seq, key, nonce_seed)

    emitter.emit("aead_encrypt", "plaintext", artifact_bytes=plaintext,
                 algorithm=suite.app_aead,
                 human_readable=args.message)
    emitter.emit("aead_encrypt", "aead_ciphertext", artifact_bytes=parts.ciphertext,
                 algorithm=suite.app_aead, human_readable=hex_preview(parts.ciphertext))
    emitter.emit("aead_encrypt", "aead_tag", artifact_bytes=parts.tag,
                 algorithm=suite.app_aead, human_readable=hex_preview(parts.tag))

    try:
        proc.stdin.write(parts.wire)
        proc.stdin.flush()
        emitter.emit("transmit", "wire_frame", artifact_bytes=parts.wire,
                     algorithm=suite.app_aead,
                     human_readable=f"{len(parts.wire)} bytes on the wire "
                                    f"(header {len(parts.aad)} + ct {len(parts.ciphertext)} + tag {len(parts.tag)})")
        print(f"[client] sent {len(parts.wire)} bytes seq={seq}", file=sys.stderr)
        # Give the server time to read before we tear down the channel.
        time.sleep(0.5)
        return 0
    except BrokenPipeError as e:
        err = proc.stderr.read().decode("utf-8", "replace") if proc.stderr else ""
        print(f"[client] ERROR: connection broke: {e}\n{err}", file=sys.stderr)
        return 1
    finally:
        try:
            proc.stdin.close()
        except Exception:
            pass
        proc.terminate()
        emitter.close()


if __name__ == "__main__":
    raise SystemExit(main())
