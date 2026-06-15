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
import sys
import time
from pathlib import Path

from app.aead import derive_app_key, seal
from app.config import load_suite
from app.events import EventEmitter, hex_preview
from app.tls_pipe import channel_binding, spawn_client


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--salt", required=True, help="shared run salt (hex); must match server")
    ap.add_argument("--message", required=True, help="operator plaintext to send")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=None)
    ap.add_argument("--events-file", default=None)
    ap.add_argument("--keylog", default=None)
    ap.add_argument("--connect-wait", type=float, default=1.0,
                    help="seconds to wait for the TLS handshake before sending")
    args = ap.parse_args()

    suite = load_suite()
    port = args.port or suite.server_port
    run_salt = bytes.fromhex(args.salt)
    key, nonce_seed = derive_app_key(channel_binding(suite, run_salt))

    emitter = EventEmitter("client", to_stdout=True, file_path=args.events_file)
    keylog = Path(args.keylog) if args.keylog else None

    proc = spawn_client(suite, host=args.host, port=port, keylog=keylog)
    print(f"[client] connecting to {args.host}:{port} group={suite.group}",
          file=sys.stderr)
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
