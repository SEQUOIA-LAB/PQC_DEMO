"""Server role (runs on Pi-A). Same codebase as the client, different entrypoint.

Spawns the pinned PQC-TLS s_server, then reads ONE app-layer framed message from
the client, decrypts + verifies it, and emits schema events for the dashboard
(stages: aead_decrypt, verify). See PROJECT_PLAN.md §4.1, §10 Phase 1.

Usage:
    python -m server --salt <hex> [--host 127.0.0.1] [--port 4433] \
        [--events-file runs/server.jsonl] [--keylog runs/server.keylog]
"""
from __future__ import annotations

import argparse
import struct
import sys
import time
from pathlib import Path

from app.aead import HEADER_LEN, TAG_LEN, derive_app_key, open_frame, parse_header
from app.config import REPO_ROOT, load_suite
from app.events import EventEmitter, hex_preview
from app.tls_pipe import channel_binding, spawn_server


def _read_exact(stream, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = stream.read(n - len(buf))
        if not chunk:
            raise EOFError(f"stream closed after {len(buf)}/{n} bytes")
        buf += chunk
    return buf


def main() -> int:
    suite = load_suite()
    ap = argparse.ArgumentParser()
    ap.add_argument("--salt", default=suite.demo_salt,
                    help="shared run salt (hex); must match client. Defaults to the "
                         "fixed demo salt in suite.conf so both Pis agree from a git pull.")
    ap.add_argument("--host", default=None,
                    help="address to bind (defaults to suite.conf server_addr)")
    ap.add_argument("--port", type=int, default=None)
    ap.add_argument("--events-file", default=None)
    ap.add_argument("--keylog", default=None)
    ap.add_argument("--sig-alg", default=None,
                    help="certificate signature algorithm (defaults to suite default)")
    args = ap.parse_args()

    host = args.host or suite.server_addr
    args.host = host
    port = args.port or suite.server_port
    run_salt = bytes.fromhex(args.salt)
    key, nonce_seed = derive_app_key(channel_binding(suite, run_salt))

    # Resolve the cert for the chosen signature algorithm (defaults to suite).
    sig_alg = args.sig_alg or suite.sig_alg
    from app.gen_certs import ensure_cert
    _ca, cert, srv_key = ensure_cert(sig_alg)

    emitter = EventEmitter("server", to_stdout=True,
                           file_path=args.events_file)
    keylog = Path(args.keylog) if args.keylog else None

    proc = spawn_server(suite, host=args.host, port=port, keylog=keylog,
                        cert=cert, key=srv_key)
    print(f"[server] listening on {args.host}:{port} group={suite.group} "
          f"sig={sig_alg}", file=sys.stderr)

    try:
        # Read the framed message: header first (to learn ct length), then body.
        header = _read_exact(proc.stdout, HEADER_LEN)
        seq, ct_len = parse_header(header)
        body = _read_exact(proc.stdout, ct_len + TAG_LEN)
        wire = header + body

        plaintext, parts = open_frame(wire, key, nonce_seed)

        emitter.emit("aead_decrypt", "aead_ciphertext",
                     artifact_bytes=parts.ciphertext, algorithm=suite.app_aead,
                     human_readable=hex_preview(parts.ciphertext))
        emitter.emit("aead_decrypt", "plaintext",
                     artifact_bytes=plaintext, algorithm=suite.app_aead,
                     human_readable=plaintext.decode("utf-8", "replace"))
        emitter.emit("verify", "aead_tag",
                     artifact_bytes=parts.tag, algorithm=suite.app_aead,
                     human_readable="tag verified OK (GCM authentication passed)")
        print(f"[server] received message seq={seq}: "
              f"{plaintext.decode('utf-8', 'replace')!r}", file=sys.stderr)
        return 0
    except Exception as e:  # noqa: BLE001 — surface any failure clearly at the demo table
        emitter.emit("verify", "error",
                     human_readable=f"FAILED: {e}", note="decrypt/verify error")
        print(f"[server] ERROR: {e}", file=sys.stderr)
        err = proc.stderr.read().decode("utf-8", "replace") if proc.stderr else ""
        if err:
            print(f"[server] s_server stderr:\n{err}", file=sys.stderr)
        return 1
    finally:
        proc.terminate()
        emitter.close()


if __name__ == "__main__":
    raise SystemExit(main())
