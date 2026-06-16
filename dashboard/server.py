"""Single dashboard (PROJECT_PLAN.md §4.6: one dashboard, not two).

Stdlib-only HTTP server (no extra deps) that:
  - serves dashboard/index.html (custom-message input + stepped view + metrics),
  - POST /api/run  -> runs run_demo.py with the operator's message,
  - GET  /api/events -> returns runs/events.jsonl as a JSON array,
  - GET  /api/replay -> returns the replay timeline (replay/ engine),
  - GET  /api/metrics -> returns runs/metrics.json if present (Phase 4, on Pi).

Run:
    .venv/bin/python -m dashboard.server  # http://127.0.0.1:8080
"""
from __future__ import annotations

import json
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

REPO_ROOT = Path(__file__).resolve().parent.parent
RUNS = REPO_ROOT / "runs"
INDEX = Path(__file__).resolve().parent / "index.html"


def _events() -> list[dict]:
    # Merge captured handshake artifacts (handshake.jsonl) with the message
    # stages (events.jsonl) so the dashboard shows the full PQC story in one
    # flow: real ML-KEM key shares + ML-DSA-65 signature, then the message.
    out: list[dict] = []
    for name in ("handshake.jsonl", "events.jsonl"):
        f = RUNS / name
        if f.exists():
            out += [json.loads(ln) for ln in f.read_text().splitlines() if ln.strip()]
    return out


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quieter
        pass

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code: int = 200) -> None:
        self._send(code, json.dumps(obj).encode(), "application/json")

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            self._send(200, INDEX.read_bytes(), "text/html; charset=utf-8")
        elif path == "/api/events":
            self._json(_events())
        elif path == "/api/replay":
            try:
                from replay.engine import build_timeline
                self._json(build_timeline(_events()))
            except Exception as e:  # noqa: BLE001
                self._json({"error": str(e)}, 500)
        elif path == "/api/metrics":
            f = RUNS / "metrics.json"
            self._json(json.loads(f.read_text()) if f.exists() else {"note": "no metrics yet (run on Pi, Phase 4)"})
        elif path == "/api/algorithms":
            from app.algorithms import (active_sig_algs, DEFAULT_SIG,
                                        KEM_GROUPS, DEFAULT_GROUP)
            self._json({
                "default": DEFAULT_SIG,
                "signature_algorithms": [
                    {"id": a.id, "label": a.label, "fips": a.fips,
                     "kind": a.kind, "note": a.note, "legacy": a.legacy}
                    for a in active_sig_algs()],
                "default_group": DEFAULT_GROUP,
                "kem_groups": [
                    {"id": g.id, "label": g.label, "fips": g.fips,
                     "kind": g.kind, "note": g.note, "legacy": g.legacy}
                    for g in KEM_GROUPS],
            })
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path != "/api/run":
            self._json({"error": "not found"}, 404)
            return
        length = int(self.headers.get("Content-Length", 0))
        payload = json.loads(self.rfile.read(length) or b"{}")
        message = str(payload.get("message", "hello quantum world"))
        sig_alg = payload.get("sig_alg")  # optional; None -> suite default
        group = payload.get("group")      # optional; None -> suite default

        # Validate requested algorithm + group against the registries (fail clearly).
        sig_args: list[str] = []
        if sig_alg:
            from app.algorithms import all_ids
            if sig_alg not in all_ids():
                self._json({"error": f"unknown signature algorithm {sig_alg!r}"}, 400)
                return
            sig_args += ["--sig-alg", sig_alg]
        if group:
            from app.algorithms import all_group_ids
            if group not in all_group_ids():
                self._json({"error": f"unknown KEM group {group!r}"}, 400)
                return
            sig_args += ["--group", group]

        # First capture a real handshake's artifacts (key shares + the chosen
        # signature), then run the instrumented message through the channel, so
        # the dashboard renders both the handshake story AND the message.
        cap = subprocess.run(
            [sys.executable, "-m", "capture.handshake",
             "--port", "14533", "--events-file", "runs/handshake.jsonl", *sig_args],
            cwd=REPO_ROOT, capture_output=True, text=True,
        )
        proc = subprocess.run(
            [sys.executable, "run_demo.py", "--message", message, *sig_args],
            cwd=REPO_ROOT, capture_output=True, text=True,
        )
        self._json({
            "returncode": proc.returncode,
            "capture_rc": cap.returncode,
            "sig_alg": sig_alg or "ML-DSA-65",
            "group": group or "X25519MLKEM768",
            "stdout_tail": proc.stdout.splitlines()[-6:],
            "events": _events(),
        })


def main() -> int:
    import argparse
    import threading
    import webbrowser

    ap = argparse.ArgumentParser(description="PQC-TLS demo dashboard")
    ap.add_argument("--host", default="127.0.0.1",
                    help="bind address; use 0.0.0.0 to reach it from another box on the link")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--open", action="store_true",
                    help="open the dashboard in a browser once it is up")
    ap.add_argument("--open-url", default=None,
                    help="URL to open (defaults to http://127.0.0.1:<port>; set when bound to 0.0.0.0)")
    a = ap.parse_args()

    httpd = ThreadingHTTPServer((a.host, a.port), Handler)
    shown_host = "127.0.0.1" if a.host == "0.0.0.0" else a.host
    url = a.open_url or f"http://{shown_host}:{a.port}"
    print(f"[dashboard] serving on http://{a.host}:{a.port}  -> open {url}  (Ctrl-C to stop)")

    if a.open:
        # Open after a short delay so the server is accepting first.
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[dashboard] stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
