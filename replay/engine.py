"""Build a human-paced, ordered replay timeline from captured/app events.

Input: a list of schema events (from runs/handshake.jsonl + runs/events.jsonl).
Output: a timeline — events grouped and ordered by the canonical stage flow, each
annotated with a short explanation for the demo narration. Pure data transform;
the dashboard (or the CLI player below) drives the pacing.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

# Canonical stage flow for the demo narrative (handshake first, then message).
STAGE_FLOW = [
    "keygen", "encapsulate", "derive_secret",
    "sign_transcript", "verify_signature",
    "aead_encrypt", "transmit", "aead_decrypt", "verify",
]
STAGE_RANK = {s: i for i, s in enumerate(STAGE_FLOW)}

# One-line narration per stage for the operator at the demo table.
STAGE_BLURB = {
    "keygen": "Client generates its hybrid key share (X25519 + ML-KEM-768).",
    "encapsulate": "Server encapsulates a shared secret against the client's ML-KEM key.",
    "derive_secret": "Both sides derive the same TLS secret (shown as a fingerprint — not extractable).",
    "sign_transcript": "Server signs the handshake transcript with its ML-DSA-65 key.",
    "verify_signature": "Client verifies the ML-DSA-65 signature — the server is authenticated.",
    "aead_encrypt": "Operator's plaintext is AEAD-sealed (AES-256-GCM) into ciphertext + tag.",
    "transmit": "The framed message crosses the wire inside the PQC-TLS channel.",
    "aead_decrypt": "Server decrypts the ciphertext back to the plaintext.",
    "verify": "Server verifies the GCM tag — the message is authentic and intact.",
}


def build_timeline(events: list[dict]) -> list[dict]:
    """Order events by stage flow then sequence, attach narration."""
    def sort_key(ev: dict):
        return (STAGE_RANK.get(ev.get("stage"), 99), ev.get("seq", 0))

    ordered = sorted(events, key=sort_key)
    timeline = []
    for i, ev in enumerate(ordered):
        timeline.append({
            "step": i + 1,
            "stage": ev.get("stage"),
            "side": ev.get("side"),
            "artifact_type": ev.get("artifact_type"),
            "algorithm": ev.get("algorithm"),
            "size_bytes": ev.get("size_bytes"),
            "human_readable": ev.get("human_readable"),
            "artifact_bytes_b64": ev.get("artifact_bytes_b64"),
            "note": ev.get("note"),
            "narration": STAGE_BLURB.get(ev.get("stage"), ""),
        })
    return timeline


def _load(paths: list[Path]) -> list[dict]:
    events: list[dict] = []
    for p in paths:
        if p.exists():
            for ln in p.read_text().splitlines():
                if ln.strip():
                    events.append(json.loads(ln))
    return events


def play_cli(timeline: list[dict], pace: float, step: bool) -> None:
    """Play the timeline to the terminal at human pace, or one --step at a time."""
    for item in timeline:
        bar = "─" * 60
        print(f"\n{bar}")
        print(f"STEP {item['step']:>2}  [{item['stage']}]  ({item['side']})")
        print(f"  {item['narration']}")
        if item["human_readable"]:
            print(f"  → {item['human_readable']}")
        meta = f"  {item['algorithm'] or ''}  {item['size_bytes']} bytes"
        if item["note"]:
            meta += f"\n  note: {item['note']}"
        print(meta)
        if step:
            try:
                input("  [enter to step] ")
            except EOFError:
                pass
        else:
            time.sleep(pace)
    print(f"\n{'─'*60}\nreplay complete — {len(timeline)} steps.\n")


if __name__ == "__main__":
    repo = Path(__file__).resolve().parent.parent
    ap = argparse.ArgumentParser(description="Stepped replay of captured PQC-TLS artifacts")
    ap.add_argument("--events", nargs="*", default=[
        str(repo / "runs" / "handshake.jsonl"),
        str(repo / "runs" / "events.jsonl"),
    ], help="event JSONL files to replay (default: handshake + message events)")
    ap.add_argument("--pace", type=float, default=1.5, help="seconds per step")
    ap.add_argument("--step", action="store_true", help="manual step (press enter)")
    ap.add_argument("--json", action="store_true", help="print timeline as JSON and exit")
    a = ap.parse_args()

    events = _load([Path(p) for p in a.events])
    if not events:
        print("[replay] no events found — run run_demo.py and capture.handshake first",
              file=sys.stderr)
        raise SystemExit(1)
    timeline = build_timeline(events)
    if a.json:
        print(json.dumps(timeline, indent=2))
    else:
        play_cli(timeline, a.pace, a.step)
