"""Emit dashboard events conforming to protocol/events.schema.json.

Every stage rendered by the dashboard is one event with a fixed shape. Both
roles use this. Events are written as JSON Lines (one JSON object per line) to a
sink: stdout, a file, or both (PROJECT_PLAN.md §4.6, §7).
"""
from __future__ import annotations

import base64
import json
import sys
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional, TextIO

# Allowed stages/sides — mirror protocol/events.schema.json. Validated on emit
# so a typo fails loud rather than silently producing an off-contract event.
VALID_STAGES = {
    "keygen", "encapsulate", "derive_secret", "sign_transcript",
    "verify_signature", "aead_encrypt", "transmit", "aead_decrypt", "verify",
}
VALID_SIDES = {"server", "client"}

_seq_lock = threading.Lock()
_seq_counter = 0


def _next_seq() -> int:
    global _seq_counter
    with _seq_lock:
        _seq_counter += 1
        return _seq_counter


@dataclass
class Event:
    stage: str
    side: str
    timestamp: float
    artifact_type: str
    size_bytes: int
    artifact_bytes_b64: Optional[str] = None
    human_readable: Optional[str] = None
    algorithm: Optional[str] = None
    seq: Optional[int] = None
    note: Optional[str] = None

    def to_json(self) -> str:
        return json.dumps(asdict(self), separators=(",", ":"))


class EventEmitter:
    """Writes events as JSON Lines to stdout and/or a file."""

    def __init__(
        self,
        side: str,
        *,
        to_stdout: bool = True,
        file_path: Optional[Path | str] = None,
    ) -> None:
        if side not in VALID_SIDES:
            raise ValueError(f"side must be one of {VALID_SIDES}, got {side!r}")
        self.side = side
        self._to_stdout = to_stdout
        self._fh: Optional[TextIO] = None
        if file_path is not None:
            p = Path(file_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            self._fh = open(p, "a", buffering=1)  # line-buffered
        self._lock = threading.Lock()

    def emit(
        self,
        stage: str,
        artifact_type: str,
        *,
        artifact_bytes: Optional[bytes] = None,
        human_readable: Optional[str] = None,
        algorithm: Optional[str] = None,
        size_bytes: Optional[int] = None,
        note: Optional[str] = None,
    ) -> Event:
        if stage not in VALID_STAGES:
            raise ValueError(f"stage must be one of {VALID_STAGES}, got {stage!r}")

        b64 = base64.b64encode(artifact_bytes).decode() if artifact_bytes is not None else None
        if size_bytes is None:
            size_bytes = len(artifact_bytes) if artifact_bytes is not None else 0

        ev = Event(
            stage=stage,
            side=self.side,
            timestamp=time.time(),
            artifact_type=artifact_type,
            size_bytes=size_bytes,
            artifact_bytes_b64=b64,
            human_readable=human_readable,
            algorithm=algorithm,
            seq=_next_seq(),
            note=note,
        )
        line = ev.to_json()
        with self._lock:
            if self._to_stdout:
                sys.stdout.write(line + "\n")
                sys.stdout.flush()
            if self._fh is not None:
                self._fh.write(line + "\n")
        return ev

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None


def hex_preview(data: bytes, head: int = 16) -> str:
    """Short hex preview for human_readable fields, e.g. '3a1f...(512 bytes)'."""
    if len(data) <= head:
        return data.hex()
    return f"{data[:head].hex()}…({len(data)} bytes)"
