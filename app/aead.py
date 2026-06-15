"""App-layer AES-256-GCM frame for the operator's custom message.

Implements protocol/message_format.md. This is OUR code (not OpenSSL's), which
makes it the fully-observable instrumentation surface for the Phase 1 stepped
demo (PROJECT_PLAN.md §10). It rides INSIDE the established PQC-TLS 1.3 channel;
this AEAD layer exists so we can capture the real plaintext -> ciphertext+tag ->
wire-bytes -> plaintext transformation.

Uses the Python stdlib only where possible; AES-GCM comes from the `cryptography`
package (pinned in requirements.txt) — it is FIPS-standard AES-256-GCM, the same
primitive as the TLS record AEAD.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"PQDM"
VERSION = 1
HEADER_FMT = ">4sB3sQI"          # MAGIC, VERSION, reserved(3), SEQ(u64), CT_LEN(u32)
HEADER_LEN = struct.calcsize(HEADER_FMT)   # = 20 bytes
TAG_LEN = 16


def derive_app_key(channel_binding: bytes) -> tuple[bytes, bytes]:
    """Derive (key32, nonce_seed12) from a value bound to the TLS channel.

    The spec form (protocol/message_format.md) is the RFC 8446 keying-material
    exporter. The pinned-OpenSSL CLI path we drive does not surface the exporter
    to Python, so both ends instead HKDF-derive from a shared channel-bound
    value (the TLS session's negotiated parameters + a shared transcript salt).
    The single input is documented here so the two ends stay byte-identical:
    whatever bytes both roles agree on go in, the same key/nonce come out.
    """
    hk = HKDF(algorithm=hashes.SHA256(), length=32 + 12,
              salt=b"pqc-demo/v1", info=b"app-aead-key+nonce")
    out = hk.derive(channel_binding)
    return out[:32], out[32:44]


@dataclass
class FrameParts:
    """Intermediate artifacts of one encrypt, for the dashboard."""
    plaintext: bytes
    aad: bytes
    nonce: bytes
    ciphertext: bytes
    tag: bytes
    wire: bytes


def _nonce_for(seq: int, nonce_seed: bytes) -> bytes:
    # 96-bit GCM nonce = nonce_seed XOR le64(seq) in the low 8 bytes.
    ctr = struct.pack("<Q", seq) + b"\x00\x00\x00\x00"
    return bytes(a ^ b for a, b in zip(nonce_seed, ctr))


def seal(plaintext: bytes, seq: int, key: bytes, nonce_seed: bytes) -> FrameParts:
    """Encrypt + frame one message. `cryptography`'s AESGCM returns ct||tag."""
    nonce = _nonce_for(seq, nonce_seed)
    aad = struct.pack(HEADER_FMT, MAGIC, VERSION, b"\x00\x00\x00", seq, 0)
    # We don't yet know ct length for the header, so build a provisional aad with
    # ct_len, recompute. Encrypt first to learn the length.
    ct_and_tag = AESGCM(key).encrypt(nonce, plaintext, None)  # AAD set below
    ciphertext, tag = ct_and_tag[:-TAG_LEN], ct_and_tag[-TAG_LEN:]
    header = struct.pack(HEADER_FMT, MAGIC, VERSION, b"\x00\x00\x00", seq, len(ciphertext))
    # Re-encrypt binding the real header as AAD (so SEQ/len are authenticated).
    ct_and_tag = AESGCM(key).encrypt(nonce, plaintext, header)
    ciphertext, tag = ct_and_tag[:-TAG_LEN], ct_and_tag[-TAG_LEN:]
    wire = header + ciphertext + tag
    return FrameParts(plaintext=plaintext, aad=header, nonce=nonce,
                      ciphertext=ciphertext, tag=tag, wire=wire)


def parse_header(wire: bytes) -> tuple[int, int]:
    """Validate magic/version, return (seq, ct_len)."""
    if len(wire) < HEADER_LEN:
        raise ValueError("frame shorter than header")
    magic, version, _resv, seq, ct_len = struct.unpack(HEADER_FMT, wire[:HEADER_LEN])
    if magic != MAGIC:
        raise ValueError(f"bad magic {magic!r}")
    if version != VERSION:
        raise ValueError(f"unsupported version {version}")
    return seq, ct_len


def open_frame(wire: bytes, key: bytes, nonce_seed: bytes) -> tuple[bytes, FrameParts]:
    """Verify + decrypt one framed message. Raises on tag mismatch."""
    seq, ct_len = parse_header(wire)
    header = wire[:HEADER_LEN]
    ciphertext = wire[HEADER_LEN:HEADER_LEN + ct_len]
    tag = wire[HEADER_LEN + ct_len:HEADER_LEN + ct_len + TAG_LEN]
    nonce = _nonce_for(seq, nonce_seed)
    plaintext = AESGCM(key).decrypt(nonce, ciphertext + tag, header)  # raises if tag bad
    parts = FrameParts(plaintext=plaintext, aad=header, nonce=nonce,
                       ciphertext=ciphertext, tag=tag, wire=wire)
    return plaintext, parts
