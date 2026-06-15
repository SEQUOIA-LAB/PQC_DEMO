# App-layer custom-message frame

This spec defines the framing for an **operator-supplied plaintext message** sent
*after* the PQC-TLS 1.3 handshake has established a channel. It is **our** code
(not OpenSSL's), which makes it the high-value, fully-observable instrumentation
surface for the stepped demo (PROJECT_PLAN.md §7, §10 Phase 1).

The message rides *inside* the already-established TLS 1.3 channel. The TLS record
layer is itself AEAD-protected (`TLS_AES_256_GCM_SHA384`). On top of that, we add
**our own** AEAD layer so we can capture `plaintext → ciphertext+tag → on-wire
bytes → decrypted plaintext` with real intermediate artifacts. The app-layer key
is derived from the TLS channel via the keying-material exporter (RFC 8446 §7.5),
so both ends agree without a second handshake.

## Key derivation

Both ends call the TLS keying-material exporter on the live connection:

```
key (32 bytes)   = TLS-Exporter("pqc-demo app aead key",   context=b"",            length=32)
nonce_seed (12B) = TLS-Exporter("pqc-demo app aead nonce", context=b"",            length=12)
```

The 96-bit GCM nonce for message N is `nonce_seed XOR le64(N)` (counter in the low
8 bytes), guaranteeing uniqueness per (key, nonce) without transmitting nonces.

> Python note: `ssl.SSLSocket` does not expose the RFC 8446 exporter directly.
> The app derives the key from a stable, channel-bound value instead — see
> `app/aead.py` `derive_app_key()` — and documents the exact input there. The
> contract above is the intended/spec form; the implementation note records the
> concrete substitute so the two ends stay byte-identical.

## Wire frame (big-endian)

```
 0               1               2               3
 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| MAGIC = 0x50 0x51 0x44 0x4D ("PQDM")                          |
+---------------+-----------------------------------------------+
| VERSION = 1   | (reserved = 0)                                |
+---------------+-----------------------------------------------+
| SEQ (uint64, big-endian)                                      |
+--------------------------------------------------------------+
| CIPHERTEXT_LEN (uint32, big-endian)                          |
+--------------------------------------------------------------+
| CIPHERTEXT  (CIPHERTEXT_LEN bytes)                           |
+--------------------------------------------------------------+
| TAG (16 bytes, AES-256-GCM authentication tag)              |
+--------------------------------------------------------------+
```

Field summary:

| Field          | Size      | Notes                                                  |
|----------------|-----------|--------------------------------------------------------|
| MAGIC          | 4 bytes   | `b"PQDM"` — reject frame if mismatch                   |
| VERSION        | 1 byte    | `0x01`                                                 |
| reserved       | 3 bytes   | zero                                                   |
| SEQ            | 8 bytes   | message counter, drives the GCM nonce                  |
| CIPHERTEXT_LEN | 4 bytes   | length of ciphertext (excludes tag)                    |
| CIPHERTEXT     | variable  | AES-256-GCM ciphertext of the UTF-8 plaintext          |
| TAG            | 16 bytes  | GCM tag                                                |

**AAD (additional authenticated data):** the 20-byte header (MAGIC..CIPHERTEXT_LEN)
is fed as AEAD associated data, so tampering with SEQ/length is detected.

## Stage events emitted (per protocol/events.schema.json)

Sender (client by default):
1. `aead_encrypt` — `artifact_type="plaintext"` then `"aead_ciphertext"`, `"aead_tag"`.
2. `transmit` — `artifact_type="wire_frame"`, the full framed bytes.

Receiver (server):
3. `aead_decrypt` — `artifact_type="aead_ciphertext"` in, `"plaintext"` out.
4. `verify` — tag verification result.

Each carries `algorithm="AES-256-GCM"` and the real bytes (base64) so the
dashboard shows the actual transformation, not a mock.
