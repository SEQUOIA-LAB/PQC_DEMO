"""Phase 2: handshake artifact capture.

Pulls REAL handshake artifacts from the pinned OpenSSL via:
  - `s_client -trace`         : key_share sizes (ML-KEM enc key + ciphertext),
                                CertificateVerify (ML-DSA-65 signature) length,
                                negotiated group.
  - SSLKEYLOGFILE             : the TLS 1.3 secrets, shown as a fingerprint
                                (the derived shared secret is NOT directly
                                extractable — PROJECT_PLAN.md §13 — so we render
                                a SHA-256 fingerprint of the keylog secret).
  - the server certificate    : the actual ML-DSA-65 signature bytes on the cert.

Output: schema events (protocol/events.schema.json), stages keygen / encapsulate
/ derive_secret / sign_transcript / verify_signature.
"""
