"""PQC-TLS demo application layer.

Modules:
  config    — loads protocol/suite.conf (the shared wire contract).
  events    — emits schema-conformant events to the dashboard.
  aead      — app-layer AES-256-GCM frame (protocol/message_format.md).
  gen_certs — generates an ML-DSA-65 CA + server certificate via OpenSSL.
"""
