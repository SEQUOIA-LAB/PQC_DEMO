"""Phase 4: metrics — PQC vs classical, measured on real hardware.

Measure on the Pi (Cortex-A72), NOT the Mac/x86 — the A72 numbers are the whole
point and won't match (PROJECT_PLAN.md §4 Phase 4, §10). This package drives the
pinned OpenSSL to compare:
  - the PQC suite      : X25519MLKEM768 group + ML-DSA-65 certificate,
  - a classical suite  : X25519 group + ECDSA P-256 certificate,
on three axes: handshake latency, handshake throughput (connections/sec), and
the underlying primitive speeds (KEM + signature).

Output: runs/metrics.json, consumed by the dashboard (/api/metrics).
"""
