# CLAUDE.md — agent operating rules

Derived from `PROJECT_PLAN.md`. Read the plan for the full rationale; this is the
quick operating contract for working in this repo.

## What this is
A post-quantum TLS demo: two roles (server/client) complete a real
`X25519MLKEM768` + `ML-DSA-65` TLS 1.3 handshake, send an operator-typed message
through the channel with fully-instrumented AEAD, and visualize every stage on a
single dashboard with stepped replay.

## Hard rules (do not violate)
1. **FIPS names only.** `X25519MLKEM768`, `ML-KEM-768`, `ML-DSA-65`, `SLH-DSA`.
   Never Kyber / Dilithium / SPHINCS+ — in code, labels, UI, or commits.
2. **`protocol/` is the single source of truth.** `suite.conf` (crypto params),
   `events.schema.json` (event shape — locked), `message_format.md` (app frame).
   Both roles read these; never let a role define crypto independently.
3. **We don't implement crypto.** OpenSSL 3.5.x (pinned, built from source) does
   ML-KEM/ML-DSA. We configure it, capture what it did, and write the app-layer
   message wrapper on top.
4. **Build crypto from pinned source per machine.** Never copy compiled binaries
   between Mac/container/Pi. Same tag (`openssl-3.5.7`) → identical behavior.
5. **No fabricated handshake animation.** Capture-then-replay only (`capture/` →
   `replay/`). The handshake is milliseconds; we record real artifacts and
   replay them at human pace.
6. **One dashboard.** Both roles emit schema events to it.
7. **Test the Linux path in the Pi-proxy container** before deploying to a Pi.

## Pinned versions (verified 2026-06-15)
- OpenSSL **3.5.7** (latest 3.5.x LTS) — `crypto/setup-openssl.sh`.
- Python deps in `requirements.txt` (cryptography 44.0.0, jsonschema 4.23.0).

## Layout
- `protocol/` — the wire contract (see above).
- `crypto/setup-openssl.sh` — pinned source build (Mac + Linux/arm64). Installs
  to `~/opt/openssl-3.5`. `crypto/openssl.cnf` is the minimal config the CLI
  needs (install_sw ships no default cnf).
- `app/` — config loader, schema events, AES-256-GCM frame, cert generation,
  the TLS-pipe helper that drives the pinned `s_server`/`s_client`.
- `server/`, `client/` — the two role entrypoints (`python -m server|client`).
- `capture/` — real handshake artifact capture via `s_client -trace` + keylog.
- `replay/` — stepped replay engine (CLI + dashboard API).
- `dashboard/` — single stdlib HTTP dashboard (message input + steps + metrics).
- `deploy/` — netplan files + `deploy.sh` (git-pull deploy to a Pi).
- `docker/Dockerfile.pi-proxy` — arm64 ubuntu:23.10 Pi userland proxy.

## Common commands (from repo root)
```bash
export PQC_OPENSSL="$HOME/opt/openssl-3.5/bin/openssl"   # use the pinned build
crypto/setup-openssl.sh                                  # build OpenSSL (once)
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python -m app.gen_certs                        # ML-DSA-65 certs
.venv/bin/python run_demo.py --message "hello quantum world"   # Phase 1 e2e
.venv/bin/python -m capture.handshake --events-file runs/handshake.jsonl
.venv/bin/python -m replay.engine --step                 # stepped replay (CLI)
.venv/bin/python -m dashboard.server                     # http://127.0.0.1:8080
```

## Status (built so far)
- Phases 0–3 implemented and verified on the Mac. Phase 4 (metrics on the Pi) and
  Phase 5 (deploy + rehearse on hardware) require the two Pis — scaffolded in
  `deploy/`, run on hardware.

## Known constraints
- The TLS **derived secret is not byte-extractable**; `capture/` shows a SHA-256
  fingerprint of the SSLKEYLOGFILE secret material (PROJECT_PLAN.md §13), and the
  schema/event for it carries a `note` saying so. Never invent secret bytes.
- `SSLKEYLOGFILE` requires `enable-sslkeylog` in the OpenSSL build (now in
  `setup-openssl.sh`). `capture/` degrades gracefully if the keylog is empty.
- Ubuntu 23.10 is EOL; the Pi-proxy Dockerfile repoints apt at
  `old-releases.ubuntu.com`. Recommend 24.04 LTS to Ben if reinstalling.
