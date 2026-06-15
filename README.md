# PQC-TLS Demo

A demonstrable, expert-credible post-quantum TLS system: two roles complete a real
**`X25519MLKEM768`** + **`ML-DSA-65`** TLS 1.3 handshake, an operator sends a typed
message through the channel with fully-instrumented AEAD, and a single dashboard
visualizes every stage with stepped, capture-then-replay playback.

See [PROJECT_PLAN.md](PROJECT_PLAN.md) for the design and [CLAUDE.md](CLAUDE.md)
for the operating rules.

## Status

| Phase | What | State |
|---|---|---|
| 0 | Foundations: `protocol/`, pinned OpenSSL build, vanilla PQC handshake | ✅ done & verified on Mac |
| 1 | Custom message: `app/` AEAD frame + roles + dashboard | ✅ working end-to-end |
| 2 | Handshake capture (`capture/`) | ✅ real artifacts captured |
| 3 | Stepped replay (`replay/`) | ✅ CLI + dashboard API |
| 4 | Metrics (PQC vs classical) | ⏳ run on the Pi (Cortex-A72) |
| 5 | Dashboard polish + deploy to Pis | ⏳ `deploy/` scaffolded, run on hardware |

## Quick start (Mac or Linux/arm64)

```bash
# 1) Build the pinned OpenSSL 3.5.7 (native ML-KEM/ML-DSA). Takes a few minutes.
crypto/setup-openssl.sh
export PQC_OPENSSL="$HOME/opt/openssl-3.5/bin/openssl"

# 2) Python env (pinned deps).
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

# 3) Generate the ML-DSA-65 CA + server cert.
.venv/bin/python -m app.gen_certs

# 4) Run the full Phase-1 demo (real PQC-TLS, two local processes).
.venv/bin/python run_demo.py --message "hello quantum world"

# 5) Capture real handshake artifacts (Phase 2).
.venv/bin/python -m capture.handshake --events-file runs/handshake.jsonl

# 6) Stepped replay in the terminal (Phase 3).
.venv/bin/python -m replay.engine --step

# 7) The dashboard (message input + steps + metrics): http://127.0.0.1:8080
.venv/bin/python -m dashboard.server
```

## Validate the Linux path before the Pi

```bash
docker build --platform linux/arm64 -f docker/Dockerfile.pi-proxy -t pqc-pi-proxy .
docker run --rm -it --platform linux/arm64 -v "$PWD":/work -w /work pqc-pi-proxy bash
#  inside:  crypto/setup-openssl.sh && python3 -m venv .venv && ...
```

## Deploy to the Pis

Repo is canonical on the Mac → push to a git remote → on each Pi run
`deploy/deploy.sh server` / `deploy/deploy.sh client`, apply the netplan files in
`deploy/`, and run the roles over the direct ethernet link (10.0.0.1 ↔ 10.0.0.2).

## Pinned versions
- OpenSSL **3.5.7** (latest 3.5.x LTS, verified 2026-06-15)
- Python: `cryptography==44.0.0`, `jsonschema==4.23.0`
