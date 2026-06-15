# PQC-TLS Demo — Master Build Plan

**Audience:** the coding agent (Claude Code) building this project.
**Author of record:** Ben Dong (UC Merced EECS).
**Status:** living document. Update the "Verify at build time" section as facts are confirmed.

---

## 1. Goal

Build a demonstrable, expert-credible post-quantum TLS system on two Raspberry Pis:

1. A **PQC-TLS channel** between two Pis (one server, one client) using NIST-standardized algorithms.
2. An **interactive walkthrough**: an operator types a custom plaintext message; the system visualizes each transformation it undergoes (key generation → encapsulation → signature/verification → symmetric encryption → transmission → decryption), exposing the intermediate artifacts at every stage.
3. **Live metrics**: handshake latency, throughput, connections/sec — PQC vs. classical, on real Cortex-A72 hardware.

This must withstand scrutiny from PQC experts at a demo table. Algorithm labels and protocol claims must be accurate.

---

## 2. Algorithms (use these exact names)

| Role | Algorithm | Standard | Notes |
|---|---|---|---|
| Key exchange (hybrid) | `X25519MLKEM768` | FIPS 203 + RFC | OpenSSL 3.5 default TLS group |
| KEM (standalone) | `ML-KEM-768` | FIPS 203 | formerly Kyber-768 |
| Signature | `ML-DSA-65` | FIPS 204 | formerly Dilithium |
| Signature (alt / hash-based) | `SLH-DSA` | FIPS 205 | formerly SPHINCS+ |
| Signature (optional) | `FALCON` / FN-DSA | FIPS 206 (draft) | **needs liboqs**, not native — only if explicitly requested |

Do **not** use the legacy names (Kyber/Dilithium/SPHINCS+) in code, labels, or UI. Use the FIPS names above.

---

## 3. Environment

**Dev machine:** Apple M1 Max (macOS, `arm64`/aarch64).
**Targets:** 2× Raspberry Pi 4 (Cortex-A72, `arm64`), Ubuntu 23.10.

> ⚠️ **Ubuntu 23.10 is past end-of-support.** `apt` may need `old-releases.ubuntu.com` mirrors, and some packages may be unavailable. Flag this to Ben early. Recommend 24.04 LTS if a reinstall is acceptable; otherwise proceed on 23.10 and pin everything we build from source (which we're doing anyway).

**Key architectural fact:** M1 Mac and the Pi are *both* `arm64`. Same word size, endianness, alignment. This does **not** mean binaries are portable (macOS Mach-O ≠ Linux ELF, different libc), but it means a Docker `arm64` Linux container on the Mac is a faithful proxy for the Pi's runtime. Use that.

---

## 4. Architecture principles (do not violate)

1. **One repo, two roles.** There is no "master program driving both Pis." There is a single codebase with `server` and `client` entrypoints. Each Pi runs the same code, different role. They are symmetric.
2. **Single source of truth for the wire contract.** The two ends must agree byte-for-byte (cipher suite, key share, message framing, AEAD). One file owns this. Never let the two roles define it independently — TLS fails closed on any mismatch.
3. **Build crypto from pinned source on each machine.** Never copy a compiled OpenSSL between machines. Same git tag → identical behavior on Mac, container, and Pi.
4. **Real crypto is OpenSSL's job, not ours.** We do not implement ML-KEM/ML-DSA. We (a) configure OpenSSL, (b) instrument it to capture what happened, (c) write the app-layer message wrapper on top of the established channel.
5. **The handshake is too fast to "watch live."** It completes in milliseconds. The stepped view is **capture-then-replay**: record real artifacts, then replay at human speed with pause-per-stage. Don't pretend to animate a live handshake.
6. **One dashboard, not two.** A single visualization shows the message crossing both ends. Both Pis emit structured JSON events to it.

---

## 5. Crypto stack decision

**Baseline: OpenSSL 3.5 LTS, built from source. No liboqs, no oqs-provider** for the core demo.

Rationale: OpenSSL 3.5 has native `ML-KEM`, `ML-DSA`, `SLH-DSA`, and ships `X25519MLKEM768` as a default TLS 1.3 group. This covers the entire core algorithm set with `s_server`/`s_client` and the EVP APIs. Adding liboqs would be redundant complexity.

Only add **liboqs + oqs-provider** if Ben explicitly wants FALCON in the demo. Keep it behind an optional build flag so the default path stays lean.

> Verify the exact current OpenSSL version at build time (3.5 LTS is the stable target; 3.6 also exists). Prefer the latest 3.5.x LTS patch release for a reproducible, supported demo unless Ben says otherwise.

---

## 6. Repo structure

```
pqc-tls-demo/
├── PROJECT_PLAN.md          # this file
├── CLAUDE.md                # agent operating rules (derived from this)
├── protocol/                # THE SHARED CONTRACT — single source of truth
│   ├── suite.conf           # cipher suite, groups, sig algs (both ends read this)
│   ├── events.schema.json   # JSON schema for every event emitted to the dashboard
│   └── message_format.md    # app-layer custom-message framing spec
├── crypto/
│   └── setup-openssl.sh     # pinned OpenSSL 3.5.x source build (Mac + Linux)
├── server/                  # TLS server role (runs on Pi-A)
├── client/                  # TLS client role (runs on Pi-B)
├── app/                     # app-layer custom-message send/receive + AEAD instrumentation
├── capture/                 # handshake artifact capture (SSLKEYLOGFILE, msg callback, s_client -trace)
├── replay/                  # stepped replay engine (reads captured artifacts)
├── dashboard/               # single visualization (hosts custom-message input + step view + metrics)
├── deploy/
│   ├── netplan-server.yaml
│   ├── netplan-client.yaml
│   └── deploy.sh            # git-pull based deploy to a Pi
└── docker/
    └── Dockerfile.pi-proxy  # arm64 ubuntu:23.10 image mirroring the Pi, for local testing
```

---

## 7. The shared wire contract

Before writing any role code, define `protocol/`:

- **`suite.conf`** — the TLS group (`X25519MLKEM768`), signature algorithm (`ML-DSA-65`), TLS version (1.3), and certificate setup. Both server and client load this. Changing crypto = editing this one file.
- **`events.schema.json`** — every stage the dashboard renders is an event with a fixed shape: `{stage, side, timestamp, artifact_type, artifact_bytes_b64, human_readable, size_bytes}`. Stages: `keygen`, `encapsulate`, `derive_secret`, `sign_transcript`, `verify_signature`, `aead_encrypt`, `transmit`, `aead_decrypt`, `verify`. Lock this schema early; everything downstream depends on it.
- **`message_format.md`** — the app-layer frame for the custom message *after* the handshake: header + AEAD ciphertext + tag. This is our code, so it's the easy, high-value instrumentation surface.

---

## 8. Networking (Ubuntu / netplan)

Two planes:
- **Management plane:** WiFi on each Pi → internet, SSH, dev access. Leave as configured.
- **Demo plane:** a direct ethernet cable between the two Pis, static IPs, no gateway. All PQC-TLS traffic rides this. Pi 4 has auto-MDIX so a straight-through cable works Pi-to-Pi.

First, confirm the wired interface name on each Pi — Ubuntu on Pi is usually `eth0` but verify:
```bash
ip link
```

`deploy/netplan-server.yaml` (Pi-A, the server):
```yaml
network:
  version: 2
  renderer: networkd        # Ubuntu Server. Use NetworkManager if Desktop (check: nmcli -v)
  ethernets:
    eth0:                   # replace with verified interface name
      dhcp4: no
      addresses: [10.0.0.1/24]
      # intentionally no gateway/routes — this link is point-to-point
```

`deploy/netplan-client.yaml` (Pi-B, the client): identical but `10.0.0.2/24`.

Apply on each Pi:
```bash
sudo cp netplan-*.yaml /etc/netplan/99-demo-link.yaml
sudo netplan apply
```
Verify: from the server, `ping 10.0.0.2`. Server listens on `10.0.0.1:<port>`; client dials `10.0.0.1`. The demo never depends on venue WiFi.

> If a Pi runs Ubuntu **Desktop** (NetworkManager renderer), set `renderer: NetworkManager` or use `nmcli` instead. Detect with `nmcli -v`.

---

## 9. Local dev environment (Mac)

1. Build OpenSSL 3.5.x from source natively on macOS via `crypto/setup-openssl.sh` (install to a local prefix, e.g. `~/opt/openssl-3.5`, never the system OpenSSL).
2. Develop the orchestration / app / dashboard in **Python or Node** (interpreted → portable; pin versions in a lockfile).
3. **Validate the Linux build in Docker.** Build `docker/Dockerfile.pi-proxy` from `ubuntu:23.10` (`--platform linux/arm64`, which runs natively on M1). Run `setup-openssl.sh` inside it. This is the Pi's userland minus the real CPU — catch ELF/glibc/netplan-adjacent issues here, not on the Pi.
4. Local end-to-end test loop: run server and client either as two processes on the Mac, or Mac-as-client against the Pi-proxy container as server. Real handshake, full speed, no hardware needed.

The only things you genuinely cannot get locally: (a) **real Cortex-A72 latency/throughput** — must be measured on the Pi; (b) the physical ethernet link. Everything else is developed and tested on the Mac.

---

## 10. Build phases (in order)

**Phase 0 — Foundations.**
Define `protocol/` (suite, event schema, message format). Write and test `crypto/setup-openssl.sh` on macOS and in the arm64 Ubuntu container. Confirm a vanilla `s_server`/`s_client` PQC handshake (`X25519MLKEM768`, `ML-DSA-65` cert) succeeds locally. *Nothing else starts until a real PQC handshake completes.*

**Phase 1 — Custom message (the easy, high-impact win).**
Implement `app/`: after the handshake, send an operator-supplied plaintext through the channel. Instrument the AEAD: capture `plaintext → ciphertext+tag → on-wire bytes → decrypted plaintext`, emit events per the schema. This is our own code, so it's fully observable. Render it in a minimal `dashboard/`.

**Phase 2 — Handshake capture.**
Implement `capture/`: pull real handshake artifacts via `SSLKEYLOGFILE`, the OpenSSL message callback, and/or `s_client -trace` — public keys, ML-KEM ciphertext, derived secret (where exposable), ML-DSA signature. Normalize into schema events.

**Phase 3 — Stepped replay.**
Implement `replay/`: take captured artifacts and play them back stage-by-stage at human pace, pause/step controls. This is the "watch each step" experience. Do **not** try to animate the live handshake.

**Phase 4 — Metrics.**
Handshake latency, throughput, connections/sec; PQC vs. classical side-by-side. Measure on the **Pi**, not the Mac — A72 numbers are the whole point and won't match x86/M1.

**Phase 5 — Dashboard polish + deploy.**
Single fullscreen dashboard: custom-message input, stepped replay panels (both sides), live metrics. Deploy to Pis; rehearse on the real ethernet link.

---

## 11. Deployment workflow

- Repo is canonical on the Mac. Push to a private Git remote (GitHub or a bare repo).
- `deploy/deploy.sh` on each Pi does `git pull`, runs `setup-openssl.sh` (once / on version change), installs pinned Python/Node deps into a venv/lockfile, and restarts the role.
- VSCode Remote-SSH into each Pi is for **running and tailing logs**, not editing source. One terminal tails the server, one tails the client. The agent edits only the canonical repo on the Mac.
- Never edit divergent copies on the two Pis. The repo is the single source; the Pis are deploy targets.

---

## 12. Constraints & gotchas

- **Don't copy compiled binaries between machines.** Build from pinned source per target.
- **Pin everything:** OpenSSL git tag, Python/Node versions, all package versions. Reproducibility is the compatibility guarantee.
- **macOS ≠ Linux** even though both are arm64. Test the Linux path in the Pi-proxy container before deploying.
- **Don't bind the demo to venue WiFi.** Direct ethernet, static IPs.
- **Don't fabricate handshake animation.** Capture-then-replay only.
- **Legacy algorithm names are a credibility bug.** FIPS names everywhere.
- **23.10 is EOL** — expect `apt` friction; prefer source builds and flag to Ben.

---

## 13. Verify at build time (don't assume — check)

- [ ] Exact current OpenSSL 3.5.x LTS patch version and its release tag.
- [ ] Wired interface name on each Pi (`ip link`) — may not be `eth0`.
- [ ] Netplan renderer on each Pi (`networkd` vs `NetworkManager`).
- [ ] Whether `apt` needs `old-releases.ubuntu.com` on 23.10.
- [ ] Whether the derived shared secret is exposable for the step view, or whether to show it as a fingerprint/hash instead (it may not be directly extractable — design the event accordingly).
- [ ] FN-DSA/FALCON standardization + liboqs status, *only if* FALCON is wanted.

---

## 14. Definition of done

- Two Pis complete a real `X25519MLKEM768` + `ML-DSA-65` TLS 1.3 handshake over the direct ethernet link.
- An operator types a custom message and watches it traverse every stage with real intermediate artifacts shown.
- The stepped handshake replay runs with pause/step controls.
- Live PQC-vs-classical metrics display, measured on the Pi.
- Everything builds from pinned source on a clean Mac and a clean Pi via the scripts, no manual fixups.
