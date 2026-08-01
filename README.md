# Vanguard — Passwordless Authentication & Approval Platform

*Easy to use. Hard to break.*

Vanguard is a full-stack authentication platform built for a 24-hour hackathon
challenge (Tally Code Brewers). It replaces passwords with real-time passkey
(WebAuthn/FIDO2) sign-in, adds an offline TOTP fallback for when the primary
channel is unavailable, and layers a trust-tiered, multi-party approval
system on top for sensitive actions.

## Why

Passwords get phished, reused, and stolen. SMS codes get intercepted via
SIM-swapping. Vanguard's core idea: verify identity through a live, hardware-backed
channel first (a passkey), and fall back to a channel that works with **zero
network dependency** (a locally-computed 6-digit code) when the primary path
isn't available — instead of falling back to something weaker.

## Key features

- **Real-time passwordless sign-in** — WebAuthn/FIDO2 passkeys, verified
  server-side with `py_webauthn` (real cryptographic signature verification,
  not a mock).
- **Offline fallback code** — a TOTP code computed entirely client-side via
  the Web Crypto API, no network call required to generate it.
- **Trust-tiered actions** — routine actions need just a passkey; critical
  actions (e.g. large transfers) require a passkey **and** a fresh TOTP
  step-up code, enforced server-side.
- **Multi-party approvals (M-of-N quorum)** — sensitive actions can require
  approval from multiple people, with a named backup approver if a primary
  approver is unreachable.
- **IP-based abuse protection** — automatic temporary bans after repeated
  failed verification attempts.
- **Signed, persistent audit trail** — every verified action is written to a
  SQLite-backed, append-only ledger, so disputes ("did they really approve
  this?") can be resolved with evidence.
- **Graceful recovery** — one-time recovery codes issued at registration for
  the "device is truly gone" scenario, separate from the offline-code fallback
  (which only requires *no network*, not *a working device*).
- **Real-time push** — pending approvals are broadcast over WebSockets so an
  approver sees a request the moment it's created.
- **Undo window & panic switch** — a short grace period to cancel an
  accidental approval, and a one-tap "this wasn't me" control that instantly
  revokes sessions.

## Tech stack

| Layer | Technology |
|---|---|
| Backend | Python 3, FastAPI, Pydantic, Uvicorn |
| Auth | `webauthn` (py_webauthn) for FIDO2/passkeys, `pyotp` for TOTP |
| Storage | SQLite (audit ledger) |
| Realtime | WebSockets (FastAPI native) |
| Frontend | HTML5, hand-written CSS3, vanilla JavaScript (ES6+) |
| Browser APIs | Web Authentication API, Web Crypto API, WebSocket API |

## Architecture

```
Browser (frontend.html)
   │  WebAuthn ceremony (navigator.credentials)
   │  Client-side TOTP generation (crypto.subtle)
   ▼
FastAPI server (main.py)
   │  Verifies passkey signatures (py_webauthn)
   │  Verifies TOTP codes (pyotp)
   │  Enforces trust-tier policy per action
   │  Tracks per-IP failures / bans
   ▼
SQLite (vanguard_audit.db) — signed, append-only approval ledger
```

## Getting started

```bash
git clone https://github.com/<your-username>/vanguard.git
cd vanguard
pip install -r requirements.txt
python3 -m uvicorn main:app --host 0.0.0.0 --port 8080
```

Then open **http://localhost:8080/** in a browser that supports WebAuthn
(Chrome, Edge, Safari) with a platform authenticator available (Touch ID,
Windows Hello, or a security key).

## Known limitations

- User accounts and sessions are in-memory and reset when the server
  restarts; only the audit ledger persists (SQLite).
- IP-ban simulation uses a demo-only `x-demo-ip` header override since local
  testing happens from a single machine.
- Built for a hackathon timebox — not hardened for production deployment.

## License

MIT — see [LICENSE](LICENSE).