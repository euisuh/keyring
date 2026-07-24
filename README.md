# Keyring

Self-hosted TOTP vault with a static browser app and a small Flask credential
gate. Vault data stays in the browser, encrypted with AES-GCM; there is no
database or cloud sync.

**Live:** [uiseoya.com/credential?service=otp](https://uiseoya.com/credential?service=otp)

| Login | Vault |
|-------|-------|
| ![Login screen](docs/screenshots/login.png) | ![Vault](docs/screenshots/vault.png) |

## Features

- **RFC 6238 TOTP** — real `crypto.subtle` HMAC-SHA-1 for base32 secrets; deterministic hash fallback for demo seeds
- **AES-GCM-256 vault** — PBKDF2-SHA-256 (210 000 iterations) → AES-GCM. 12-byte random IV prepended to ciphertext, stored as base64 in `localStorage`
- **Backup codes** — per-service recovery code sets with tap-to-copy and used-state tracking
- **Import and export** — JSON backup and restore for accounts and recovery codes
- **Demo mode** — `?demo=1` loads sample accounts without touching the real vault
- **Drag reorder** — HTML5 drag-and-drop to reorder accounts
- **Tweaks panel** — live accent color, density, layout, and theme switching
- **Mobile-ready** — responsive layout plus a standalone-capable web app manifest

## Before you deploy

- Keyring supports one login credential, supplied as
  `KEYRING_CREDENTIAL=identifier:password`.
- Vaults are browser-local. Clearing site data removes the vault unless it was
  exported first; another browser or device starts with an empty vault.
- The frontend fetches React, Babel, and fonts from public CDNs, so first load
  requires internet access.
- Use HTTPS outside localhost. Web Crypto is available only in secure contexts
  in supported browsers.

## Stack

| Layer | Technology |
|-------|------------|
| Frontend | HTML + React 18 UMD + Babel standalone — no build step |
| Styles | CSS custom properties (dark/light themes, accent theming) |
| Crypto | `window.crypto.subtle` — PBKDF2 + AES-GCM + HMAC-SHA-1 |
| Auth backend | Flask 3 + Gunicorn (single `POST /keyring/api/auth` endpoint) |
| Server | nginx:alpine |
| Container | Docker + Docker Compose |

## How it works

```
Browser
  └─ /credential?service=otp    ← auth gate (credential/index.html + credential-app.jsx)
       │  POST /keyring/api/auth  ← nginx proxies to keyring-auth Flask service
       │  200 OK → sessionStorage handoff
       └─ /keyring/              ← vault app (keyring/index.html + keyring-*.jsx)
            │  TOTP codes via crypto.subtle (client only)
            └─ localStorage kr_vault ← AES-GCM encrypted vault
```

The vault never leaves the browser. The auth service only checks the configured
login credential; it does not receive OTP secrets or vault contents.

## Deploy

### Prerequisites

- Docker + Docker Compose
- nginx-proxy-manager (for production TLS — or remove the `npm` network and expose port directly)

### Steps

```bash
git clone https://github.com/euisuh/keyring.git
cd keyring
cp .env.example .env
# Edit .env: set KEYRING_CREDENTIAL=your@email.com:yourpassword
docker compose up -d --build
```

Runs on `127.0.0.1:8088` by default. In production, reverse-proxy through nginx-proxy-manager to add TLS.

If you don't use nginx-proxy-manager, remove the `npm` network block from `docker-compose.yml` and change the port binding to `0.0.0.0:8088:80`.

### Environment variables

| Variable | Description | Default |
|----------|-------------|---------|
| `KEYRING_CREDENTIAL` | Login credential in `identifier:password` format | `you@email.com:changeme` |

### Health check

```bash
curl http://localhost:8088/keyring/api/health
# {"status": "ok"}
```

### Local dev (no Docker)

Serve `public/` from a static server for the frontend:

```bash
python3 -m http.server 8080 -d public
```

For auth, run the Flask service separately:

```bash
cd auth
pip install flask gunicorn
KEYRING_CREDENTIAL=you@email.com:pw python app.py
```

Then visit `http://localhost:8080/credential?service=otp`. The auth POST will fail (different port) — use demo mode instead: `http://localhost:8080/keyring/?demo=1`.

## Tests

The smoke tests cover the health endpoint, valid login, rejected login, and a
missing server credential:

```bash
python3 -m venv .venv
.venv/bin/pip install -r auth/requirements.txt
cd auth && ../.venv/bin/python -m unittest -v
```

GitHub Actions runs the same suite on pushes and pull requests.

## Structure

```
.github/
  workflows/
    test.yml             # Flask auth smoke tests
public/
  keyring/
    index.html          # Vault app shell — loads keyring-*.jsx via Babel
  credential/
    index.html          # Auth gate shell — loads credential-app.jsx
  keyring-lib.jsx       # TOTP engine, AES-GCM vault crypto, shared icons + components
  keyring-app.jsx       # Root vault app — auth routing, account list, vault persistence
  keyring-screens.jsx   # AccountRow, BackupCard, AddModal, AddBackupModal
  credential-app.jsx    # Auth gate — OTP service definition + login form
  tweaks-panel.jsx      # Floating tweaks shell (theme, accent, density, layout)
  favicon.ico / favicon.png / manifest.json / robots.txt
auth/
  app.py                # Flask auth endpoint
  test_app.py           # Auth and health smoke tests
  requirements.txt
  Dockerfile
nginx.conf
Dockerfile
docker-compose.yml
.env.example
docs/
  architecture.md
```

## Security model

- OTP secrets are stored AES-GCM encrypted in `localStorage`. The vault key is derived from your password at login and kept only in a JS `useRef` — it is never persisted.
- The PBKDF2 salt is random and stored separately in `localStorage`; each vault write uses a new random 12-byte AES-GCM IV.
- The credential page temporarily passes the entered password through `sessionStorage`; the vault app removes that handoff value when it reads it.
- The Flask service reads its login credential from `KEYRING_CREDENTIAL`, compares both fields with `hmac.compare_digest`, and has no database.
- React, ReactDOM, and Babel CDN scripts include Subresource Integrity hashes.
- nginx sends `X-Frame-Options: SAMEORIGIN`, `X-Content-Type-Options: nosniff`, and `Referrer-Policy: strict-origin-when-cross-origin` headers on all responses.
- The credential gate is marked `noindex, nofollow` in its meta tags. `robots.txt` also disallows `/credential` and `/keyring/`.

This is a small self-hosted project, not an independently audited password
manager. Browser compromise or script injection can expose a vault while it is
unlocked.

## License

MIT
