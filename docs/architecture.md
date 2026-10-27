# Architecture

## Overview

Keyring is a two-component system: a static frontend and a single-endpoint auth backend. The vault itself is entirely client-side — the backend only verifies login credentials.

```
┌─────────────────────────────────────────────────────────────────┐
│ Browser                                                         │
│                                                                 │
│  /credential?service=otp        /keyring/                      │
│  ┌──────────────────────────┐   ┌──────────────────────────┐   │
│  │ credential-app.jsx       │   │ keyring-app.jsx           │   │
│  │                          │   │  + keyring-lib.jsx        │   │
│  │  Login form              │   │  + keyring-screens.jsx    │   │
│  │  POST /keyring/api/auth  │   │                           │   │
│  │  200 OK → sessionStorage ├──▶│  Vault: AES-GCM encrypted │   │
│  │          handoff         │   │  in localStorage          │   │
│  │                          │   │  TOTP: crypto.subtle      │   │
│  └──────────────────────────┘   └──────────────────────────┘   │
└───────────────────────┬─────────────────────────────────────────┘
                        │ POST /keyring/api/auth
┌───────────────────────▼─────────────────────────────────────────┐
│ nginx                                                           │
│                                                                 │
│  /credential  ──▶ credential/index.html                        │
│  /keyring/    ──▶ keyring/index.html                           │
│  /            ──▶ 302 /credential?service=otp                  │
│  /*.jsx       ──▶ static file (30d cache)                      │
│  /keyring/api/──▶ proxy keyring-auth:8080                      │
└───────────────────────┬─────────────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────────────┐
│ keyring-auth (Flask)                                            │
│                                                                 │
│  POST /keyring/api/auth                                         │
│    reads KEYRING_CREDENTIAL env var                             │
│    compares { id, password } → 200 | 401                       │
│                                                                 │
│  GET  /keyring/api/health  →  200                               │
└─────────────────────────────────────────────────────────────────┘
```

## Auth flow

1. User navigates to any URL → nginx redirects root to `/credential?service=otp`
2. `credential-app.jsx` renders a login form for the OTP service
3. On submit: `POST /keyring/api/auth` with `{ id, password }`
4. nginx proxies to `keyring-auth:8080`
5. Flask compares against `KEYRING_CREDENTIAL` env var. Returns `200` or `401` (nginx returns `429` past 10 requests/min, burst 5)
6. On `200`: credential-app writes `{ email, pw }` to `sessionStorage['kr_pending_auth']` then navigates to `/keyring/`
7. `keyring-app.jsx` reads `kr_pending_auth` from sessionStorage on mount, removes it immediately, and calls `handleLogin(email, pw)`
8. `handleLogin` derives an AES-GCM key from the password via PBKDF2, decrypts the vault from `localStorage['kr_vault']`, and loads accounts into React state

The raw password is in `sessionStorage` only between the two pages and is not kept after login. The derived `CryptoKey` and a non-extractable PBKDF2 base key (used to open encrypted imports with a different salt) live in `useRef`s for the session lifetime and are cleared on sign-out.

## Vault crypto

| Step | Detail |
|------|--------|
| Key derivation | PBKDF2-HMAC-SHA-256, 600 000 iterations, 16-byte random salt stored in the envelope |
| Encryption | AES-GCM-256, 12-byte random IV per save, AAD `keyring/v2/PBKDF2-SHA256/<iter>/<salt>` |
| Storage | JSON `{"v":2,"kdf","iter","salt","iv","ct"}` in `localStorage['kr_vault']` |
| On wrong password | `openVault` throws → login fails with "Wrong password" |

New users get an empty vault on first login. Existing users get their decrypted vault. Older formats are migrated on login: pre-v2 encrypted vaults (`btoa(iv + ct)`, 210 000 iterations, salt in `kr_salt`) are re-encrypted as v2 with a new salt, and legacy plaintext `kr_accounts` are encrypted and removed. Crypto code is in `keyring-crypto.jsx`; details in `SECURITY.md`.

## TOTP engine

- For **base32 secrets** (real accounts): RFC 6238 via `crypto.subtle.importKey` + `HMAC-SHA-1`. Counter = `Math.floor(unix_time / period)`.
- For **demo seeds** (non-base32 strings): deterministic FNV-1a hash — produces stable fake codes for demo mode without needing real secrets.
- Period is per-account (30s or 60s). The `useClock` hook ticks every 250 ms so countdowns stay smooth regardless of tab focus state.

## Data model

```typescript
// TOTP account stored in vault
interface Account {
  id: string;       // 'a' + Date.now()
  issuer: string;   // "GitHub"
  account: string;  // "you@email.com"
  seed: string;     // base32 secret or demo seed string
  tone: string;     // color preset: 'slate' | 'blue' | 'violet' | 'amber' | 'rose' | 'teal' | 'green' | 'red'
  fav: boolean;     // pinned to top of list
  period?: number;  // TOTP window in seconds (default 30)
}

// Backup recovery code set
interface Backup {
  id: string;
  issuer: string;
  tone: string;
  codes: string[];  // raw recovery code strings
  used: number[];   // indices of codes already used
}

// Vault stored AES-GCM encrypted in localStorage['kr_vault']
interface Vault {
  accounts: Account[];
  backups: Backup[];
}
```

## File responsibilities

| File | Responsibility |
|------|----------------|
| `keyring-crypto.jsx` | Vault envelope (PBKDF2 + AES-GCM), legacy decrypt, import/export, vault shape validation |
| `keyring-lib.jsx` | TOTP engine, shared icons, `Tile`, `Countdown`, `Toast`, `useClock`, demo seed data |
| `keyring-app.jsx` | Root vault app — auth state machine, vault load/save on state change, account/backup CRUD, drag reorder, export/import |
| `keyring-screens.jsx` | `AccountRow` (live code display + tap-to-copy), `BackupCard`, `AddModal`, `AddBackupModal` |
| `credential-app.jsx` | Auth gate — login form, guest/demo mode, `POST /keyring/api/auth`, sessionStorage handoff |
| `tweaks-panel.jsx` | Floating tweaks panel — `useTweaks` hook, `TweakRadio`, `TweakColor`, drag to reposition |
| `auth/app.py` | Flask: credential verification at `POST /keyring/api/auth`, health check at `GET /keyring/api/health` |
| `nginx.conf` | Route `/credential` + `/keyring/`, proxy `/keyring/api/` to auth container, cache static assets |
