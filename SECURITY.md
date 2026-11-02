# Security

Keyring is a small self-hosted project. It has not been independently audited.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on this repository
(Security tab → "Report a vulnerability"). Please do not open a public issue
for an unfixed vulnerability. Include the affected file or endpoint, steps to
reproduce, and the impact you expect.

## What is stored where

| Data | Location | Form |
|------|----------|------|
| TOTP secrets, backup codes | `localStorage['kr_vault']` | AES-GCM-256 envelope (below) |
| Vault password, in transit from the login page to the vault page | `sessionStorage['kr_pending_auth']` | Plaintext JSON; removed by the vault page when it loads |
| Derived vault key and PBKDF2 base key | JS memory (`useRef`) | Non-extractable `CryptoKey`s; dropped on sign-out or tab close |
| Login credential | Server env `KEYRING_CREDENTIAL` | Plaintext `identifier:password` |
| Export file | Wherever you save it | AES-GCM-256 envelope under the vault password |
| Theme and layout settings | `localStorage['ej_theme']`, `['kr_tweaks']` | Plaintext, not sensitive |

## Vault format (v2)

```json
{"v":2,"kdf":"PBKDF2-SHA256","iter":600000,"salt":"<16 bytes b64>","iv":"<12 bytes b64>","ct":"<b64>"}
```

- Key: PBKDF2-HMAC-SHA-256(password, salt, `iter`) → AES-GCM-256. 600 000
  iterations follows the OWASP Password Storage Cheat Sheet for PBKDF2-HMAC-SHA256.
- Salt: 16 random bytes per vault, generated with `crypto.getRandomValues`.
- IV: 12 random bytes from `crypto.getRandomValues`, new on every save.
- Associated data: `keyring/v2/PBKDF2-SHA256/<iter>/<salt>`, so a changed
  header fails authentication.
- Envelopes with `iter` outside 100 000–10 000 000, or with the wrong salt or IV
  length, are rejected before key derivation.
- Exports use the same envelope inside
  `{"format":"keyring-export","version":2,"exportedAt":…,"vault":{…}}`.

Code: `public/keyring-crypto.jsx`. Tests: `test/vault-crypto.test.js`.

**Legacy vaults.** Vaults written before v2 are `base64(iv || ciphertext)`, with
no associated data, 210 000 iterations, and the salt in `localStorage['kr_salt']`.
The app still reads them. On the next successful login it re-encrypts the
vault as v2 with a new salt and removes `kr_salt`. Plaintext v1 export files
(`{"version":1,"accounts":[…]}`) can still be imported. The app warns that the
file is unencrypted.

## Threat model

**What it protects against**

- Someone who copies the browser profile or `localStorage` while the vault is
  locked. They have to brute-force the password offline at 600 000 PBKDF2
  iterations per guess. How long that takes depends on the strength of the password.
- An export file that leaks. It is encrypted the same way as the stored vault.
- Changes to the stored vault or an export file. AES-GCM authentication rejects them.
- Online password guessing against `/keyring/api/auth`. nginx limits it to
  10 requests per minute with a burst of 5.

**What it does not protect against**

- **Script running in the page while the vault is unlocked.** Examples: a
  compromised CDN, a malicious browser extension, or another app served from
  the same origin. Such a script can read decrypted state and use the in-memory
  keys. The CSP in `nginx.conf` limits script sources to the app's own origin
  and unpkg.com, and limits fetch and image requests to the app's own origin. It
  has to allow `'unsafe-inline'` because Babel standalone runs the transpiled
  code as inline scripts. The CDN scripts have Subresource Integrity hashes.
  The Google Fonts stylesheet does not.
- **The server operator.** The vault password is the same as the login password
  in `KEYRING_CREDENTIAL`. Anyone who can read the server's `.env` and also
  get a copy of the browser's `localStorage` can decrypt the vault.
- **Sharing an origin with other apps.** `localStorage` and `sessionStorage`
  are scoped per origin. Serve Keyring from its own origin, not next to other apps.
- **The login handoff.** The password sits in plaintext in `sessionStorage`
  between the login page and the vault page. If the vault page never loads
  (for example, the CDN is down), it stays there until the tab is closed.
- **Clipboard.** Copied TOTP and backup codes stay on the clipboard. The app
  does not clear them.
- **Brute force per client behind a reverse proxy.** nginx sees the proxy's
  address unless you set `real_ip` for your proxy. In that case the rate limit
  is one bucket shared by all clients.
- **Losing data.** The vault exists only in the browser. Clearing site data
  deletes it unless you exported a copy.

## Operational notes

- Use HTTPS. Web Crypto works only in secure contexts.
- Changing the password in `KEYRING_CREDENTIAL` does not re-encrypt existing
  vaults, and an encrypted export opens only under the password it was made
  with. Changing the password currently means re-adding accounts.
- Rolling back to a version older than v2 after a vault has been migrated
  makes the vault unreadable to that older version. The data is still intact,
  and redeploying v2 makes it readable again.
