// keyring-crypto.jsx — vault encryption, plain JS (no JSX) so Node can test it.
// Loaded in the browser via Babel like the other .jsx files; required by
// test/vault-crypto.test.js under Node's built-in WebCrypto.
//
// Stored vault (v2), a JSON envelope:
//   {"v":2,"kdf":"PBKDF2-SHA256","iter":600000,"salt":<b64 16B>,"iv":<b64 12B>,"ct":<b64>}
//   key = PBKDF2-HMAC-SHA256(password, salt, iter) -> AES-GCM-256
//   AAD = "keyring/v2/PBKDF2-SHA256/<iter>/<salt b64>" so header edits fail auth.
// Legacy vault (v1, before 2026-10): base64(iv[12] || ct), no AAD, salt in
//   localStorage kr_salt, 210 000 iterations. Opened read-only, then re-sealed as v2.

const KDF_NAME = 'PBKDF2-SHA256';
const KDF_ITER = 600000;        // OWASP Password Storage Cheat Sheet, PBKDF2-HMAC-SHA256
const LEGACY_ITER = 210000;
const MIN_ITER = 100000;        // refuse envelopes weaker than this
const MAX_ITER = 10000000;      // refuse envelopes that would hang the tab
const SALT_LEN = 16;
const IV_LEN = 12;

function b64enc(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return btoa(s);
}
function b64dec(s) {
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}

// Non-extractable PBKDF2 base key. Kept for the session so encrypted imports
// with a different salt can be opened without holding the password string.
function passwordKey(password) {
  return crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
}
function deriveKey(baseKey, salt, iterations) {
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}
function envelopeAad(iter, saltB64) {
  return new TextEncoder().encode(`keyring/v2/${KDF_NAME}/${iter}/${saltB64}`);
}

// New vault params: fresh random salt, current iteration count.
async function newVaultKey(baseKey) {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  return { key: await deriveKey(baseKey, salt, KDF_ITER), salt, iter: KDF_ITER };
}

// Encrypt with a fresh random IV on every call. Returns the envelope object.
async function sealVault(data, { key, salt, iter }) {
  const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
  const saltB64 = b64enc(salt);
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: envelopeAad(iter, saltB64) },
    key,
    new TextEncoder().encode(JSON.stringify(data))
  ));
  return { v: 2, kdf: KDF_NAME, iter, salt: saltB64, iv: b64enc(iv), ct: b64enc(ct) };
}

function parseEnvelope(env) {
  if (typeof env === 'string') env = JSON.parse(env);
  if (!env || env.v !== 2 || env.kdf !== KDF_NAME) throw new Error('Unsupported vault format');
  if (!Number.isInteger(env.iter) || env.iter < MIN_ITER || env.iter > MAX_ITER) throw new Error('Unsupported KDF parameters');
  const salt = b64dec(env.salt), iv = b64dec(env.iv), ct = b64dec(env.ct);
  if (salt.length !== SALT_LEN || iv.length !== IV_LEN || ct.length < 16) throw new Error('Malformed vault');
  return { iter: env.iter, saltB64: env.salt, salt, iv, ct };
}

// Open a stored vault string (v2 envelope or legacy base64) or a v2 envelope
// object. Throws on wrong password or any tampering.
// Returns { data, params: {key, salt, iter}, legacy }.
async function openVault(stored, baseKey, legacySaltB64) {
  if (typeof stored === 'string' && !stored.trimStart().startsWith('{')) {
    if (!legacySaltB64) throw new Error('Legacy vault without salt');
    const salt = b64dec(legacySaltB64);
    const key = await deriveKey(baseKey, salt, LEGACY_ITER);
    const bytes = b64dec(stored);
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes.slice(0, IV_LEN) }, key, bytes.slice(IV_LEN));
    return { data: JSON.parse(new TextDecoder().decode(plain)), params: { key, salt, iter: LEGACY_ITER }, legacy: true };
  }
  const e = parseEnvelope(stored);
  const key = await deriveKey(baseKey, e.salt, e.iter);
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: e.iv, additionalData: envelopeAad(e.iter, e.saltB64) }, key, e.ct
  );
  return { data: JSON.parse(new TextDecoder().decode(plain)), params: { key, salt: e.salt, iter: e.iter }, legacy: false };
}

// Shape-check vault contents from storage or an import file. Drops accounts
// without a seed and backups without a codes array, fills missing labels;
// throws if there is no accounts array.
function sanitizeVault(data) {
  if (!data || !Array.isArray(data.accounts)) throw new Error('Invalid vault data');
  const str = (v) => typeof v === 'string';
  const accounts = data.accounts
    .filter((a) => a && str(a.seed) && a.seed)
    .map((a, i) => ({
      id: str(a.id) ? a.id : `a${Date.now()}-${i}`,
      issuer: str(a.issuer) && a.issuer ? a.issuer : 'Unknown',
      account: str(a.account) && a.account ? a.account : '—',
      seed: a.seed,
      tone: str(a.tone) ? a.tone : 'slate',
      fav: a.fav === true,
      ...(Number.isInteger(a.period) && a.period > 0 && a.period <= 3600 ? { period: a.period } : {}),
    }));
  const backups = (Array.isArray(data.backups) ? data.backups : [])
    .filter((b) => b && Array.isArray(b.codes))
    .map((b, i) => {
      const codes = b.codes.map((c) => String(c)); // keep indexes so `used` stays aligned
      return {
        id: str(b.id) ? b.id : `b${Date.now()}-${i}`,
        issuer: str(b.issuer) && b.issuer ? b.issuer : 'Unknown', tone: str(b.tone) ? b.tone : 'slate', codes,
        used: (Array.isArray(b.used) ? b.used : []).filter((n) => Number.isInteger(n) && n >= 0 && n < codes.length),
      };
    });
  return { accounts, backups };
}

// Export file: {"format":"keyring-export","version":2,"exportedAt":...,"vault":<envelope>}
async function buildExport(data, params) {
  return JSON.stringify({ format: 'keyring-export', version: 2, exportedAt: new Date().toISOString(), vault: await sealVault(data, params) }, null, 2);
}
// Accepts v2 encrypted exports and v1 plaintext exports ({version:1, accounts, backups}).
async function readExport(text, baseKey) {
  const file = JSON.parse(text);
  if (file && file.version === 2) {
    const { data } = await openVault(file.vault, baseKey);
    return { ...sanitizeVault(data), encrypted: true };
  }
  return { ...sanitizeVault(file), encrypted: false };
}

const KeyringCrypto = {
  KDF_ITER, LEGACY_ITER, b64enc, b64dec, passwordKey, deriveKey, newVaultKey,
  sealVault, openVault, sanitizeVault, buildExport, readExport,
};
if (typeof module !== 'undefined' && module.exports) module.exports = KeyringCrypto;
else Object.assign(window, KeyringCrypto);
