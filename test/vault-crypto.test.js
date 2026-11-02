// node --test test/
const test = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { runInNewContext } = require('node:vm');
const K = require('../public/keyring-crypto.jsx');

const PW = 'correct-horse';
const VAULT = {
  accounts: [{ id: 'a1', issuer: 'GitHub', account: 'alice', seed: 'JBSWY3DPEHPK3PXP', tone: 'slate', fav: true, period: 30 }],
  backups: [{ id: 'b1', issuer: 'GitHub', tone: 'slate', codes: ['1111-2222', '3333-4444'], used: [1] }],
};
// Produced by the pre-v2 encryptVault (210k iterations, iv||ct base64, no AAD)
// with password PW and salt bytes 1..16.
const LEGACY_SALT = 'AQIDBAUGBwgJCgsMDQ4PEA==';
const LEGACY_VAULT = 'tuPH/b/UOZE6HbfLLrWbgmSgRYUfrIIImPYwJFu2bpN2ie7uiwBZ+dPijKTuYXdrchy6sPkoqyqqHxkS4OLQAtfLRqqW8v5uSqtvHAHGyI3tp5lQs3Xpsie/gURdIxdjRBIx0LbwlZU6YMM3dpGHAzb30OItL0ii8kMV8RE+p/Hup85sbscRJJAvmyaBE97q1w/dsjNTG3SqAksZeukVp4RtGZQxwaip4K11LmgaRU88akQEradbNEofsRMMWB7LupLFtenzeC8nsnNJbK6PAeDvE/AgDMlcEqQ5NDWcuI6nqiZl99DxOLhvrPQWi3qQY3ja5yu/ZPL/nGsWr1v/LQ==';

let base, params, env;
test.before(async () => {
  base = await K.passwordKey(PW);
  params = await K.newVaultKey(base);
  env = await K.sealVault(VAULT, params);
});

test('v2 envelope round-trips with current parameters', async () => {
  assert.equal(env.v, 2);
  assert.equal(env.iter, 600000);
  assert.equal(K.b64dec(env.salt).length, 16);
  assert.equal(K.b64dec(env.iv).length, 12);
  const opened = await K.openVault(JSON.stringify(env), await K.passwordKey(PW));
  assert.deepEqual(opened.data, VAULT);
  assert.equal(opened.legacy, false);
});

test('legacy vault from the previous format still decrypts', async () => {
  const opened = await K.openVault(LEGACY_VAULT, base, LEGACY_SALT);
  assert.deepEqual(opened.data, VAULT);
  assert.equal(opened.legacy, true);
  assert.equal(opened.params.iter, 210000);
});

test('migration keeps legacy salt for stale-tab writes', async () => {
  const storage = new Map([['kr_vault', LEGACY_VAULT], ['kr_salt', LEGACY_SALT]]);
  const localStorage = {
    getItem: (key) => storage.get(key) ?? null,
    setItem: (key, value) => storage.set(key, value),
    removeItem: (key) => storage.delete(key),
  };
  const source = readFileSync(require.resolve('../public/keyring-app.jsx'), 'utf8');
  const start = source.indexOf('const handleLogin = async');
  const end = source.indexOf('const handleGuestLogin', start);
  assert.ok(start >= 0 && end > start);
  // Execute the app's login handler without JSX or a browser.
  const login = runInNewContext(`${source.slice(start, end)}; handleLogin;`, {
    ...K, localStorage,
    vaultParams: { current: null }, baseKey: { current: null }, vaultLoaded: { current: false },
    setAccounts() {}, setBackups() {}, setUser() {},
  });
  const stale = await K.openVault(LEGACY_VAULT, base, LEGACY_SALT);
  await login('alice@example.com', PW);
  assert.equal(JSON.parse(localStorage.getItem('kr_vault')).v, 2);

  const updated = { ...VAULT, accounts: [...VAULT.accounts, { ...VAULT.accounts[0], id: 'a2', issuer: 'New' }] };
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv }, stale.params.key, new TextEncoder().encode(JSON.stringify(updated))
  ));
  localStorage.setItem('kr_vault', K.b64enc(new Uint8Array([...iv, ...ct])));
  const reopened = await K.openVault(localStorage.getItem('kr_vault'), base, localStorage.getItem('kr_salt'));
  assert.deepEqual(reopened.data, updated);
  await login('alice@example.com', PW);
  assert.deepEqual((await K.openVault(localStorage.getItem('kr_vault'), base)).data, updated);
  assert.equal(localStorage.getItem('kr_salt'), LEGACY_SALT);
});

test('wrong password is rejected for both formats', async () => {
  const bad = await K.passwordKey('wrong');
  await assert.rejects(K.openVault(JSON.stringify(env), bad));
  await assert.rejects(K.openVault(LEGACY_VAULT, bad, LEGACY_SALT));
});

test('every seal uses a fresh IV', async () => {
  const ivs = new Set();
  for (let i = 0; i < 20; i++) ivs.add((await K.sealVault(VAULT, params)).iv);
  assert.equal(ivs.size, 20);
});

test('header and ciphertext tampering fail authentication', async () => {
  await assert.rejects(K.openVault({ ...env, iter: 600001 }, base));
  // AAD is required: the right key without the header as AAD must not decrypt.
  await assert.rejects(crypto.subtle.decrypt({ name: 'AES-GCM', iv: K.b64dec(env.iv) }, params.key, K.b64dec(env.ct)));
  const ct = K.b64dec(env.ct); ct[0] ^= 1;
  await assert.rejects(K.openVault({ ...env, ct: K.b64enc(ct) }, base));
});

test('out-of-range KDF parameters are refused before deriving', async () => {
  await assert.rejects(K.openVault({ ...env, iter: 1000 }, base), /KDF/);
  await assert.rejects(K.openVault({ ...env, iter: 1e9 }, base), /KDF/);
  await assert.rejects(K.openVault({ ...env, v: 3 }, base), /format/);
  await assert.rejects(K.openVault({ ...env, iv: K.b64enc(new Uint8Array(8)) }, base), /Malformed/);
});

test('exports are encrypted and readable; v1 plaintext exports still import', async () => {
  const text = await K.buildExport(VAULT, params);
  assert.ok(!text.includes('JBSWY3DPEHPK3PXP'), 'seed must not appear in export');
  const fromV2 = await K.readExport(text, base);
  assert.equal(fromV2.encrypted, true);
  assert.deepEqual(fromV2.accounts, VAULT.accounts);

  // Export from another browser: same password, different salt.
  const other = await K.newVaultKey(await K.passwordKey(PW));
  assert.equal((await K.readExport(await K.buildExport(VAULT, other), base)).accounts.length, 1);
  await assert.rejects(K.readExport(text, await K.passwordKey('wrong')));

  const v1 = JSON.stringify({ version: 1, exportedAt: '2026-01-01T00:00:00Z', ...VAULT });
  const fromV1 = await K.readExport(v1, base);
  assert.equal(fromV1.encrypted, false);
  assert.deepEqual(fromV1.backups, VAULT.backups);
});

test('sanitizeVault drops unusable entries and keeps used indexes aligned', () => {
  assert.throws(() => K.sanitizeVault({ accounts: 'x' }));
  const out = K.sanitizeVault({
    accounts: [null, { issuer: 'NoSeed' }, { seed: 'ABCDEFGH', issuer: 7, period: -1 }],
    backups: [{ issuer: 'X', codes: [123, 'abc'], used: [1, 5, 'a'] }, { issuer: 'NoCodes' }],
  });
  assert.equal(out.accounts.length, 1);
  assert.equal(out.accounts[0].issuer, 'Unknown');
  assert.equal(out.accounts[0].period, undefined);
  assert.deepEqual(out.backups[0].codes, ['123', 'abc']);
  assert.deepEqual(out.backups[0].used, [1]);
  assert.equal(out.backups.length, 1);
});

test('imports default whitespace-only issuers', async () => {
  const out = await K.readExport(JSON.stringify({
    accounts: [{ seed: 'ABCDEFGH', issuer: ' \t\n ' }, { seed: 'ABCDEFGH', issuer: ' GitHub ' }],
    backups: [{ issuer: ' \t\n ', codes: [] }, { issuer: ' GitHub ', codes: [] }],
  }), base);
  assert.deepEqual(out.accounts.map((a) => a.issuer), ['Unknown', 'GitHub']);
  assert.deepEqual(out.backups.map((b) => b.issuer), ['Unknown', 'GitHub']);
});

test('imports default tones outside the allowlist', async () => {
  const tones = ['constructor', '__proto__', 'toString', 'unknown', '', null,
    'blue', 'green', 'violet', 'amber', 'rose', 'slate', 'teal', 'red'];
  const out = await K.readExport(JSON.stringify({
    accounts: tones.map((tone) => ({ seed: 'ABCDEFGH', tone })),
    backups: tones.map((tone) => ({ codes: [], tone })),
  }), base);
  const expected = tones.map((tone, i) => i < 6 ? 'slate' : tone);
  assert.deepEqual(out.accounts.map((a) => a.tone), expected);
  assert.deepEqual(out.backups.map((b) => b.tone), expected);
});
