// lib.jsx — shared data, TOTP engine, icons, primitives
const { useState, useEffect, useRef, useCallback } = React;

/* ───────────────────────── TOTP engine ─────────────────────────
   Real RFC 6238 TOTP for base32 secrets (accounts you actually use).
   Deterministic hash fallback for demo seed strings. */

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function isBase32(s) {
  return /^[A-Z2-7\s]+=*$/.test(s.replace(/\s/g, '').toUpperCase()) && s.replace(/[\s=]/g, '').length >= 8;
}
function base32Decode(s) {
  s = s.replace(/\s/g, '').toUpperCase().replace(/=+$/, '');
  let bits = 0, val = 0;
  const bytes = [];
  for (const c of s) {
    const i = B32.indexOf(c);
    if (i === -1) continue;
    val = (val << 5) | i;
    bits += 5;
    if (bits >= 8) { bits -= 8; bytes.push((val >> bits) & 0xff); }
  }
  return new Uint8Array(bytes).buffer;
}
async function realTotp(secret, step) {
  const keyBytes = base32Decode(secret);
  const counter = new ArrayBuffer(8);
  new DataView(counter).setUint32(4, step, false);
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, counter));
  const off = mac[19] & 0xf;
  const code = ((mac[off] & 0x7f) << 24) | (mac[off+1] << 16) | (mac[off+2] << 8) | mac[off+3];
  return String(code % 1000000).padStart(6, '0');
}
function fnv1a(str) {
  let h = 2166136261 >>> 0;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619) >>> 0;
  }
  return h;
}
function hashCode(seed, step) {
  return String(fnv1a(seed + '|' + step) % 1000000).padStart(6, '0');
}

/* ───────────────────────── Vault crypto ─────────────────────────
   PBKDF2-SHA-256 (210k iterations) → AES-GCM-256.
   12-byte IV prepended to ciphertext, stored as base64 in localStorage. */
function b64enc(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return btoa(s);
}
function b64dec(s) {
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}
async function deriveKey(password, salt) {
  const raw = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 210000, hash: 'SHA-256' },
    raw,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}
async function encryptVault(data, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(JSON.stringify(data))
  ));
  const out = new Uint8Array(12 + ct.length);
  out.set(iv);
  out.set(ct, 12);
  return b64enc(out);
}
async function decryptVault(b64, key) {
  const bytes = b64dec(b64);
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: bytes.slice(0, 12) },
    key,
    bytes.slice(12)
  );
  return JSON.parse(new TextDecoder().decode(plain));
}

const PERIOD = 30;
function nowStep(period = PERIOD) { return Math.floor(Date.now() / 1000 / period); }
function secondsLeft(period = PERIOD) { return period - (Math.floor(Date.now() / 1000) % period); }
function fmtCode(c) { return c.slice(0, 3) + ' ' + c.slice(3); }

/* useClock — shared tick. Returns global 30s step/left plus a stepFor(period)
   helper so per-account countdowns with different periods work correctly. */
function useClock(active = true) {
  const [, force] = useState(0);
  useEffect(() => {
    if (!active) return;
    let id;
    const loop = () => { force((n) => n + 1); id = setTimeout(loop, 250); };
    id = setTimeout(loop, 250);
    return () => clearTimeout(id);
  }, [active]);
  return {
    step: nowStep(30),
    left: secondsLeft(30),
    stepFor: (p) => nowStep(p),
    leftFor: (p) => secondsLeft(p),
  };
}

/* ───────────────────────── Brand tiles ─────────────────────────
   Minimal monogram tiles (no logo recreation): tinted square + initial. */
const TILE_PRESETS = {
  blue:   ['#e8efff', '#2f6df6', '#0d244f'],
  green:  ['#e4f6ec', '#16a34a', '#0b3a21'],
  violet: ['#efe9ff', '#7c5cff', '#2a1a5e'],
  amber:  ['#fdf0dc', '#e08a16', '#5a3604'],
  rose:   ['#ffe9ee', '#e5447b', '#5e0f2c'],
  slate:  ['#eceef3', '#4b5566', '#1a2230'],
  teal:   ['#ddf6f3', '#0f9d8f', '#053b36'],
  red:    ['#ffe7e6', '#e5484d', '#5e1010'],
};
function autoTone(issuer) {
  const tones = Object.keys(TILE_PRESETS);
  return tones[fnv1a((issuer || '').toLowerCase()) % tones.length];
}
function Tile({ label, tone = 'slate', size = 38 }) {
  const dark = document.documentElement.getAttribute('data-theme') === 'dark';
  const [softL, mid, deep] = TILE_PRESETS[tone] || TILE_PRESETS.slate;
  const bg = dark ? `color-mix(in srgb, ${mid} 26%, #15151a)` : softL;
  const fg = dark ? `color-mix(in srgb, ${mid} 55%, #ffffff)` : deep;
  const initial = (label || '?').trim()[0].toUpperCase();
  return (
    <div style={{
      width: size, height: size, flex: '0 0 auto', borderRadius: Math.min(8, size * 0.22),
      background: bg, color: fg, display: 'grid', placeItems: 'center',
      fontWeight: 800, fontSize: size * 0.42, letterSpacing: 0,
      boxShadow: `inset 0 0 0 1px color-mix(in srgb, ${mid} 22%, transparent)`,
      fontFamily: 'var(--font-ui)', userSelect: 'none',
    }}>{initial}</div>
  );
}

/* ───────────────────────── Icons (1.6 stroke, inherit color) ───────────── */
const I = {
  search: 'M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14zM20 20l-3.5-3.5',
  plus: 'M12 5v14M5 12h14',
  copy: 'M9 9h9v9a2 2 0 0 1-2 2H9a2 2 0 0 1-2-2V9zM7 15H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h7a2 2 0 0 1 2 2v1',
  check: 'M4 12.5 9 17.5 20 6.5',
  star: 'M12 3.6l2.5 5.2 5.7.8-4.1 4 1 5.7-5.1-2.7-5.1 2.7 1-5.7-4.1-4 5.7-.8z',
  drag: 'M9 6h.01M15 6h.01M9 12h.01M15 12h.01M9 18h.01M15 18h.01',
  kebab: 'M12 5h.01M12 12h.01M12 19h.01',
  x: 'M6 6l12 12M18 6L6 18',
  lock: 'M6 10V8a6 6 0 1 1 12 0v2M5 10h14a1 1 0 0 1 1 1v8a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1v-8a1 1 0 0 1 1-1z',
  eye: 'M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12zM12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z',
  eyeOff: 'M3 3l18 18M10.6 10.6a3 3 0 0 0 4 4M9.4 5.2A9.8 9.8 0 0 1 12 5c6.5 0 10 7 10 7a16 16 0 0 1-3.3 4M6.2 6.3A16 16 0 0 0 2 12s3.5 7 10 7a9.7 9.7 0 0 0 3-.5',
  arrow: 'M5 12h14M13 6l6 6-6 6',
  trash: 'M4 7h16M9 7V5a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2M6 7l1 13a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1l1-13',
  shield: 'M12 3l8 3v6c0 5-3.5 7.7-8 9-4.5-1.3-8-4-8-9V6l8-3z',
  key: 'M14 7a4 4 0 1 1-3.4 6.1L4 19.7 6.3 22M10.6 13.1L14 9.7',
  logout: 'M15 4h3a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-3M10 12h10M16 8l4 4-4 4',
  sun: 'M12 4V2.5M12 21.5V20M4 12H2.5M21.5 12H20M6 6L5 5M19 19l-1-1M6 18l-1 1M19 5l-1 1M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8z',
  moon: 'M20.5 14.5A8.5 8.5 0 1 1 9.5 3.5a6.6 6.6 0 0 0 11 11z',
  expand: 'M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5',
  download: 'M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3',
  upload: 'M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M17 8l-5-5-5 5M12 3v12',
};
function Icon({ d, size = 18, sw = 1.7, fill = 'none', style }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill={fill}
      stroke={fill === 'none' ? 'currentColor' : 'none'} strokeWidth={sw}
      strokeLinecap="round" strokeLinejoin="round" style={style} aria-hidden="true">
      {d.split('M').filter(Boolean).map((seg, i) => <path key={i} d={'M' + seg} />)}
    </svg>
  );
}

/* ───────────────────────── Brand mark ───────────────────────── */
function Logo({ size = 26 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" fill="none" aria-hidden="true">
      <circle cx="13" cy="13" r="8.2" stroke="var(--accent)" strokeWidth="2.4" />
      <path d="M18.8 18.8L26 26" stroke="var(--accent)" strokeWidth="2.4" strokeLinecap="round" />
      <circle cx="13" cy="13" r="2.6" fill="var(--accent)" />
    </svg>
  );
}

/* ───────────────────────── Countdown indicator ───────────────────────── */
function Countdown({ left, period = PERIOD, style, full = false }) {
  const frac = left / period;
  const warn = left <= 5;
  const color = warn ? 'var(--warn)' : 'var(--accent)';
  if (style === 'digits') {
    return (
      <span className="mono" style={{
        fontSize: 13, fontWeight: 600, color, minWidth: 26, textAlign: 'right',
      }}>{left}s</span>
    );
  }
  if (style === 'bar') {
    return (
      <div style={{ width: full ? '100%' : 30, height: 3, borderRadius: 2, background: 'var(--border)', overflow: 'hidden' }}>
        <div style={{
          height: '100%', width: `${frac * 100}%`, background: color, borderRadius: 2,
          transition: 'width 1s linear, background .3s',
        }} />
      </div>
    );
  }
  // ring (default)
  const r = 9, C = 2 * Math.PI * r;
  return (
    <svg width="24" height="24" viewBox="0 0 24 24" style={{ transform: 'rotate(-90deg)' }}>
      <circle cx="12" cy="12" r={r} fill="none" stroke="var(--code-bg)" strokeWidth="2.6" />
      <circle cx="12" cy="12" r={r} fill="none" stroke={color} strokeWidth="2.6"
        strokeLinecap="round" strokeDasharray={C}
        strokeDashoffset={C * (1 - frac)}
        style={{ transition: 'stroke-dashoffset 1s linear, stroke .3s' }} />
    </svg>
  );
}

/* ───────────────────────── Toast ───────────────────────── */
function useToast() {
  const [toast, setToast] = useState(null);
  const t = useRef(null);
  const show = useCallback((msg, kind = 'ok') => {
    setToast({ msg, kind, id: Date.now() });
    clearTimeout(t.current);
    t.current = setTimeout(() => setToast(null), 1900);
  }, []);
  return [toast, show];
}
function Toast({ toast }) {
  if (!toast) return null;
  return (
    <div key={toast.id} style={{
      position: 'absolute', left: '50%', bottom: 22, transform: 'translateX(-50%)',
      background: 'var(--text)', color: 'var(--surface)',
      padding: '10px 16px', borderRadius: 7, fontSize: 13.5, fontWeight: 600,
      display: 'flex', alignItems: 'center', gap: 9, whiteSpace: 'nowrap',
      boxShadow: '0 12px 30px -8px rgba(0,0,0,.5)', zIndex: 50, letterSpacing: '.01em',
    }}>
      <Icon d={I.check} size={15} sw={2.4} />
      {toast.msg}
    </div>
  );
}

/* ───────────────────────── Seed data ───────────────────────── */
// period: TOTP window in seconds (30 or 60). Different values = codes change
// at different times so the demo looks like a real running authenticator.
const SEED_ACCOUNTS = [
  { id: 'a1', issuer: 'GitHub',      account: 'euisuh',               seed: 'gh-7741-ej',  tone: 'slate',  fav: true,  period: 30 },
  { id: 'a2', issuer: 'Google',      account: 'euisuh@gmail.com',     seed: 'go-2210-ej',  tone: 'blue',   fav: true,  period: 30 },
  { id: 'a3', issuer: 'AWS',         account: 'root · us-east-1',     seed: 'aws-9920-ej', tone: 'amber',  fav: false, period: 30 },
  { id: 'a4', issuer: 'Cloudflare',  account: 'euisuh@cloudflare',    seed: 'cf-5512-ej',  tone: 'amber',  fav: false, period: 60 },
  { id: 'a5', issuer: 'Notion',      account: 'euisuh@notion',        seed: 'no-6634-ej',  tone: 'slate',  fav: false, period: 60 },
  { id: 'a6', issuer: 'Vercel',      account: 'euisuh.jeong',         seed: 'vc-1180-ej',  tone: 'slate',  fav: false, period: 30 },
  { id: 'a7', issuer: 'Anthropic',   account: 'euisuh@anthropic.com', seed: 'an-8821-ej',  tone: 'rose',   fav: true,  period: 30 },
  { id: 'a8', issuer: 'Discord',     account: 'euisuh#0001',          seed: 'dc-3098-ej',  tone: 'violet', fav: false, period: 30 },
  { id: 'a9', issuer: 'Hugging Face','account': 'euisuh',             seed: 'hf-4417-ej',  tone: 'amber',  fav: false, period: 60 },
];

const SEED_BACKUP = [
  { id: 'b1', issuer: 'GitHub',  tone: 'slate',  codes: ['8f2k-91xa', 'q7w3-44mn', '0ab1-77cd', 'zz29-1k4p', 'm5n6-8b2v', '7h3j-90lo'], used: [1] },
  { id: 'b2', issuer: 'Google',  tone: 'blue',   codes: ['4471 2290', '8830 1142', '9921 5567', '0034 8891', '7712 3340'], used: [] },
  { id: 'b3', issuer: 'Anthropic', tone: 'rose', codes: ['anth-a91k', 'anth-77zz', 'anth-3m4n', 'anth-8b0c', 'anth-2z9q'], used: [0] },
];

Object.assign(window, {
  hashCode, realTotp, isBase32, nowStep, secondsLeft, fmtCode, useClock, PERIOD,
  b64enc, b64dec, deriveKey, encryptVault, decryptVault,
  Tile, Icon, I, Logo, Countdown, useToast, Toast, autoTone,
  TILE_PRESETS, SEED_ACCOUNTS, SEED_BACKUP,
});
