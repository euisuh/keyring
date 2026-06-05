// credential-app.jsx — per-service authentication gate
const { useState, useEffect, useRef, useCallback } = React;

/* ───────── URL params ───────── */
const PARAMS  = new URLSearchParams(location.search);
const SVC_ID  = PARAMS.get('service') || '';
const NEXT_PATH = PARAMS.get('next') || '';

function safeNextPath(fallback) {
  if (NEXT_PATH.startsWith('/') && !NEXT_PATH.startsWith('//')) return NEXT_PATH;
  return fallback;
}

/* ───────── service registry ───────── */
const SERVICES = {
  otp: {
    name: 'Keyring',
    kind: '2FA · OTP vault',
    glyph: 'OTP',
    tone: '#7dd3fc',
    headline: <>Unlock your <span className="accent">vault</span>.</>,
    sub: <>access your<span className="ser"> one-time codes</span>.</>,
    lede: <>Your OTP vault stays local. Enter your <b>keyring credentials</b> to unlock your saved codes on this device.</>,
    guestLabel: 'EXPLORE DEMO VAULT',
    guestHint: 'Guest mode loads sample accounts. No real codes are shown.',
    onAuth: () => {},
    onGuest: () => {
      try { localStorage.removeItem('kr_user'); } catch (e) {}
    },
    redirect: async (auth, qs, id, pw) => {
      if (auth) {
        let res;
        try {
          res = await fetch('/keyring/api/auth', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id, password: pw }),
          });
        } catch (e) {
          return 'Could not reach auth server. Try again.';
        }
        if (!res.ok) return 'Incorrect username or password.';
        try { sessionStorage.setItem('kr_pending_auth', JSON.stringify({ email: id, pw })); } catch (e) {}
        location.href = '/keyring/';
      } else {
        location.href = '/keyring/?demo=1';
      }
    },
  },
};

const FALLBACK = {
  name: 'Tool',
  kind: 'Private',
  glyph: '···',
  tone: 'var(--accent)',
  headline: <>Authenticate<span className="accent">.</span></>,
  sub: <>verify your<span className="ser"> identity</span>.</>,
  lede: <><b>Any email and password</b> grants access on this device.</>,
  guestLabel: 'CONTINUE AS GUEST',
  guestHint: 'Guest mode provides limited access.',
  onAuth: () => {},
  onGuest: () => {},
  redirect: (_auth, _qs) => { location.href = '/'; },
};

const SVC = SERVICES[SVC_ID] || FALLBACK;

/* ───────── icons ───────── */
function Ico({ d, size = 16, sw = 1.7, style }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth={sw} strokeLinecap="round" strokeLinejoin="round" style={style} aria-hidden="true">
      {d.split('|').map((p, i) => <path key={i} d={p} />)}
    </svg>
  );
}
const IC = {
  arrow:  'M5 12h14|M13 6l6 6-6 6',
  eye:    'M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z|M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z',
  eyeOff: 'M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94|M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19|M1 1l22 22',
  shield: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z',
  sun:    'M12 4V2|M12 22v-2|M4 12H2|M22 12h-2|M5 5l-1.4-1.4|M20.4 20.4 19 19|M5 19l-1.4 1.4|M20.4 3.6 19 5|M12 16a4 4 0 1 0 0-8 4 4 0 0 0 0 8z',
  moon:   'M21 12.8A8.6 8.6 0 1 1 11.2 3 6.7 6.7 0 0 0 21 12.8z',
};

function useClock() {
  const [t, setT] = useState('');
  useEffect(() => {
    const fmt = () => {
      const d = new Date();
      const kst = d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', hour12: false, timeZone: 'Asia/Seoul' });
      const utc = d.toLocaleTimeString('en-GB', { hour12: false, timeZone: 'UTC' });
      setT(`${kst} KST · ${utc} UTC`);
    };
    fmt();
    const id = setInterval(fmt, 1000);
    return () => clearInterval(id);
  }, []);
  return t;
}

function App() {
  const [theme, setTheme] = useState(() => {
    try { return localStorage.getItem('ej_theme') || 'dark'; } catch (e) { return 'dark'; }
  });
  const accent = '#7dd3fc';

  const [identifier, setIdentifier] = useState('');
  const [pw, setPw] = useState('');
  const [show, setShow] = useState(false);
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const [shown, setShown] = useState(false);
  useEffect(() => { const id = requestAnimationFrame(() => setShown(true)); return () => cancelAnimationFrame(id); }, []);

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    document.documentElement.style.setProperty('--accent', accent);
    try { localStorage.setItem('ej_theme', theme); } catch (e) {}
  }, [theme, accent]);

  const clock = useClock();
  const toggleTheme = () => setTheme((t) => t === 'dark' ? 'light' : 'dark');
  const goConsole = useCallback(() => {
    location.href = '/';
  }, []);

  const buildQs = useCallback(() => {
    return new URLSearchParams();
  }, []);

  useEffect(() => {
    const isEditable = (el) => {
      if (!el) return false;
      const tag = el.tagName;
      return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || el.isContentEditable;
    };

    const onKey = (e) => {
      if (e.defaultPrevented || e.metaKey || e.ctrlKey || e.altKey) return;
      if (e.key === 'Escape') {
        e.preventDefault();
        goConsole();
        return;
      }
      if (e.key.toLowerCase() === 'c' && !isEditable(e.target)) {
        e.preventDefault();
        goConsole();
      }
    };

    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [goConsole]);

  const submit = async (e) => {
    e.preventDefault();
    const id = identifier.trim();
    if (!id || !pw) { setErr('Username and password required.'); return; }
    setErr(''); setBusy(true);
    const name = id.includes('@') ? id.split('@')[0] : id;
    const u = { name, email: id, guest: false };
    SVC.onAuth(u);
    const errMsg = await SVC.redirect(true, buildQs(), id, pw);
    if (errMsg) { setErr(errMsg); setBusy(false); }
  };

  const guest = async () => {
    SVC.onGuest();
    await SVC.redirect(false, buildQs(), '', '');
  };

  return (
    <>
      {/* topbar */}
      <div className="topbar">
        <div className="topbar-inner">
          <span className="dot"></span>
          <a className="brand" href="/">EUISUH.JEONG</a>
          <span className="spacer"></span>
          <a className="back-link" href="/">
            <Ico d={IC.arrow} size={13} sw={1.6} style={{ transform: 'rotate(180deg)' }} />
            keyring
          </a>
          <button className="theme-toggle" onClick={toggleTheme}
            title={theme === 'dark' ? 'Light mode' : 'Dark mode'}
            aria-label={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}>
            <Ico d={theme === 'dark' ? IC.sun : IC.moon} size={14} sw={1.6} />
          </button>
          <span className="clock">{clock}</span>
        </div>
      </div>

      {/* credential form */}
      <div className="cred-wrap" style={{
        opacity: shown ? 1 : 0,
        transform: shown ? 'none' : 'translateY(12px)',
        transition: 'opacity .5s ease, transform .5s ease',
      }}>
        <div className="cred-inner">
          {/* service badge */}
          <div className="svc-badge">
            <span className="svc-tile" style={{
              background: `color-mix(in oklab, ${SVC.tone} 18%, transparent)`,
              color: SVC.tone, border: `1px solid color-mix(in oklab, ${SVC.tone} 35%, transparent)`,
            }}>{SVC.glyph}</span>
            {SVC.name} · {SVC.kind}
          </div>

          {/* hero text */}
          <div className="kicker">operator access</div>
          <h1 className="cred-h1">{SVC.headline}<br />{SVC.sub}</h1>
          <p className="cred-lede">{SVC.lede}</p>

          {/* form */}
          <form onSubmit={submit} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <label style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
              <span className="cred-label">Username or Email</span>
              <input className="cred-input" type="text" value={identifier}
                placeholder="username or you@email.com" autoComplete="username"
                onChange={(e) => { setIdentifier(e.target.value); setErr(''); }} />
            </label>

            <label style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
              <span className="cred-label">Password</span>
              <div style={{ position: 'relative' }}>
                <input className="cred-input" style={{ paddingRight: 50 }}
                  type={show ? 'text' : 'password'} value={pw}
                  placeholder="••••••••" autoComplete="current-password"
                  onChange={(e) => { setPw(e.target.value); setErr(''); }} />
                <button type="button" onClick={() => setShow((s) => !s)}
                  aria-label="Toggle password" style={{
                    position: 'absolute', right: 6, top: 6,
                    width: 36, height: 36, border: 'none', background: 'transparent',
                    color: 'var(--text-dim)', borderRadius: 8, display: 'grid', placeItems: 'center',
                  }}>
                  <Ico d={show ? IC.eyeOff : IC.eye} size={17} />
                </button>
              </div>
            </label>

            {err && <div className="cred-err">⚠ {err}</div>}

            <button type="submit" className="cred-btn-primary" disabled={busy}>
              {busy
                ? 'AUTHENTICATING...'
                : <><span>UNLOCK {SVC.name.toUpperCase()}</span> <Ico d={IC.arrow} size={16} sw={2} /></>}
            </button>
          </form>

          {/* guest divider */}
          <div className="cred-divider"><span className="cred-or">OR</span></div>

          <button onClick={guest} className="cred-btn-ghost">
            <Ico d={IC.shield} size={16} /> {SVC.guestLabel}
          </button>

          <p className="cred-hint">{SVC.guestHint}</p>
        </div>
      </div>
    </>
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(<App />);
