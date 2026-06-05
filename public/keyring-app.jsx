// app.jsx — root: auth routing, vault, tweaks
const TWEAK_DEFAULTS = /*EDITMODE-BEGIN*/{
  "theme": "dark",
  "accent": "#7dd3fc",
  "density": "comfy",
  "layout": "full"
}/*EDITMODE-END*/;

function load(key, fallback) {
  try { const v = localStorage.getItem(key); return v ? JSON.parse(v) : fallback; }
  catch (e) { return fallback; }
}

// ── ?demo=1 means "opened without admin" → ephemeral guest session that never
//    touches the saved vault. Presentation state comes from local settings. ──
const KR_PARAMS = new URLSearchParams(location.search);
const KR_DEMO = KR_PARAMS.get('demo') === '1';
const KR_INIT_TWEAKS = (() => {
  const d = { ...TWEAK_DEFAULTS };
  try {
    const th = localStorage.getItem('ej_theme');
    if (th === 'light' || th === 'dark') d.theme = th;
  } catch (e) {}
  try {
    const saved = localStorage.getItem('kr_tweaks');
    if (saved) {
      const parsed = JSON.parse(saved);
      if (parsed.accent) d.accent = parsed.accent;
      if (parsed.density) d.density = parsed.density;
      if (parsed.layout) d.layout = parsed.layout;
    }
  } catch (e) {}
  return d;
})();
const GUEST = { name: 'Guest', email: 'guest@demo', guest: true };

function keyringCredentialRedirect() {
  location.replace('/credential?service=otp');
}

function App() {
  const [t, setTweak] = useTweaks(KR_INIT_TWEAKS);
  const [mobile, setMobile] = React.useState(() => window.innerWidth <= 520);
  React.useEffect(() => {
    const fn = () => setMobile(window.innerWidth <= 520);
    window.addEventListener('resize', fn);
    return () => window.removeEventListener('resize', fn);
  }, []);
  const masterKey = React.useRef(null);
  const vaultLoaded = React.useRef(false);
  const importRef = React.useRef(null);
  const [user, setUser] = React.useState(KR_DEMO ? GUEST : null);
  const [authReady, setAuthReady] = React.useState(KR_DEMO);
  const [tab, setTab] = React.useState('auth');
  const [query, setQuery] = React.useState('');
  const [accounts, setAccounts] = React.useState(KR_DEMO ? SEED_ACCOUNTS : []);
  const [backups, setBackups] = React.useState(KR_DEMO ? SEED_BACKUP : []);
  const [adding, setAdding] = React.useState(false);
  const [addingBackup, setAddingBackup] = React.useState(false);
  const [editing, setEditing] = React.useState(null);
  const [toast, showToast] = useToast();
  const { step, left, stepFor, leftFor } = useClock(!!user);

  // ── encrypted vault persist ──
  React.useEffect(() => {
    if (!vaultLoaded.current || KR_DEMO || !masterKey.current) return;
    encryptVault({ accounts, backups }, masterKey.current)
      .then((b64) => localStorage.setItem('kr_vault', b64))
      .catch(() => showToast('Failed to save vault'));
  }, [accounts, backups]); // eslint-disable-line react-hooks/exhaustive-deps

  // ── login / auth ──
  const handleLogin = async (email, pw) => {
    let saltB64 = localStorage.getItem('kr_salt');
    let salt;
    if (saltB64) {
      salt = b64dec(saltB64);
    } else {
      salt = crypto.getRandomValues(new Uint8Array(16));
      localStorage.setItem('kr_salt', b64enc(salt));
    }
    const key = await deriveKey(pw, salt);
    const vaultB64 = localStorage.getItem('kr_vault');
    let initAccounts = [], initBackups = [];
    let legacyMigration = false;
    if (vaultB64) {
      let decrypted;
      try { decrypted = await decryptVault(vaultB64, key); }
      catch { throw new Error('Wrong password'); }
      initAccounts = decrypted.accounts || [];
      initBackups = decrypted.backups || [];
    } else {
      const legacy = load('kr_accounts', null);
      if (legacy) {
        initAccounts = legacy;
        initBackups = load('kr_backups', []);
        legacyMigration = true;
      }
    }
    // persist vault BEFORE committing any state — if this throws, nothing is mutated
    let b64;
    try { b64 = await encryptVault({ accounts: initAccounts, backups: initBackups }, key); }
    catch { throw new Error('Failed to save vault. Please try again.'); }
    localStorage.setItem('kr_vault', b64);
    if (legacyMigration) {
      localStorage.removeItem('kr_accounts');
      localStorage.removeItem('kr_backups');
    }
    masterKey.current = key;
    vaultLoaded.current = true;
    setAccounts(initAccounts);
    setBackups(initBackups);
    setUser({ name: email.split('@')[0] || 'You', email, guest: false });
  };

  const handleGuestLogin = () => {
    vaultLoaded.current = false;
    setUser(GUEST);
    setAccounts(SEED_ACCOUNTS);
    setBackups(SEED_BACKUP);
  };

  const handleSignOut = () => {
    masterKey.current = null;
    vaultLoaded.current = false;
    location.replace('/credential?service=otp');
  };

  // ── auto-login from credential.html sessionStorage handoff ──
  React.useEffect(() => {
    if (KR_DEMO) return;
    const raw = sessionStorage.getItem('kr_pending_auth');
    if (!raw) { location.replace('/credential?service=otp'); return; }
    sessionStorage.removeItem('kr_pending_auth');
    let parsed;
    try { parsed = JSON.parse(raw); } catch { location.replace('/credential?service=otp'); return; }
    handleLogin(parsed.email, parsed.pw)
      .then(() => setAuthReady(true))
      .catch(() => location.replace('/credential?service=otp'));
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // ── export / import ──
  const exportVault = () => {
    const data = { version: 1, exportedAt: new Date().toISOString(), accounts, backups };
    const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
    const a = document.createElement('a');
    a.href = url; a.download = `keyring-${new Date().toISOString().slice(0, 10)}.json`; a.click();
    URL.revokeObjectURL(url);
    showToast('Vault exported');
  };
  const handleImportFile = (e) => {
    const file = e.target.files?.[0]; if (!file) return;
    const input = e.target; // capture before FileReader async callback
    const reader = new FileReader();
    reader.onload = (ev) => {
      try {
        const data = JSON.parse(ev.target.result);
        if (!Array.isArray(data.accounts)) throw new Error();
        const accs = data.accounts;
        const bkps = Array.isArray(data.backups)
          ? data.backups.map((b) => ({ ...b, used: Array.isArray(b.used) ? b.used : [] }))
          : [];
        if (window.confirm(`Import ${accs.length} accounts? This replaces your current vault.`)) {
          setAccounts(accs);
          setBackups(bkps);
          showToast(`Imported ${accs.length} accounts`);
        }
      } catch { showToast('Invalid export file'); }
      input.value = '';
    };
    reader.readAsText(file);
  };

  // apply theme + accent + density to :root; sync theme to shared key
  React.useEffect(() => {
    const r = document.documentElement;
    r.setAttribute('data-theme', t.theme);
    r.style.setProperty('--accent', t.accent);
    r.style.setProperty('--accent-soft', `color-mix(in oklab, ${t.accent} 14%, transparent)`);
    r.style.setProperty('--row-pad', t.density === 'compact' ? '8px 10px' : '13px 12px');
    try { localStorage.setItem('ej_theme', t.theme); } catch (e) {}
    try { localStorage.setItem('kr_tweaks', JSON.stringify({ accent: t.accent, density: t.density, layout: t.layout })); } catch (e) {}
  }, [t.theme, t.accent, t.density, t.layout]);

  const compact = t.density === 'compact' || mobile;
  const full = t.layout === 'full' && !mobile;
  const iconBtnSize = compact ? 34 : 38;
  const toggleTheme = () => setTweak('theme', t.theme === 'dark' ? 'light' : 'dark');

  // ── account actions ──
  const toggleFav = (id) => setAccounts((a) => a.map((x) => x.id === id ? { ...x, fav: !x.fav } : x));
  const delAcc = (id) => { setAccounts((a) => a.filter((x) => x.id !== id)); showToast('Account removed'); };
  const addAcc = (acc) => { setAccounts((a) => [acc, ...a]); setAdding(false); showToast(`${acc.issuer} added`); };
  const saveAcc = (acc) => { setAccounts((a) => a.map((x) => x.id === acc.id ? acc : x)); setEditing(null); showToast(`${acc.issuer} updated`); };
  const copyCode = (issuer, code) => showToast(`Copied · ${code}`);

  // backup
  const addBk = (bk) => { setBackups((bs) => [bk, ...bs]); setAddingBackup(false); showToast(`${bk.issuer} backup codes added`); };
  const toggleUsed = (bid, idx) => setBackups((bs) => bs.map((b) => b.id !== bid ? b : { ...b, used: b.used.includes(idx) ? b.used.filter((i) => i !== idx) : [...b.used, idx] }));

  // ── drag reorder ──
  const dragId = React.useRef(null);
  const [overId, setOverId] = React.useState(null);
  const dragHandlers = {
    start: (e, id) => { dragId.current = id; e.dataTransfer.effectAllowed = 'move'; },
    over: (e, id) => { e.preventDefault(); if (id !== overId) setOverId(id); },
    drop: (e, id) => {
      e.preventDefault();
      const from = dragId.current;
      if (!from || from === id) { setOverId(null); return; }
      setAccounts((arr) => {
        const a = [...arr];
        const fi = a.findIndex((x) => x.id === from);
        const ti = a.findIndex((x) => x.id === id);
        const [m] = a.splice(fi, 1); a.splice(ti, 0, m);
        return a;
      });
      setOverId(null); dragId.current = null;
    },
    end: () => { setOverId(null); dragId.current = null; },
  };

  // ── filtered + sorted list (favorites first, preserve order) ──
  const list = React.useMemo(() => {
    const q = query.trim().toLowerCase();
    const f = accounts.filter((a) => !q || a.issuer.toLowerCase().includes(q) || a.account.toLowerCase().includes(q));
    return [...f].sort((a, b) => (b.fav === a.fav) ? 0 : b.fav ? 1 : -1);
  }, [accounts, query]);

  const panel = (
    <TweaksPanel title="Tweaks">
      <TweakSection label="Appearance" />
      <TweakRadio label="Theme" value={t.theme} options={['light', 'dark']} onChange={(v) => setTweak('theme', v)} />
      <TweakColor label="Accent" value={t.accent}
        options={['#7dd3fc', '#84d8ff', '#c9b8ff', '#ffd479', '#ff9eb5']}
        onChange={(v) => setTweak('accent', v)} />
      <TweakSection label="Vault" />
      <TweakRadio label="Layout" value={t.layout} options={['compact', 'full']} onChange={(v) => setTweak('layout', v)} />
      <TweakRadio label="Density" value={t.density} options={['comfy', 'compact']} onChange={(v) => setTweak('density', v)} />
    </TweaksPanel>
  );

  if (!authReady || !user) return null;

  const padX = full ? 32 : 18;
  const themeBtn = (
    <button onClick={toggleTheme} title={t.theme === 'dark' ? 'Light mode' : 'Dark mode'} style={{
      width: iconBtnSize, height: iconBtnSize, border: '1px solid var(--border)', borderRadius: 7,
      background: 'var(--surface-2)', color: 'var(--text-2)', display: 'grid', placeItems: 'center',
    }}
      onMouseEnter={(e) => { e.currentTarget.style.background = 'var(--hover)'; e.currentTarget.style.color = 'var(--text)'; }}
      onMouseLeave={(e) => { e.currentTarget.style.background = 'var(--surface-2)'; e.currentTarget.style.color = 'var(--text-2)'; }}>
      <Icon d={t.theme === 'dark' ? I.sun : I.moon} size={18} />
    </button>
  );

  const Tabs = (
    <div style={{ display: 'flex', gap: 7 }}>
      {[['auth', compact ? 'OTP' : 'Authenticator', accounts.length], ['backup', compact ? 'Backup' : 'Backup codes', backups.length]].map(([k, lbl, n]) => (
        <button key={k} onClick={() => setTab(k)} style={{
          flex: full ? '0 0 auto' : 1, height: 38, padding: full ? '0 18px' : 0,
          border: '1px solid', borderColor: tab === k ? 'transparent' : 'var(--border)',
          borderRadius: 7, background: tab === k ? 'var(--accent)' : 'transparent',
          color: tab === k ? 'var(--bg)' : 'var(--text-2)', fontSize: 13.5, fontWeight: 700,
          display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 7, transition: 'all .15s', whiteSpace: 'nowrap',
        }}>
          {lbl}
          <span style={{ fontSize: 11.5, fontWeight: 700, padding: '1px 6px', borderRadius: 20,
            background: tab === k ? 'rgba(8,9,13,.16)' : 'var(--code-bg)', color: 'inherit' }}>{n}</span>
        </button>
      ))}
    </div>
  );

  const Search = (
    <div style={{ position: 'relative', width: '100%' }}>
      <span style={{ position: 'absolute', left: 12, top: 11, color: 'var(--text-3)' }}><Icon d={I.search} size={17} /></span>
      <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search accounts"
        style={{ width: '100%', height: 40, padding: '0 12px 0 38px', fontSize: 14, fontFamily: 'var(--font-ui)',
          color: 'var(--text)', background: 'var(--surface-2)', border: '1px solid var(--border)', borderRadius: 7, outline: 'none' }}
        onFocus={(e) => { e.target.style.borderColor = 'var(--accent)'; e.target.style.boxShadow = '0 0 0 3px var(--accent-soft)'; }}
        onBlur={(e) => { e.target.style.borderColor = 'var(--border)'; e.target.style.boxShadow = 'none'; }} />
      {query && <button onClick={() => setQuery('')} style={{ position: 'absolute', right: 8, top: 8, width: 24, height: 24, border: 'none', background: 'transparent', color: 'var(--text-3)', borderRadius: 7, display: 'grid', placeItems: 'center' }}><Icon d={I.x} size={15} /></button>}
    </div>
  );

  const gridStyle = { display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(380px, 1fr))', columnGap: 24, rowGap: compact ? 2 : 4, alignContent: 'start' };
  const colStyle = { display: 'flex', flexDirection: 'column', gap: compact ? 1 : 2 };
  const rows = list.map((acc) => (
    <AccountRow key={acc.id} acc={acc}
      compact={compact} onCopy={copyCode} onFav={toggleFav} onEdit={setEditing} onDelete={delAcc}
      dragHandlers={dragHandlers} dragging={dragId.current === acc.id} dropTarget={overId === acc.id && dragId.current !== acc.id}
      stepFor={stepFor} leftFor={leftFor} />
  ));

  return (
    <div className="app" style={full ? {
      width: 'min(1080px, 100%)', height: 'calc(100vh - 48px)', borderRadius: 12,
    } : undefined}>
      {/* header */}
      <header style={{ padding: full ? '22px 32px 16px' : '18px 18px 12px', display: 'flex', alignItems: 'center', gap: 11, borderBottom: '1px solid var(--border-2)' }}>
        <Logo size={full ? 28 : 26} />
        <span style={{ fontSize: full ? 20 : 18, fontWeight: 800, letterSpacing: '.01em' }}>Keyring</span>
        <div style={{ flex: 1 }} />
        {themeBtn}
        <button onClick={() => tab === 'backup' ? setAddingBackup(true) : setAdding(true)} title={tab === 'backup' ? 'Add backup codes' : 'Add account'} style={{
          width: iconBtnSize, height: iconBtnSize, border: 'none', borderRadius: 7, background: 'var(--accent)',
          color: 'var(--bg)', display: 'grid', placeItems: 'center',
        }}>
          <Icon d={I.plus} size={20} sw={2.2} />
        </button>
        <AccountMenu user={user} size={iconBtnSize} onSignOut={handleSignOut}
          onExport={user.guest ? null : exportVault}
          onImport={user.guest ? null : () => importRef.current?.click()} />
      </header>
      <input ref={importRef} type="file" accept=".json" style={{ display: 'none' }} onChange={handleImportFile} />

      {/* toolbar */}
      {full ? (
        <div style={{ padding: '20px 32px 8px', display: 'flex', alignItems: 'center', gap: 14, flexWrap: 'wrap' }}>
          {Tabs}
          {tab === 'auth' && <div style={{ flex: '1 1 220px', minWidth: 160, maxWidth: 360, marginLeft: 'auto' }}>{Search}</div>}
        </div>
      ) : (
        <>
          <div style={{ padding: '14px 18px 6px' }}>{Tabs}</div>
          {tab === 'auth' && <div style={{ padding: '8px 18px 4px' }}>{Search}</div>}
        </>
      )}

      {/* list */}
      <div className="scroll" style={{ flex: 1, padding: full ? `${tab === 'auth' ? 10 : 16}px ${padX}px 36px` : (tab === 'auth' ? '6px 12px 18px' : '10px 18px 18px') }}>
        {tab === 'auth' ? (
          list.length ? <div style={full ? gridStyle : colStyle}>{rows}</div> : <Empty query={query} />
        ) : (
          <>
            <div style={full
              ? { display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(360px, 1fr))', gap: 16, alignContent: 'start' }
              : { display: 'flex', flexDirection: 'column', gap: 10 }}>
              {backups.map((b) => <BackupCard key={b.id} b={b} onCopy={copyCode} onToggleUsed={toggleUsed} />)}
            </div>
            <p style={{ fontSize: 12, color: 'var(--text-3)', textAlign: 'center', lineHeight: 1.5, margin: `${full ? 20 : 12}px 0 0` }}>
              Recovery codes are single‑use. Tap one to copy it and mark it used.
            </p>
          </>
        )}
      </div>

      {adding && <AddModal onClose={() => setAdding(false)} onSave={addAcc} />}
      {addingBackup && <AddBackupModal onClose={() => setAddingBackup(false)} onSave={addBk} />}
      {editing && <AddModal onClose={() => setEditing(null)} onSave={saveAcc} initial={editing} />}
      <Toast toast={toast} />
      {panel}

      <style>{`
        .acc-row:hover{ background: var(--hover) !important; }
        .acc-row:hover .drag-h{ opacity:1; }
      `}</style>
    </div>
  );
}

function AccountMenu({ user, size = 38, onSignOut, onExport, onImport }) {
  const [open, setOpen] = React.useState(false);
  const ref = React.useRef(null);
  React.useEffect(() => {
    const h = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener('mousedown', h);
    return () => document.removeEventListener('mousedown', h);
  }, []);
  const initial = (user.name || '?')[0].toUpperCase();
  return (
    <div ref={ref} style={{ position: 'relative' }}>
      <button onClick={() => setOpen((o) => !o)} style={{
        width: size, height: size, border: '1px solid var(--border)', borderRadius: 7,
        background: 'var(--surface-2)', color: 'var(--text)', fontWeight: 800, fontSize: 15,
        display: 'grid', placeItems: 'center',
      }}>{initial}</button>
      {open && (
        <div style={{
          position: 'absolute', right: 0, top: 46, width: 210, background: 'var(--surface)',
          border: '1px solid var(--border)', borderRadius: 8, boxShadow: 'var(--shadow)', zIndex: 40,
          backdropFilter: 'blur(16px) saturate(150%)', WebkitBackdropFilter: 'blur(16px) saturate(150%)',
          padding: 7,
        }}>
          <div style={{ padding: '8px 10px 10px', borderBottom: '1px solid var(--border-2)', marginBottom: 5 }}>
            <div style={{ fontSize: 14, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 7 }}>
              {user.name}
              {user.guest && <span style={{ fontSize: 10.5, fontWeight: 700, padding: '2px 7px', borderRadius: 20, background: 'var(--accent-soft)', color: 'var(--accent)' }}>DEMO</span>}
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-2)', marginTop: 2 }}>{user.email}</div>
          </div>
          {onExport && onImport && <>
            {[
              [I.download, 'Export vault', () => { onExport(); setOpen(false); }],
              [I.upload,   'Import vault', () => { setOpen(false); setTimeout(() => onImport(), 50); }],
            ].map(([icon, label, fn]) => (
              <button key={label} onClick={fn} style={{
                width: '100%', display: 'flex', alignItems: 'center', gap: 9, padding: '9px 10px',
                border: 'none', background: 'transparent', borderRadius: 7, color: 'var(--text)',
                fontSize: 13.5, fontWeight: 600, fontFamily: 'var(--font-ui)',
              }}
                onMouseEnter={(e) => e.currentTarget.style.background = 'var(--hover)'}
                onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}>
                <Icon d={icon} size={17} /> {label}
              </button>
            ))}
            <div style={{ height: 1, background: 'var(--border-2)', margin: '4px 2px' }} />
          </>}
          <button onClick={onSignOut} style={{
            width: '100%', display: 'flex', alignItems: 'center', gap: 9, padding: '9px 10px',
            border: 'none', background: 'transparent', borderRadius: 7, color: 'var(--text)',
            fontSize: 13.5, fontWeight: 600, fontFamily: 'var(--font-ui)',
          }}
            onMouseEnter={(e) => e.currentTarget.style.background = 'var(--hover)'}
            onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}>
            <Icon d={I.logout} size={17} /> Sign out
          </button>
        </div>
      )}
    </div>
  );
}

function Empty({ query }) {
  return (
    <div style={{ textAlign: 'center', padding: '60px 30px', color: 'var(--text-3)' }}>
      <div style={{ width: 52, height: 52, margin: '0 auto 16px', borderRadius: 8, background: 'var(--surface-2)', display: 'grid', placeItems: 'center', color: 'var(--text-2)' }}>
        <Icon d={query ? I.search : I.key} size={24} />
      </div>
      <div style={{ fontSize: 15, fontWeight: 700, color: 'var(--text-2)' }}>{query ? 'No matches' : 'No accounts yet'}</div>
      <div style={{ fontSize: 13, marginTop: 4 }}>{query ? `Nothing matches “${query}”.` : 'Add your first account to get started.'}</div>
    </div>
  );
}

(function () {
  ReactDOM.createRoot(document.getElementById('root')).render(<App />);
})();
