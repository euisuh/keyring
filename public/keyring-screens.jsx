// screens.jsx — Vault, Add-account modal
const { useState: uS, useEffect: uE, useRef: uR, useMemo: uM } = React;

/* ═══════════════════════════ ACCOUNT ROW ═══════════════════════════ */
function AccountRow({ acc, compact, onCopy, onFav, onEdit, onDelete,
  dragHandlers, dragging, dropTarget, stepFor, leftFor }) {
  const period = acc.period || 30;
  const step = stepFor(period);
  const left = leftFor(period);

  // Real TOTP for base32 secrets; deterministic hash for demo seeds
  const [code, setCode] = uS(fmtCode(hashCode(acc.seed, step)));
  uE(() => {
    if (isBase32(acc.seed)) {
      realTotp(acc.seed, step).then((c) => setCode(fmtCode(c))).catch(() => setCode(fmtCode(hashCode(acc.seed, step))));
    } else {
      setCode(fmtCode(hashCode(acc.seed, step)));
    }
  }, [acc.seed, step]);

  const warn = left <= 5;
  const [flash, setFlash] = uS(false);

  const tap = () => {
    const raw = code.replace(/\s/g, '');
    navigator.clipboard?.writeText(raw).catch(() => {});
    setFlash(true); setTimeout(() => setFlash(false), 320);
    onCopy(acc.issuer, raw);
  };

  return (
    <div
      draggable
      onDragStart={(e) => dragHandlers.start(e, acc.id)}
      onDragOver={(e) => dragHandlers.over(e, acc.id)}
      onDrop={(e) => dragHandlers.drop(e, acc.id)}
      onDragEnd={dragHandlers.end}
      style={{
        width: '100%', minWidth: 0,
        display: 'flex', alignItems: 'center', gap: compact ? 7 : 10,
        padding: compact ? '9px 8px 9px 6px' : 'var(--row-pad)',
        paddingLeft: 10,
        borderRadius: 8, background: dropTarget ? 'var(--accent-soft)' : 'transparent',
        opacity: dragging ? 0.35 : 1, position: 'relative', cursor: 'grab',
        zIndex: dropTarget ? 2 : 'auto',
        transition: 'background .12s',
      }}
      className="acc-row">
      <Tile label={acc.issuer} tone={acc.tone} size={compact ? 32 : 38} />

      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
          <span style={{ fontSize: compact ? 14 : 15, fontWeight: 700, letterSpacing: 0, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{acc.issuer}</span>
          {acc.fav && <Icon d={I.star} size={12} fill="var(--accent)" style={{ flex: '0 0 auto' }} />}
        </div>
        <div style={{ fontSize: 12.5, color: 'var(--text-2)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', marginTop: 1 }}>{acc.account}</div>
      </div>

      {/* code (tap to copy) */}
      <button onClick={tap} title="Tap to copy" style={{
        display: 'flex', flexDirection: 'column', alignItems: 'stretch', gap: compact ? 4 : 5,
        border: 'none', flex: '0 0 auto',
        background: flash ? 'var(--accent-soft)' : 'var(--code-bg)',
        padding: compact ? '2px 7px' : '3px 10px', borderRadius: 7, transition: 'background .15s',
      }}>
        <span className="mono" style={{
          fontSize: compact ? 14.5 : 19, fontWeight: 600, letterSpacing: '.08em', whiteSpace: 'nowrap',
          color: warn ? 'var(--warn)' : 'var(--text)', transition: 'color .3s',
        }}>{code}</span>
        <Countdown left={left} period={period} style="bar" full />
      </button>

      {/* row menu */}
      <RowMenu acc={acc} compact={compact} onFav={onFav} onCopy={tap} onEdit={onEdit} onDelete={onDelete} />
    </div>
  );
}
function RowMenu({ acc, compact, onFav, onCopy, onEdit, onDelete }) {
  const [open, setOpen] = uS(false);
  const ref = uR(null);
  uE(() => {
    if (!open) return;
    const h = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener('mousedown', h);
    return () => document.removeEventListener('mousedown', h);
  }, [open]);
  const item = (icon, label, onClick, danger, fill) => (
    <button onClick={() => { onClick(); setOpen(false); }} style={{
      width: '100%', display: 'flex', alignItems: 'center', gap: 9, padding: '8px 10px',
      border: 'none', background: 'transparent', borderRadius: 8, fontFamily: 'var(--font-ui)',
      fontSize: 13, fontWeight: 600, color: danger ? 'var(--warn)' : 'var(--text)', whiteSpace: 'nowrap',
    }}
      onMouseEnter={(e) => e.currentTarget.style.background = 'var(--hover)'}
      onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}>
      <Icon d={icon} size={15} fill={fill ? (danger ? 'var(--warn)' : 'var(--accent)') : 'none'} /> {label}
    </button>
  );
  return (
    <div ref={ref} style={{ position: 'relative', flex: '0 0 auto', zIndex: open ? 120 : 1 }}>
      <button onClick={() => setOpen((o) => !o)} title="More" style={{
        width: compact ? 26 : 30, height: compact ? 26 : 30, border: 'none', borderRadius: 7, display: 'grid', placeItems: 'center',
        background: open ? 'var(--press)' : 'transparent', color: 'var(--text-3)',
      }}
        onMouseEnter={(e) => { if (!open) e.currentTarget.style.background = 'var(--hover)'; }}
        onMouseLeave={(e) => { if (!open) e.currentTarget.style.background = 'transparent'; }}>
        <Icon d={I.kebab} size={18} sw={2.4} />
      </button>
      {open && (
        <div style={{
          position: 'absolute', right: 0, top: 34, width: 168, background: 'var(--surface)',
          border: '1px solid var(--border)', borderRadius: 8, boxShadow: 'var(--shadow)',
          backdropFilter: 'blur(16px) saturate(150%)', WebkitBackdropFilter: 'blur(16px) saturate(150%)',
          zIndex: 130, padding: 6,
        }}>
          {item(I.copy, 'Copy code', onCopy)}
          {item(I.key, 'Edit secret', () => onEdit(acc))}
          {item(I.star, acc.fav ? 'Unfavorite' : 'Favorite', () => onFav(acc.id), false, acc.fav)}
          {item(I.trash, 'Remove account', () => onDelete(acc.id), true)}
        </div>
      )}
    </div>
  );
}

/* ═══════════════════════════ BACKUP CARD ═══════════════════════════ */
function BackupCard({ b, onCopy, onToggleUsed }) {
  const [open, setOpen] = uS(true);
  const used = b.used || [];
  const remaining = b.codes.length - used.length;
  return (
    <div style={{ border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden', background: 'var(--surface)' }}>
      <button onClick={() => setOpen((o) => !o)} style={{
        width: '100%', display: 'flex', alignItems: 'center', gap: 12, padding: 13,
        border: 'none', background: 'transparent', textAlign: 'left',
      }}>
        <Tile label={b.issuer} tone={b.tone} size={36} />
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: 15, fontWeight: 700, letterSpacing: 0 }}>{b.issuer}</div>
          <div style={{ fontSize: 12.5, color: 'var(--text-2)', marginTop: 1 }}>{remaining} of {b.codes.length} recovery codes left</div>
        </div>
        <Icon d={I.arrow} size={17} style={{ color: 'var(--text-3)', transform: open ? 'rotate(90deg)' : 'rotate(0)', transition: 'transform .2s' }} />
      </button>
      {open && (
        <div style={{ padding: '2px 13px 13px', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 7 }}>
          {b.codes.map((c, i) => {
            const used = (b.used || []).includes(i);
            return (
              <button key={i} onClick={() => { if (used) { onToggleUsed(b.id, i); return; } navigator.clipboard?.writeText(c).catch(() => {}); onCopy(b.issuer, c); onToggleUsed(b.id, i); }}
                title={used ? 'Mark unused' : 'Copy & mark used'}
                className="mono" style={{
                  display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8,
                  padding: '9px 11px', borderRadius: 7, border: '1px solid var(--border-2)',
                  background: used ? 'transparent' : 'var(--code-bg)', fontSize: 13.5, fontWeight: 600,
                  color: used ? 'var(--text-3)' : 'var(--text)',
                  textDecoration: used ? 'line-through' : 'none',
                }}>
                {c}
                {!used && <Icon d={I.copy} size={13} style={{ color: 'var(--text-3)' }} />}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

/* ═══════════════════════════ ADD / EDIT SHEET ═══════════════════════════ */
function AddModal({ onClose, onSave, initial }) {
  const editing = !!initial;
  const [issuer, setIssuer] = uS(initial?.issuer || '');
  const [account, setAccount] = uS(initial && initial.account !== '—' ? initial.account : '');
  const [secret, setSecret] = uS(initial?.seed || '');
  const [reveal, setReveal] = uS(!editing);
  const [err, setErr] = uS('');

  const save = () => {
    if (!issuer.trim()) { setErr('Service name is required.'); return; }
    if (secret.replace(/\s/g, '').length < 6) { setErr('Enter a valid secret key (the long code from the QR setup).'); return; }
    onSave({
      id: initial?.id || 'a' + Date.now(),
      issuer: issuer.trim(),
      account: account.trim() || '—',
      seed: secret.replace(/\s/g, ''),
      tone: initial?.tone || autoTone((initial?.issuer || issuer).trim()),
      fav: initial?.fav || false,
    });
  };
  const field = {
    width: '100%', height: 46, padding: '0 13px', fontSize: 14.5, fontFamily: 'var(--font-ui)',
    color: 'var(--text)', background: 'var(--surface-2)', border: '1px solid var(--border)',
    borderRadius: 7, outline: 'none',
  };
  const focus = (e) => { e.target.style.borderColor = 'var(--accent)'; e.target.style.boxShadow = '0 0 0 3px var(--accent-soft)'; };
  const blur = (e) => { e.target.style.borderColor = 'var(--border)'; e.target.style.boxShadow = 'none'; };

  return (
    <div onClick={onClose} style={{
      position: 'absolute', inset: 0, background: 'rgba(10,10,12,.45)', backdropFilter: 'blur(3px)',
      display: 'flex', alignItems: 'flex-end', justifyContent: 'center', zIndex: 200,
    }}>
      <div onClick={(e) => e.stopPropagation()} style={{
        width: '100%', background: 'var(--surface)', borderRadius: '12px 12px 0 0',
        padding: '8px 22px 24px',
        borderTop: '1px solid var(--border)',
      }}>
        <div style={{ width: 38, height: 4, background: 'var(--border)', borderRadius: 4, margin: '6px auto 16px' }} />
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 18 }}>
          <h2 style={{ fontSize: 19, fontWeight: 800, letterSpacing: 0, margin: 0, whiteSpace: 'nowrap' }}>{editing ? 'Edit account' : 'Add account'}</h2>
          <button onClick={onClose} style={{ width: 32, height: 32, border: 'none', background: 'var(--surface-2)', borderRadius: 7, display: 'grid', placeItems: 'center', color: 'var(--text-2)' }}>
            <Icon d={I.x} size={17} />
          </button>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 13 }}>
          <Field label="Service" hint="e.g. GitHub, Notion">
            <input style={field} value={issuer} placeholder="Service name" onFocus={focus} onBlur={blur}
              onChange={(e) => { setIssuer(e.target.value); setErr(''); }} />
          </Field>
          <Field label="Account" hint="optional">
            <input style={field} value={account} placeholder="you@email.com" onFocus={focus} onBlur={blur}
              onChange={(e) => setAccount(e.target.value)} />
          </Field>
          <Field label="Secret key" hint="from the QR setup screen">
            <div style={{ position: 'relative' }}>
              <input style={{ ...field, paddingRight: 44, fontFamily: 'var(--font-mono)', letterSpacing: '.05em',
                WebkitTextSecurity: reveal ? 'none' : 'disc' }} value={secret} type="text"
                placeholder="JBSW Y3DP EHPK 3PXP" onFocus={focus} onBlur={blur}
                onChange={(e) => { setSecret(e.target.value); setErr(''); }} />
              <button type="button" onClick={() => setReveal((s) => !s)} aria-label="Toggle secret"
                style={{ position: 'absolute', right: 5, top: 5, width: 36, height: 36, border: 'none', background: 'transparent', color: 'var(--text-3)', borderRadius: 7, display: 'grid', placeItems: 'center' }}>
                <Icon d={reveal ? I.eyeOff : I.eye} size={18} />
              </button>
            </div>
          </Field>

          {err && <div style={{ fontSize: 13, color: 'var(--warn)', fontWeight: 600 }}>{err}</div>}

          <button onClick={save} style={{
            height: 48, marginTop: 4, border: 'none', borderRadius: 7, background: 'var(--accent)',
            color: 'var(--bg)', fontSize: 15.5, fontWeight: 700, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8, whiteSpace: 'nowrap',
          }}>
            <Icon d={editing ? I.check : I.plus} size={18} sw={2.2} /> {editing ? 'Save changes' : 'Add to vault'}
          </button>
        </div>
      </div>
    </div>
  );
}
function Field({ label, hint, children }) {
  return (
    <label style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
      <span style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--text-2)' }}>
        {label}{hint && <span style={{ color: 'var(--text-3)', fontWeight: 500 }}> · {hint}</span>}
      </span>
      {children}
    </label>
  );
}

/* ═══════════════════════════ ADD BACKUP SHEET ═══════════════════════════ */
function AddBackupModal({ onClose, onSave }) {
  const [issuer, setIssuer] = uS('');
  const [raw, setRaw] = uS('');
  const [err, setErr] = uS('');

  const save = () => {
    if (!issuer.trim()) { setErr('Service name is required.'); return; }
    const codes = raw.split('\n').map((c) => c.trim()).filter(Boolean);
    if (codes.length < 1) { setErr('Enter at least one recovery code.'); return; }
    onSave({ id: 'b' + Date.now(), issuer: issuer.trim(), tone: autoTone(issuer.trim()), codes, used: [] });
  };
  const field = {
    width: '100%', padding: '10px 13px', fontSize: 14.5, fontFamily: 'var(--font-ui)',
    color: 'var(--text)', background: 'var(--surface-2)', border: '1px solid var(--border)',
    borderRadius: 7, outline: 'none',
  };
  const focus = (e) => { e.target.style.borderColor = 'var(--accent)'; e.target.style.boxShadow = '0 0 0 3px var(--accent-soft)'; };
  const blur = (e) => { e.target.style.borderColor = 'var(--border)'; e.target.style.boxShadow = 'none'; };

  return (
    <div onClick={onClose} style={{
      position: 'absolute', inset: 0, background: 'rgba(10,10,12,.45)', backdropFilter: 'blur(3px)',
      display: 'flex', alignItems: 'flex-end', justifyContent: 'center', zIndex: 200,
    }}>
      <div onClick={(e) => e.stopPropagation()} style={{
        width: '100%', background: 'var(--surface)', borderRadius: '12px 12px 0 0',
        padding: '8px 22px 24px', borderTop: '1px solid var(--border)',
      }}>
        <div style={{ width: 38, height: 4, background: 'var(--border)', borderRadius: 4, margin: '6px auto 16px' }} />
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 18 }}>
          <h2 style={{ fontSize: 19, fontWeight: 800, letterSpacing: 0, margin: 0 }}>Add backup codes</h2>
          <button onClick={onClose} style={{ width: 32, height: 32, border: 'none', background: 'var(--surface-2)', borderRadius: 7, display: 'grid', placeItems: 'center', color: 'var(--text-2)' }}>
            <Icon d={I.x} size={17} />
          </button>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 13 }}>
          <Field label="Service" hint="e.g. GitHub, Google">
            <input style={{ ...field, height: 46 }} value={issuer} placeholder="Service name" onFocus={focus} onBlur={blur}
              onChange={(e) => { setIssuer(e.target.value); setErr(''); }} />
          </Field>
          <Field label="Recovery codes" hint="one per line">
            <textarea style={{ ...field, height: 140, resize: 'vertical', fontFamily: 'var(--font-mono)', fontSize: 13, letterSpacing: '.04em', lineHeight: 1.7 }}
              value={raw} placeholder={'8f2k-91xa\nq7w3-44mn\n0ab1-77cd'} onFocus={focus} onBlur={blur}
              onChange={(e) => { setRaw(e.target.value); setErr(''); }} />
          </Field>
          {err && <div style={{ fontSize: 13, color: 'var(--warn)', fontWeight: 600 }}>{err}</div>}
          <button onClick={save} style={{
            height: 48, marginTop: 4, border: 'none', borderRadius: 7, background: 'var(--accent)',
            color: 'var(--bg)', fontSize: 15.5, fontWeight: 700, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
          }}>
            <Icon d={I.plus} size={18} sw={2.2} /> Add to vault
          </button>
        </div>
      </div>
    </div>
  );
}

Object.assign(window, { AccountRow, BackupCard, AddModal, AddBackupModal });
