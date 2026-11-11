import { useEffect, useRef, useState } from 'preact/hooks';
import { api, humanSize, countdown } from '../shared/api.js';

const TTL_OPTIONS = [
  [300, '5 minutes'],
  [900, '15 minutes'],
  [3600, '1 hour'],
  [21600, '6 hours'],
];

export function App() {
  const [state, setState] = useState(null);
  const [views, setViews] = useState({}); // token -> {url, qr}
  const [current, setCurrent] = useState(null); // token shown large
  const [ttl, setTtl] = useState(900);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [, tick] = useState(0);

  // Poll: cheap, and it is how "downloaded" shows up without a refresh.
  // Only a visible tab asks for the tunnel; a hidden one just watches.
  useEffect(() => {
    let alive = true;
    const load = () => api.state(document.visibilityState === 'visible')
      .then((s) => { if (alive) { setState(s); setError((e) => (e === OFFLINE ? '' : e)); } })
      .catch((e) => alive && setError(e instanceof TypeError ? OFFLINE : e.message));
    load();
    const id = setInterval(load, 2000);
    const t = setInterval(() => tick((n) => n + 1), 1000);
    document.addEventListener('visibilitychange', load);
    return () => {
      alive = false; clearInterval(id); clearInterval(t);
      document.removeEventListener('visibilitychange', load);
    };
  }, []);

  const tun = state?.tunnel;
  const tunnelUp = tun?.state === 'up';

  // (Re-)fetch QR views for active shares after a reload, and whenever the
  // tunnel came back under a new hostname (old links are dead then).
  useEffect(() => {
    if (!state) return;
    const base = tunnelUp ? tun.url : '';
    for (const s of state.shares) {
      const v = views[s.token];
      if (!s.downloaded && !s.expired && base && (!v || v.base !== base)) {
        api.get(s.token).then((nv) => setViews((o) => ({ ...o, [s.token]: nv }))).catch(() => {});
      }
    }
    if (!current && state.shares.length) setCurrent(state.shares[0].token);
  }, [state]);

  async function shareFiles(files) {
    setError('');
    setBusy(true);
    try {
      for (const f of files) {
        const v = await api.share(f, ttl);
        setViews((o) => ({ ...o, [v.token]: v }));
        setCurrent(v.token);
      }
      setState(await api.state());
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function renew(token) {
    setError('');
    try {
      const v = await api.renew(token);
      setViews((o) => { const n = { ...o }; delete n[token]; n[v.token] = v; return n; });
      setCurrent(v.token);
      setState(await api.state());
    } catch (e) {
      setError(e.message);
    }
  }

  async function remove(token) {
    setError('');
    try {
      await api.remove(token);
      setViews((o) => { const n = { ...o }; delete n[token]; return n; });
      if (current === token) setCurrent(null);
      setState(await api.state());
    } catch (e) {
      setError(e.message);
    }
  }

  const cur = state?.shares.find((s) => s.token === current);
  const v = current ? views[current] : null;
  const curView = v && tunnelUp && v.base === tun.url ? v : null;

  return (
    <div class="wrap">
      <header class="top">
        <h1>oncedrop</h1>
        <TunnelBadge tun={tun} />
      </header>

      {error && <p class="err">{error}</p>}

      <div class="grid">
        <div class="stack">
          <DropZone disabled={busy || !state} busy={busy} tunnelUp={tunnelUp} onFiles={shareFiles} maxSize={state?.maxSize} />
          <div class="card row between">
            <label class="row">
              <span class="muted small">Link lifetime</span>
              <select value={ttl} onChange={(e) => setTtl(Number(e.target.value))}>
                {TTL_OPTIONS.map(([v, l]) => <option value={v}>{l}</option>)}
              </select>
            </label>
            <span class="muted small">Each link works once.</span>
          </div>
          {state?.shares.length > 0 && (
            <div class="card">
              <div class="muted small" style="margin-bottom:8px">Shares</div>
              <div class="list">
                {state.shares.map((s) => (
                  <ShareItem s={s} active={s.token === current}
                    onSelect={() => setCurrent(s.token)}
                    onRenew={() => renew(s.token)}
                    onRemove={() => remove(s.token)} />
                ))}
              </div>
            </div>
          )}
        </div>

        <div class="card">
          {!cur && <p class="muted center">Drop a file and its QR code will appear here.</p>}
          {cur && (
            <div class="stack">
              <div class="row between">
                <strong style="overflow:hidden;text-overflow:ellipsis">{cur.name}</strong>
                <span class="muted small">{humanSize(cur.size)}</span>
              </div>
              <Status s={cur} />
              {!cur.downloaded && !cur.expired && !curView && (
                <p class="muted center">Connecting to the tunnel, the QR code will appear shortly…</p>
              )}
              {!cur.downloaded && !cur.expired && curView && (
                <>
                  <img class="qr" src={curView.qr} alt="QR" />
                  <div class="row between">
                    <span class="muted small">Scan with your phone. The key is in the <kbd>#</kbd> part of the address and never goes through the tunnel.</span>
                  </div>
                  <div class="row">
                    <input class="mono" readOnly value={curView.url} style="flex:1;min-width:0;padding:6px 8px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--ink)" onFocus={(e) => e.target.select()} />
                    <button onClick={() => navigator.clipboard?.writeText(curView.url)}>Copy</button>
                  </div>
                </>
              )}
              {(cur.downloaded || cur.expired) && (
                <div class="row">
                  <button class="primary" onClick={() => renew(cur.token)}>New link for this file</button>
                  <button class="danger" onClick={() => remove(cur.token)}>Delete</button>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

const OFFLINE = 'Lost connection to oncedrop. Is it still running?';

const TUNNEL_TEXT = {
  idle: 'tunnel idle',
  starting: 'connecting to the tunnel…',
  error: 'tunnel: error, retrying',
};

function TunnelBadge({ tun }) {
  if (!tun) return <div class="tunnel"><span class="dot" /><span>…</span></div>;
  if (tun.state === 'up') {
    return (
      <div class="tunnel" title={tun.verified ? 'Address verified from this computer' : 'Address not verified yet'}>
        <span class={'dot ' + (tun.verified ? 'ok' : 'warn')} />
        <span>{tun.provider} · <span class="mono">{tun.url}</span></span>
      </div>
    );
  }
  return (
    <div class="tunnel" title={tun.err || ''}>
      <span class={'dot ' + (tun.state === 'error' ? 'bad' : tun.state === 'starting' ? 'warn' : '')} />
      <span>{TUNNEL_TEXT[tun.state] || tun.state}{tun.err && tun.state === 'error' ? `: ${tun.err}` : ''}</span>
    </div>
  );
}

function Status({ s }) {
  if (s.downloaded) {
    const t = new Date(s.downloadedAt).toLocaleTimeString();
    return <div class="status ok">Downloaded at {t}{s.remoteAddr ? ` from ${s.remoteAddr}` : ''}. The link has expired.</div>;
  }
  if (s.expired) return <div class="status bad">The link expired unused.</div>;
  return <div class="status wait">Waiting for download · expires in {countdown(s.expiresAt)}</div>;
}

function ShareItem({ s, active, onSelect, onRenew, onRemove }) {
  const dead = s.downloaded || s.expired;
  return (
    <div class={'item' + (dead ? ' dim' : '')} style={active ? 'border-color:var(--accent)' : ''}>
      <div style="min-width:0;flex:1;cursor:pointer" onClick={onSelect}>
        <div class="name">{s.name}</div>
        <div class="small muted">
          {humanSize(s.size)} · {s.downloaded ? 'downloaded' : s.expired ? 'expired' : countdown(s.expiresAt)}
        </div>
      </div>
      <div class="row">
        {dead && <button onClick={onRenew}>New link</button>}
        <button class="danger" onClick={onRemove}>Delete</button>
      </div>
    </div>
  );
}

function DropZone({ onFiles, disabled, busy, tunnelUp, maxSize }) {
  const [over, setOver] = useState(false);
  const input = useRef();
  const pick = (list) => {
    const files = Array.from(list || []);
    if (!files.length) return;
    const tooBig = files.find((f) => maxSize && f.size > maxSize);
    if (tooBig) { alert(`${tooBig.name} exceeds the limit of ${humanSize(maxSize)}`); return; }
    onFiles(files);
  };
  return (
    <div class={'drop' + (over ? ' over' : '')}
      onDragOver={(e) => { e.preventDefault(); setOver(true); }}
      onDragLeave={() => setOver(false)}
      onDrop={(e) => { e.preventDefault(); setOver(false); if (!disabled) pick(e.dataTransfer.files); }}>
      <input ref={input} type="file" multiple onChange={(e) => { pick(e.target.files); e.target.value = ''; }} />
      <svg class="icon" viewBox="0 0 24 24" width="44" height="44" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
        <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z" />
        <path d="M14 3v5h5" />
        <path d="M12 18v-6M9 15l3 3 3-3" />
      </svg>
      <div>Drop a file here</div>
      <div class="small" style="margin:8px 0 12px">or</div>
      <button class="primary" disabled={disabled} onClick={() => input.current.click()}>
        {busy ? (tunnelUp ? 'Uploading…' : 'Waiting for the tunnel…') : 'Choose file'}
      </button>
    </div>
  );
}
