import { useEffect, useState } from 'preact/hooks';
import { humanSize } from '../shared/api.js';
import { importKey, decryptPayload, fetchWithProgress } from './crypto.js';

const REASONS = {
  consumed: 'This link has already been used. Ask for a new one.',
  expired: 'This link has expired. Ask for a new one.',
  not_found: 'No such file. The link is wrong or has expired.',
};

// Read once at module load. The page strips the fragment from the URL bar
// right after mounting, so re-reading location.hash on later renders would
// yield an empty key.
const token = location.pathname.split('/').filter(Boolean).pop();
const fragment = location.hash.slice(1);

export function App() {

  const [phase, setPhase] = useState('checking'); // checking | ready | downloading | done | error
  const [info, setInfo] = useState(null);
  const [progress, setProgress] = useState(0);
  const [result, setResult] = useState(null); // {header, file}
  const [error, setError] = useState('');
  const [shareNote, setShareNote] = useState('');

  useEffect(() => {
    // Drop the key from history/URL bar as soon as we have it in memory.
    if (fragment) history.replaceState(null, '', location.pathname);
    if (!fragment) { setPhase('error'); setError('This link has no key. Scan the QR code again.'); return; }
    if (!crypto?.subtle) { setPhase('error'); setError('This browser does not support encryption (WebCrypto). Open the link in Chrome or Safari.'); return; }
    fetch(`/api/s/${token}`, { cache: 'no-store' })
      .then((r) => r.json().then((b) => ({ ok: r.ok, b })))
      .then(({ ok, b }) => {
        if (!ok) { setPhase('error'); setError(REASONS[b.reason] || 'Unknown error'); return; }
        setInfo(b);
        setPhase('ready');
      })
      .catch(() => { setPhase('error'); setError('Could not reach the sender.'); });
  }, []);

  async function download() {
    setPhase('downloading');
    setError('');
    try {
      const key = await importKey(fragment);
      const buf = await fetchWithProgress(`/api/s/${token}/blob`, (got, total) => setProgress(total ? got / total : 0));
      const r = await decryptPayload(key, buf);
      setResult(r);
      setPhase('done');
      // Still inside the tap's transient activation on most browsers;
      // if not, the user gets the explicit Share button below.
      await share(r.file, true);
    } catch (e) {
      setPhase('error');
      setError(REASONS[e.reason] || e.message);
    }
  }

  async function share(file, silent) {
    if (!navigator.share || !navigator.canShare?.({ files: [file] })) {
      if (!silent) setShareNote('This browser cannot share files. Use “Save to phone”, then send it from your gallery or files app.');
      return;
    }
    try {
      await navigator.share({ files: [file], title: file.name });
      setShareNote('');
    } catch (e) {
      if (e.name === 'AbortError') return; // user closed the sheet
      if (!silent) setShareNote('Could not open the share sheet: ' + e.message);
    }
  }

  function save(file) {
    const url = URL.createObjectURL(file);
    const a = document.createElement('a');
    a.href = url;
    a.download = file.name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 30_000);
  }

  return (
    <div class="wrap narrow">
      <div class="card stack center" style="margin-top:8vh">
        <LockIcon />

        {phase === 'checking' && <p class="muted">Checking link…</p>}

        {phase === 'error' && (
          <>
            <p class="err" style="margin:0">{error}</p>
            {result && <Actions file={result.file} onShare={() => share(result.file)} onSave={() => save(result.file)} note={shareNote} />}
          </>
        )}

        {phase === 'ready' && (
          <>
            <p style="margin:0"><strong>A file is waiting for you</strong></p>
            <p class="muted small" style="margin:0">
              About {humanSize(info.cipherSize)} · end-to-end encrypted.<br />
              The link works <strong>once</strong>. Do not reload this page after downloading.
            </p>
            <button class="primary big" onClick={download}>Download and share</button>
          </>
        )}

        {phase === 'downloading' && (
          <>
            <p style="margin:0">Downloading and decrypting…</p>
            <div class="progress"><div style={`width:${Math.round(progress * 100)}%`} /></div>
          </>
        )}

        {phase === 'done' && result && (
          <>
            <p style="margin:0"><strong>{result.header.name}</strong></p>
            <p class="muted small" style="margin:0">{humanSize(result.header.size)} · decrypted on this phone</p>
            <Actions file={result.file} onShare={() => share(result.file)} onSave={() => save(result.file)} note={shareNote} />
            <p class="muted small" style="margin:0">The file exists only in this tab's memory. Closing the tab discards it.</p>
          </>
        )}
      </div>
    </div>
  );
}

function LockIcon() {
  return (
    <svg class="icon" viewBox="0 0 24 24" width="44" height="44" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
      <rect x="4" y="10" width="16" height="11" rx="2.5" />
      <path d="M8 10V7a4 4 0 0 1 8 0v3" />
      <circle cx="12" cy="15.5" r="1.3" fill="currentColor" stroke="none" />
    </svg>
  );
}

function Actions({ onShare, onSave, note }) {
  const canShare = !!navigator.share;
  return (
    <div class="stack">
      {canShare && <button class="primary big" onClick={onShare}>Share (WhatsApp, email…)</button>}
      <button class="big" onClick={onSave}>Save to phone</button>
      {note && <p class="muted small" style="margin:0">{note}</p>}
    </div>
  );
}
