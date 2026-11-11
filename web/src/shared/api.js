// Admin API client. The custom header is what stops cross-site pages from
// calling the local panel (see Admin.guard on the Go side).
const headers = { 'X-Requested-With': 'oncedrop' };

async function handle(res) {
  if (res.status === 204) return null;
  const body = await res.json().catch(() => ({}));
  if (res.status === 401) throw new Error('The panel needs a key: open the address printed in the terminal (with ?k=) or restart oncedrop.');
  if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
  return body;
}

export const api = {
  // active=1 tells the server someone is looking, which keeps the tunnel open.
  state: (active) => fetch('/api/state' + (active ? '?active=1' : ''), { headers }).then(handle),
  share: (file, ttlSec) => {
    const fd = new FormData();
    fd.append('file', file, file.name);
    if (ttlSec) fd.append('ttlSec', String(ttlSec));
    return fetch('/api/share', { method: 'POST', headers, body: fd }).then(handle);
  },
  get: (token) => fetch(`/api/share/${token}`, { headers }).then(handle),
  renew: (token) => fetch(`/api/share/${token}/renew`, { method: 'POST', headers }).then(handle),
  remove: (token) => fetch(`/api/share/${token}`, { method: 'DELETE', headers }).then(handle),
};

export function humanSize(n) {
  if (n >= 1 << 20) return (n / (1 << 20)).toFixed(1) + ' MB';
  if (n >= 1 << 10) return (n / (1 << 10)).toFixed(1) + ' KB';
  return n + ' B';
}

export function countdown(iso) {
  const ms = new Date(iso) - Date.now();
  if (ms <= 0) return 'expired';
  const s = Math.floor(ms / 1000);
  const m = Math.floor(s / 60);
  if (m >= 60) return `${Math.floor(m / 60)} h ${m % 60} min`;
  if (m > 0) return `${m} min ${s % 60} s`;
  return `${s} s`;
}
