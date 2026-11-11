// Mirrors internal/share/crypto.go:
// nonce(12) || AES-256-GCM( u32be(len(header)) || header JSON || file ).

function b64urlToBytes(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export async function importKey(fragment) {
  const raw = b64urlToBytes(fragment);
  if (raw.length !== 32) throw new Error('Invalid key in the address');
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['decrypt']);
}

export async function decryptPayload(key, buf) {
  const bytes = new Uint8Array(buf);
  if (bytes.length < 12 + 16 + 4) throw new Error('Corrupted data');
  const iv = bytes.subarray(0, 12);
  const ct = bytes.subarray(12);
  let plain;
  try {
    plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, ct);
  } catch {
    throw new Error('Could not decrypt. Wrong key or corrupted file.');
  }
  const dv = new DataView(plain);
  const hlen = dv.getUint32(0);
  const header = JSON.parse(new TextDecoder().decode(new Uint8Array(plain, 4, hlen)));
  const data = new Uint8Array(plain, 4 + hlen);
  return { header, file: new File([data], header.name, { type: header.type || 'application/octet-stream' }) };
}

// fetch with byte-level progress; returns an ArrayBuffer.
export async function fetchWithProgress(url, onProgress) {
  const res = await fetch(url, { cache: 'no-store' });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    const err = new Error(body.reason || `HTTP ${res.status}`);
    err.reason = body.reason;
    throw err;
  }
  const total = Number(res.headers.get('Content-Length')) || 0;
  if (!res.body) return res.arrayBuffer();
  const reader = res.body.getReader();
  const chunks = [];
  let got = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    got += value.length;
    onProgress?.(got, total);
  }
  const out = new Uint8Array(got);
  let off = 0;
  for (const c of chunks) { out.set(c, off); off += c.length; }
  return out.buffer;
}
