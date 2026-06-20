// ...all].js — Proxy VORTEX + test (sin frontend)

// ══════════════════════════════════════════════
const _VMK = new Uint8Array([
  0xF3,0x8A,0x1C,0x77,0xE2,0x4B,0x9D,0x30,0x56,0xC1,0xAF,0x0E,0x72,0xD9,0x3F,0x88,
  0x1B,0x64,0xA5,0xEC,0x27,0x90,0x4D,0xB6,0x03,0xF7,0x5E,0xC8,0x39,0x12,0x6A,0xDB
]);
const _VCTX = new TextEncoder().encode('VORTEX-PROXY-V1/comix');
let _VK = null;

async function _vKey() {
  if (_VK) return _VK;
  _VK = await crypto.subtle.importKey('raw', _VMK, { name:'HKDF' }, false, ['deriveKey']);
  return _VK;
}
async function _vDerive(salt) {
  return crypto.subtle.deriveKey(
    { name:'HKDF', hash:'SHA-512', salt, info:_VCTX },
    await _vKey(),
    { name:'AES-GCM', length:256 }, false, ['decrypt']
  );
}
function _vUnscramble(bytes) {
  const out = new Uint8Array(bytes.length);
  let acc = 0xA7;
  for (let i = 0; i < bytes.length; i++) {
    const plain = bytes[i] ^ (acc & 0xFF) ^ (i % 97);
    acc = ((acc << 3) | (acc >>> 5)) ^ plain ^ (i & 0xFF);
    out[i] = plain;
  }
  return out;
}
function b64d(s) {
  s = s.replace(/-/g,'+').replace(/_/g,'/');
  while (s.length % 4) s += '=';
  const b = atob(s), u = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i);
  return u;
}
async function vDecrypt(blob) {
  let raw; try { raw = b64d(blob); } catch { return null; }
  if (raw.length < 29) return null;
  try {
    const key = await _vDerive(raw.slice(0,16));
    const dec = await crypto.subtle.decrypt(
      { name:'AES-GCM', iv:raw.slice(16,28), tagLength:128 }, key, raw.slice(28)
    );
    const plain = _vUnscramble(new Uint8Array(dec));
    if (plain.length < 2) return null;
    const urlLen = (plain[0] << 8) | plain[1];
    if (plain.length < 2 + urlLen) return null;
    const td = new TextDecoder();
    return {
      url: td.decode(plain.slice(2, 2+urlLen)),
      ref: plain.length > 2+urlLen ? td.decode(plain.slice(2+urlLen)) : ''
    };
  } catch { return null; }
}

// ══════════════════════════════════════════════
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
  'Access-Control-Allow-Headers': '*',
  'Access-Control-Expose-Headers': 'Content-Type, Content-Length, X-Cache',
  'Access-Control-Max-Age': '86400',
};
function addCors(r) {
  Object.entries(CORS).forEach(([k,v]) => r.headers.set(k, v));
}
function errResp(status, msg) {
  return new Response(JSON.stringify({ error: msg }), {
    status,
    headers: { ...CORS, 'Content-Type': 'application/json' },
  });
}

// ══════════════════════════════════════════════
export default async function handler(request) {
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/$/, '');

  // ── Endpoint de test ──────────────────────
  if (path === '/api/test') {
    return new Response(JSON.stringify({
      ok: true,
      timestamp: Date.now(),
      message: 'Proxy VORTEX activo en Vercel'
    }), {
      status: 200,
      headers: { ...CORS, 'Content-Type': 'application/json' },
    });
  }

  // ── Solo se permite /api/proxy ────────────
  if (path !== '/api/proxy') {
    return errResp(404, 'Usa /api/proxy o /api/test');
  }

  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: CORS });
  }
  if (request.method !== 'GET') {
    return errResp(405, 'Solo GET permitido');
  }

  let target = null;
  let referer = 'https://hitomi.la/';

  // Modo VORTEX: ?q=
  const q = url.searchParams.get('q');
  if (q) {
    const decoded = await vDecrypt(q);
    if (!decoded || !decoded.url) return errResp(400, 'Token Vortex inválido');
    target = decoded.url;
    referer = decoded.ref || referer;
  }

  // Modo legado: ?url= (base64)
  if (!target) {
    const enc = url.searchParams.get('url') || url.searchParams.get('u') || url.searchParams.get('target');
    if (!enc) return errResp(400, 'Falta ?q= o ?url=');
    try {
      target = atob(enc);
    } catch {
      try { target = decodeURIComponent(enc); } catch { target = enc; }
    }
    const rawRef = url.searchParams.get('ref');
    if (rawRef) try { referer = decodeURIComponent(rawRef); } catch { referer = rawRef; }
  }

  if (!/^https?:\/\//i.test(target)) return errResp(400, 'URL inválida');
  try { new URL(referer); } catch { referer = 'https://hitomi.la/'; }

  const UA = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0',
  ];
  const ua = UA[Math.floor(Math.random() * UA.length)];

  const headers = {
    'User-Agent': ua,
    'Accept': 'image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Referer': referer,
    'Sec-Fetch-Dest': 'image',
    'Sec-Fetch-Mode': 'no-cors',
    'Sec-Fetch-Site': 'cross-site',
  };

  let res;
  for (let i = 0; i < 3; i++) {
    try {
      res = await fetch(target, { headers, redirect: 'follow' });
      if (res.ok || res.status === 404) break;
      if ([403, 429].includes(res.status)) await new Promise(r => setTimeout(r, 500 * (i+1)));
    } catch (e) {
      if (i === 2) return errResp(502, 'Fetch falló tras 3 intentos');
    }
  }

  if (!res) return errResp(502, 'Sin respuesta del servidor');

  const body = await res.arrayBuffer();
  const ct = res.headers.get('Content-Type') || 'application/octet-stream';
  const out = new Response(body, { status: res.status });
  addCors(out);
  out.headers.set('Content-Type', ct);
  out.headers.set('Content-Length', body.byteLength.toString());
  return out;
}
