// api/proxy.js
// Adaptado de Cloudflare Workers a Vercel Edge Functions.
// Mismo comportamiento: descifra ?q=, o usa ?url=/?u=/?target= + ?ref=,
// hace fetch con rotación de perfiles de navegador, y devuelve el recurso
// con headers CORS. Sirve como respaldo si el proxy de Cloudflare falla.

export const config = {
  runtime: 'edge',
};

const _VMK = new Uint8Array([
  0xF3,0x8A,0x1C,0x77,0xE2,0x4B,0x9D,0x30,
  0x56,0xC1,0xAF,0x0E,0x72,0xD9,0x3F,0x88,
  0x1B,0x64,0xA5,0xEC,0x27,0x90,0x4D,0xB6,
  0x03,0xF7,0x5E,0xC8,0x39,0x12,0x6A,0xDB
]);
const _VCTX = new TextEncoder().encode('VORTEX-PROXY-V1/comix');
let _VK = null;

async function _vKey() {
  if (_VK) return _VK;
  _VK = await crypto.subtle.importKey('raw', _VMK, { name: 'HKDF' }, false, ['deriveKey']);
  return _VK;
}

async function _vDerive(salt) {
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-512', salt, info: _VCTX },
    await _vKey(),
    { name: 'AES-GCM', length: 256 }, false, ['decrypt']
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
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const b = atob(s), u = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i);
  return u;
}

async function vDecrypt(blob) {
  let raw; try { raw = b64d(blob); } catch { return null; }
  if (raw.length < 29) return null;
  try {
    const key = await _vDerive(raw.slice(0, 16));
    const dec = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: raw.slice(16, 28), tagLength: 128 }, key, raw.slice(28)
    );
    const plain = _vUnscramble(new Uint8Array(dec));
    if (plain.length < 2) return null;
    const urlLen = (plain[0] << 8) | plain[1];
    if (plain.length < 2 + urlLen) return null;
    const td = new TextDecoder();
    return {
      url: td.decode(plain.slice(2, 2 + urlLen)),
      ref: plain.length > 2 + urlLen ? td.decode(plain.slice(2 + urlLen)) : ''
    };
  } catch { return null; }
}

const UA_POOL = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.6834.160 Safari/537.36',
  'Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:132.0) Gecko/20100101 Firefox/132.0',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0',
];

const SEC_CH_UA_POOL = [
  '"Google Chrome";v="133", "Not(A:Brand";v="99", "Chromium";v="133"',
  '"Google Chrome";v="132", "Not(A:Brand";v="99", "Chromium";v="132"',
  '"Microsoft Edge";v="133", "Not(A:Brand";v="99", "Chromium";v="133"',
];

const BROWSER_PROFILES = [
  (ua, ref) => ({
    'User-Agent': ua,
    'Accept': 'image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br, zstd',
    'Referer': ref,
    'Sec-Fetch-Dest': 'image',
    'Sec-Fetch-Mode': 'no-cors',
    'Sec-Fetch-Site': 'cross-site',
    'Sec-CH-UA': rSec(),
    'Sec-CH-UA-Mobile': '?0',
    'Sec-CH-UA-Platform': '"Windows"',
    'Cache-Control': 'no-cache',
    'Pragma': 'no-cache',
    'Priority': 'i',
  }),
  (ua, ref) => ({
    'User-Agent': ua,
    'Accept': 'image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8',
    'Accept-Language': 'ja,en-US;q=0.9,en;q=0.8',
    'Accept-Encoding': 'gzip, deflate, br',
    'Referer': ref,
    'Origin': new URL(ref).origin,
    'Sec-Fetch-Dest': 'image',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-site',
    'Sec-CH-UA': rSec(),
    'Sec-CH-UA-Mobile': '?0',
    'Sec-CH-UA-Platform': '"Windows"',
  }),
  (ua, ref) => ({
    'User-Agent': ua,
    'Accept': 'image/avif,image/webp,*/*',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate, br',
    'Referer': ref,
    'Sec-Fetch-Dest': 'image',
    'Sec-Fetch-Mode': 'no-cors',
    'Sec-Fetch-Site': 'cross-site',
    'Connection': 'keep-alive',
  }),
  (ua, ref) => ({
    'User-Agent': ua,
    'Accept': 'image/webp,image/png,image/svg+xml,image/*;q=0.8,video/*;q=0.8,*/*;q=0.5',
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br',
    'Referer': ref,
  }),
  (_ua, _ref) => ({
    'User-Agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    'Accept': '*/*',
    'Accept-Encoding': 'gzip, deflate, br',
  }),
];

const rUA  = () => UA_POOL[Math.floor(Math.random() * UA_POOL.length)];
const rSec = () => SEC_CH_UA_POOL[Math.floor(Math.random() * SEC_CH_UA_POOL.length)];
const rPro = (i) => BROWSER_PROFILES[i % BROWSER_PROFILES.length];

const isImg = u => /\.(jpg|jpeg|png|webp|gif|avif|jxl|svg|ico|bmp)(\?|$)/i.test(u);
const isDoc = u => /\.(js|json|nozomi)(\?|$)/i.test(u);
const getTTL = u => isImg(u) ? 86400 * 30 : isDoc(u) ? 3600 : 3600;

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
  'Access-Control-Allow-Headers': '*',
  'Access-Control-Expose-Headers': 'Content-Type, Content-Length, X-Cache, Cache-Control',
  'Access-Control-Max-Age': '86400',
  'Vary': 'Origin',
};

function addCors(headers) {
  Object.entries(CORS).forEach(([k, v]) => headers.set(k, v));
}

function errResp(status, msg) {
  return new Response(JSON.stringify({ error: msg }), {
    status,
    headers: { ...CORS, 'Content-Type': 'application/json' },
  });
}

const delay = ms => new Promise(r => setTimeout(r, ms));

function inferCT(url) {
  const ext = url.split('?')[0].split('.').pop().toLowerCase();
  return {
    jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png',
    webp: 'image/webp', gif: 'image/gif', avif: 'image/avif',
    jxl: 'image/jxl', svg: 'image/svg+xml', ico: 'image/x-icon',
    js: 'application/javascript', json: 'application/json',
    nozomi: 'application/octet-stream',
  }[ext] || 'application/octet-stream';
}

// Vercel Edge Functions usan esta firma: export default function handler(req)
export default async function handler(req) {
  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: CORS });
  }
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    return errResp(405, 'Método no permitido');
  }

  const u = new URL(req.url);
  let target = null;
  let referer = 'https://ttmi.la/';

  const q = u.searchParams.get('q');
  if (q) {
    const decoded = await vDecrypt(q);
    if (!decoded || !decoded.url) return errResp(400, 'Blob inválido');
    target = decoded.url;
    referer = decoded.ref || referer;
  }

  if (!target) {
    const enc = u.searchParams.get('url') || u.searchParams.get('u') || u.searchParams.get('target');
    if (!enc) return errResp(400, 'Falta ?q= o ?url=');
    try { target = atob(enc); }
    catch (_) { try { target = decodeURIComponent(enc); } catch (_) { target = enc; } }
    const rawRef = u.searchParams.get('ref');
    if (rawRef) try { referer = decodeURIComponent(rawRef); } catch (_) { referer = rawRef; }
  }

  if (!/^https?:\/\//i.test(target)) return errResp(400, 'URL inválida');

  try { new URL(referer); } catch { referer = 'https://ttmi.la/'; }

  // Nota: Vercel Edge no tiene `caches.default` como Cloudflare.
  // El cacheo aquí se delega al Cache-Control que mandamos abajo (la CDN
  // de Vercel respeta esos headers en respuestas GET). Si necesitas un
  // cache propio (KV), se puede agregar con Vercel KV o Upstash Redis.

  let res = null, lastErr = null;
  const ua = rUA();
  for (let i = 0; i < 5; i++) {
    try {
      const headers = rPro(i)(ua, referer);
      res = await fetch(target, {
        headers,
        redirect: 'follow',
      });
      if (res.ok) break;
      if (res.status === 404) break;
      if ([403, 401, 429].includes(res.status)) {
        await delay(300 * (i + 1));
        continue;
      }
    } catch (e) {
      lastErr = e;
      await delay(200 * (i + 1));
    }
  }

  if (!res) return errResp(502, `Fetch falló: ${lastErr?.message || 'error desconocido'}`);

  const body = await res.arrayBuffer();
  const ct = res.headers.get('Content-Type') || inferCT(target);
  const ttl = getTTL(target);

  const outHeaders = new Headers();
  addCors(outHeaders);
  outHeaders.set('Content-Type', ct);
  outHeaders.set('Cache-Control', res.ok ? `public, max-age=${ttl}, immutable` : 'no-store');
  outHeaders.set('Content-Length', body.byteLength.toString());
  outHeaders.set('X-Cache', 'MISS');

  for (const h of ['Last-Modified', 'ETag', 'Content-Disposition']) {
    const v = res.headers.get(h);
    if (v) outHeaders.set(h, v);
  }

  return new Response(body, { status: res.status, headers: outHeaders });
}
