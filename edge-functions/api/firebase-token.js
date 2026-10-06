// edge-functions/api/firebase-token.js  ->  POST /api/firebase-token
// Exchanges a valid admin token (from /api/auth) for a Firebase custom token carrying { admin: true }.
// Env vars (EdgeOne Pages project settings):
//   ADMIN_PASSWORD        - same one /api/auth uses (it is also the HMAC key for admin tokens)
//   FIREBASE_CLIENT_EMAIL - "client_email" from a Firebase service account JSON
//   FIREBASE_PRIVATE_KEY_1 ... _N - the "private_key" from the same JSON, split into chunks of <= 450 chars
//                           (EdgeOne caps each variable at 500 bytes). A single FIREBASE_PRIVATE_KEY also works.

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });

const enc = new TextEncoder();

async function safeEqual(a, b) {
  const [ha, hb] = await Promise.all([
    crypto.subtle.digest('SHA-256', enc.encode(a)),
    crypto.subtle.digest('SHA-256', enc.encode(b)),
  ]);
  const x = new Uint8Array(ha), y = new Uint8Array(hb);
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

async function hmacHex(secret, msg) {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(msg));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function validToken(token, secret) {
  if (typeof token !== 'string') return false;
  const [expStr, sig] = token.split('.');
  const exp = Number(expStr);
  if (!exp || !sig || Date.now() > exp) return false;
  return safeEqual(sig, await hmacHex(secret, `admin.${exp}`));
}

// EdgeOne env values are capped at 500 bytes, so the key may be split across FIREBASE_PRIVATE_KEY_1..N
function readPrivateKey(env) {
  if (env.FIREBASE_PRIVATE_KEY) return env.FIREBASE_PRIVATE_KEY;
  let key = '';
  for (let i = 1; i <= 12; i++) {
    const part = env[`FIREBASE_PRIVATE_KEY_${i}`];
    if (!part) break;
    key += String(part).trim();
  }
  return key;
}

const b64url = (input) => {
  const bytes = typeof input === 'string' ? enc.encode(input) : new Uint8Array(input);
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

async function importPrivateKey(pem) {
  const body = pem.replace(/\\n/g, '\n').replace(/-----(BEGIN|END) PRIVATE KEY-----/g, '').replace(/\s+/g, '');
  const der = Uint8Array.from(atob(body), (c) => c.charCodeAt(0));
  return crypto.subtle.importKey('pkcs8', der, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
}

async function mintCustomToken(email, privateKeyPem) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'RS256', typ: 'JWT' };
  const payload = {
    iss: email,
    sub: email,
    aud: 'https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit',
    iat: now,
    exp: now + 3600,
    uid: 'admin',
    claims: { admin: true },
  };
  const unsigned = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  const key = await importPrivateKey(privateKeyPem);
  const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, enc.encode(unsigned));
  return `${unsigned}.${b64url(sig)}`;
}

export async function onRequestPost(context) {
  const secret = context.env.ADMIN_PASSWORD;
  const email = context.env.FIREBASE_CLIENT_EMAIL;
  const pk = readPrivateKey(context.env);
  if (!secret || !email || !pk) return json({ ok: false, error: 'not_configured' }, 500);

  let body;
  try {
    body = await context.request.json();
  } catch {
    return json({ ok: false, error: 'bad_request' }, 400);
  }
  if (!(await validToken(body && body.token, secret))) {
    return json({ ok: false, error: 'unauthorized' }, 401);
  }

  try {
    return json({ ok: true, customToken: await mintCustomToken(email, pk) });
  } catch {
    return json({ ok: false, error: 'sign_failed' }, 500);
  }
}