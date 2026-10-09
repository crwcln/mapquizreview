// edge-functions/api/auth.js  ->  POST /api/auth
// Env vars (EdgeOne Pages project settings): ADMIN_PASSWORD, DEV_PASSWORD

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });

const enc = new TextEncoder();

// Constant-time comparison (hash first so lengths always match)
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

export async function onRequestPost(context) {
  try {
    let body;
    try {
      body = await context.request.json();
    } catch {
      return json({ ok: false, error: 'bad_request' }, 400);
    }

    const { target, password } = body || {};
    if (typeof password !== 'string' || password.length > 200) {
      return json({ ok: false, error: 'bad_request' }, 400);
    }

    const env = context && context.env ? context.env : {};
    const secrets = {
      admin: env.ADMIN_PASSWORD,
      dev: env.DEV_PASSWORD,
    };
    if (!Object.prototype.hasOwnProperty.call(secrets, target)) {
      return json({ ok: false, error: 'bad_target' }, 400);
    }
    const expected = secrets[target];
    if (!expected) {
      return json({ ok: false, error: 'not_configured' }, 500);
    }

    if (await safeEqual(password, expected)) {
      const res = { ok: true };
      if (target === 'admin') {
        // Short-lived signed token so other admin-only endpoints (e.g. /api/deploy) don't need the password again.
        const exp = Date.now() + 30 * 60 * 1000;
        res.token = `${exp}.${await hmacHex(expected, `admin.${exp}`)}`;
      }
      return json(res);
    }

    // Slow down brute-force attempts
    await new Promise((r) => setTimeout(r, 500));
    return json({ ok: false }, 401);
  } catch (error) {
    console.error('Auth edge function failed:', error);
    return json({ ok: false, error: 'internal_error' }, 500);
  }
}
