import PAGE_HTML from '../index.html';

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    let response;

    // Handle login form POST
    if (url.pathname === '/login' && request.method === 'POST') {
      response = await handleLogin(request, env);
    } else if (url.pathname === '/logout') {
      response = handleLogout();
    } else if (await isAuthenticated(request, env)) {
      response = serveContent();
    } else {
      response = loginPage();
    }

    return withSecurityHeaders(response);
  }
};

// --- Auth logic ---

const SESSION_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

async function isAuthenticated(request, env) {
  const cookie = getCookie(request, 'auth_session');
  if (!cookie) return false;
  const valid = await verifyHmac(cookie, env.AUTH_SECRET);
  if (!valid) return false;

  const dot = cookie.lastIndexOf('.');
  const payload = cookie.slice(0, dot);
  const timestamp = parseInt(payload.split(':')[1], 10);
  if (isNaN(timestamp)) return false;
  return (Date.now() - timestamp) < SESSION_MAX_AGE_MS;
}

async function handleLogin(request, env) {
  const form = await request.formData();
  const password = form.get('password');

  if (!(await safeCompare(password, env.SITE_PASSWORD))) {
    await new Promise(r => setTimeout(r, 500));
    return loginPage('Incorrect password');
  }

  const token = await signHmac(`auth:${Date.now()}`, env.AUTH_SECRET);

  return new Response(null, {
    status: 303,
    headers: {
      'Location': '/',
      'Set-Cookie': `auth_session=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800`
    }
  });
}

function handleLogout() {
  return new Response(null, {
    status: 303,
    headers: {
      'Location': '/login',
      'Set-Cookie': `auth_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
    }
  });
}

// --- HMAC signing (Web Crypto, no dependencies) ---

async function getKey(secret) {
  const enc = new TextEncoder();
  return crypto.subtle.importKey(
    'raw', enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false, ['sign', 'verify']
  );
}

async function safeCompare(a, b) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', enc.encode('timing-safe-compare'),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const [sigA, sigB] = await Promise.all([
    crypto.subtle.sign('HMAC', key, enc.encode(a)),
    crypto.subtle.sign('HMAC', key, enc.encode(b)),
  ]);
  const bytesA = new Uint8Array(sigA);
  const bytesB = new Uint8Array(sigB);
  let result = 0;
  for (let i = 0; i < bytesA.length; i++) {
    result |= bytesA[i] ^ bytesB[i];
  }
  return result === 0;
}

async function signHmac(payload, secret) {
  const key = await getKey(secret);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
  const hex = Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
  return `${payload}.${hex}`;
}

async function verifyHmac(token, secret) {
  try {
    const dot = token.lastIndexOf('.');
    const payload = token.slice(0, dot);
    const sigHex = token.slice(dot + 1);
    const key = await getKey(secret);
    const sigBytes = Uint8Array.from(sigHex.match(/.{2}/g).map(h => parseInt(h, 16)));
    return crypto.subtle.verify('HMAC', key, sigBytes, new TextEncoder().encode(payload));
  } catch {
    return false;
  }
}

// --- Cookie parser ---

function getCookie(request, name) {
  const header = request.headers.get('Cookie') || '';
  for (const part of header.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return v.join('=');
  }
  return null;
}

// --- Utilities ---

function escapeHtml(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function withSecurityHeaders(response) {
  const headers = new Headers(response.headers);
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('X-Frame-Options', 'DENY');
  headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  headers.set('Content-Security-Policy', "default-src 'self'; style-src 'unsafe-inline'");
  return new Response(response.body, { status: response.status, headers });
}

// --- Pages ---

function loginPage(error = '') {
  const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Login</title>
  <style>
    body { font-family: sans-serif; display: flex; justify-content: center;
           align-items: center; height: 100vh; margin: 0; background: #f5f5f5; }
    form { background: white; padding: 2rem; border-radius: 8px;
           box-shadow: 0 2px 8px rgba(0,0,0,0.1); display: flex; flex-direction: column; gap: 1rem; }
    input { padding: 0.5rem; font-size: 1rem; border: 1px solid #ccc; border-radius: 4px; }
    button { padding: 0.5rem; font-size: 1rem; background: #333; color: white;
             border: none; border-radius: 4px; cursor: pointer; }
    .error { color: red; font-size: 0.9rem; }
  </style>
</head>
<body>
  <form method="POST" action="/login">
    <h2 style="margin:0">Enter password</h2>
    ${error ? `<p class="error">${escapeHtml(error)}</p>` : ''}
    <input type="password" name="password" placeholder="Password" autofocus required />
    <button type="submit">Enter</button>
  </form>
</body>
</html>`;

  return new Response(html, {
    status: error ? 403 : 200,
    headers: { 'Content-Type': 'text/html' }
  });
}

function serveContent() {
  return new Response(PAGE_HTML, {
    headers: { 'Content-Type': 'text/html' }
  });
}
