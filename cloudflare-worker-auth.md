# Cloudflare Worker Password Protection

A Cloudflare Worker intercepts **every request** before anything reaches the browser. You check the cookie there, and either serve the content or return a login page. The browser never gets your HTML unless the password is correct. No framework needed — just a single `worker.js` file.

---

## Option A: Worker Serves Your HTML Directly

Good if your site is simple / mostly static.

**`worker.js`**

```js
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Handle login form POST
    if (url.pathname === '/login' && request.method === 'POST') {
      return handleLogin(request, env);
    }

    // Handle logout
    if (url.pathname === '/logout') {
      return handleLogout();
    }

    // Check auth for everything else
    const authed = await isAuthenticated(request, env);
    if (!authed) {
      return loginPage(url.pathname);
    }

    // ✅ Authenticated — serve your content
    return serveContent(url.pathname);
  }
};

// --- Auth logic ---

async function isAuthenticated(request, env) {
  const cookie = getCookie(request, 'auth_session');
  if (!cookie) return false;
  return verifyHmac(cookie, env.AUTH_SECRET);
}

async function handleLogin(request, env) {
  const form = await request.formData();
  const password = form.get('password');

  if (password !== env.SITE_PASSWORD) {
    await new Promise(r => setTimeout(r, 500)); // slow brute force
    return loginPage('/', 'Incorrect password');
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
      'Set-Cookie': `auth_session=; Path=/; HttpOnly; Secure; Max-Age=0`
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
  const match = header.match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
  return match ? match[1] : null;
}

// --- Pages ---

function loginPage(next = '/', error = '') {
  const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
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
    ${error ? `<p class="error">${error}</p>` : ''}
    <input type="hidden" name="next" value="${next}" />
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

function serveContent(pathname) {
  // Replace this with your actual content routing
  return new Response(`<h1>Welcome! You're in. (path: ${pathname})</h1>`, {
    headers: { 'Content-Type': 'text/html' }
  });
}
```

---

## Option B: Worker as a Proxy in Front of Cloudflare Pages

If your site is already deployed on Cloudflare Pages (or anywhere else), the worker sits in front and proxies requests through only after auth. This is the most flexible setup.

```js
const PROTECTED_ORIGIN = 'https://your-pages-site.pages.dev';

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === '/login' && request.method === 'POST') {
      return handleLogin(request, env);
    }
    if (url.pathname === '/logout') {
      return handleLogout();
    }

    const authed = await isAuthenticated(request, env);
    if (!authed) return loginPage(url.pathname);

    // ✅ Proxy the request to your real site
    const proxied = new Request(PROTECTED_ORIGIN + url.pathname + url.search, request);
    return fetch(proxied);
  }
};

// ... (same auth functions as Option A)
```

---

## Deploying

**`wrangler.toml`**

```toml
name = "my-protected-site"
main = "worker.js"
compatibility_date = "2024-01-01"
```

**Set your secrets:**

```bash
# The password visitors will type
wrangler secret put SITE_PASSWORD

# A long random string for signing cookies
# Generate with: openssl rand -hex 32
wrangler secret put AUTH_SECRET
```

**Deploy:**

```bash
wrangler deploy
```

---

## Security Summary

| Threat | Defense |
|---|---|
| Devtools / JS inspection | `HttpOnly` cookie — JS can't read it |
| Cookie forgery | HMAC-signed with server-only secret |
| Password brute force | 500ms delay on wrong password |
| Password in source code | Cloudflare encrypted secret, not in repo |
| Sniffing the cookie | `Secure: true` — HTTPS only |

---

## Which Option to Choose

| | Pure Worker (A) | Worker + Pages (B) |
|---|---|---|
| Best for | Small / simple sites | Existing or larger sites |
| Content lives | In worker code | On Pages (normal deploy) |
| Auth mechanism | Identical for both | Identical for both |

The auth code is exactly the same either way — Option B just swaps `serveContent()` for a `fetch()` proxy call.
