# Security Audit — gabrielwagner Worker Auth

**Date:** 2026-03-09
**Scope:** `worker-auth/worker.js`, `wrangler.toml`, `index.html`, `.dev.vars`, `.gitignore`
**Severity scale:** Critical / High / Medium / Low / Informational

---

## Summary

The application is a Cloudflare Worker providing password-based authentication via HMAC-SHA256 signed cookies. The overall design is sound for a single-password static site protector. The audit identified **2 high**, **3 medium**, and **3 low** severity findings, plus informational notes.

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 2 |
| Medium | 3 |
| Low | 3 |
| Informational | 3 |

---

## Findings

### HIGH-1: Reflected XSS via `error` parameter in login page

**File:** `worker-auth/worker.js:128`
**Severity:** High

The `error` string is interpolated directly into HTML without escaping:

```js
${error ? `<p class="error">${error}</p>` : ''}
```

Currently `error` is only set to the hardcoded string `'Incorrect password'` on line 42, so this is **not exploitable today**. However, if a future code change passes user-controlled input into the `error` parameter, it becomes a reflected XSS vulnerability. This is a latent risk.

**Recommendation:** HTML-escape the `error` value before interpolation:

```js
function escapeHtml(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

${error ? `<p class="error">${escapeHtml(error)}</p>` : ''}
```

---

### HIGH-2: Reflected XSS via `next` parameter in login page

**File:** `worker-auth/worker.js:129`
**Severity:** High

The `next` value (derived from `url.pathname`) is interpolated into an HTML attribute without escaping:

```js
<input type="hidden" name="next" value="${next}" />
```

An attacker could craft a URL with a pathname containing `" onmouseover="alert(1)` or similar payloads. While Cloudflare Workers normalize URL paths to some degree, different environments and edge cases may allow attribute injection. The `next` field is also never used in the redirect logic — `handleLogin()` always redirects to `/` regardless of the `next` form value.

**Recommendation:**
1. HTML-escape the `next` value.
2. Remove the `next` hidden field entirely since it is unused, reducing attack surface.

---

### MEDIUM-1: No session expiration validation in token payload

**File:** `worker-auth/worker.js:45, 84-95`
**Severity:** Medium

The signed token payload is `auth:<timestamp>`, but `verifyHmac()` only checks the HMAC signature — it never validates the timestamp. The cookie's `Max-Age=604800` (7 days) relies entirely on the browser to expire the cookie. A stolen cookie remains valid forever as long as `AUTH_SECRET` hasn't been rotated.

If an attacker exfiltrates a valid cookie (e.g., from a compromised device or browser profile), it works indefinitely even after the browser would have expired it.

**Recommendation:** After HMAC verification, parse the timestamp from the payload and reject tokens older than your desired session lifetime:

```js
async function isAuthenticated(request, env) {
  const cookie = getCookie(request, 'auth_session');
  if (!cookie) return false;
  const valid = await verifyHmac(cookie, env.AUTH_SECRET);
  if (!valid) return false;

  const dot = cookie.lastIndexOf('.');
  const payload = cookie.slice(0, dot);
  const timestamp = parseInt(payload.split(':')[1], 10);
  const maxAge = 7 * 24 * 60 * 60 * 1000; // 7 days in ms
  return (Date.now() - timestamp) < maxAge;
}
```

---

### MEDIUM-2: Plain-text password comparison (timing side-channel)

**File:** `worker-auth/worker.js:40`
**Severity:** Medium

```js
if (password !== env.SITE_PASSWORD) {
```

JavaScript's `!==` performs a byte-by-byte comparison that short-circuits on the first mismatch, making the comparison time proportional to the length of the common prefix. In theory, a sophisticated attacker could use timing analysis to determine the password character by character.

In practice, the 500ms delay and network jitter make this very difficult to exploit over the internet, and the Cloudflare Workers runtime introduces additional noise. Nonetheless, constant-time comparison is a best practice for secret comparison.

**Recommendation:** Use a constant-time comparison via the Web Crypto API:

```js
async function safeCompare(a, b) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', enc.encode('compare-key'),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sigA = await crypto.subtle.sign('HMAC', key, enc.encode(a));
  const sigB = await crypto.subtle.sign('HMAC', key, enc.encode(b));
  return crypto.subtle.verify('HMAC', key, sigA, enc.encode(b)); // false
  // Better: compare the two HMAC outputs byte-by-byte in constant time
}
```

Or more simply, HMAC both values and compare the digests:

```js
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
  if (bytesA.length !== bytesB.length) return false;
  let result = 0;
  for (let i = 0; i < bytesA.length; i++) {
    result |= bytesA[i] ^ bytesB[i];
  }
  return result === 0;
}
```

---

### MEDIUM-3: No rate limiting beyond the 500ms delay

**File:** `worker-auth/worker.js:41`
**Severity:** Medium

The 500ms delay on failed login attempts is a lightweight brute-force mitigation, but:
- It only limits an individual request, not an IP or session — an attacker can send thousands of concurrent requests.
- 500ms allows ~2 attempts/second per connection, or far more in parallel.
- There is no account lockout, CAPTCHA, or IP-based throttle.

For a simple personal site this may be acceptable, but a weak password (like the dev example `linkboi`) could be cracked relatively quickly.

**Recommendation:**
- Use Cloudflare's built-in [Rate Limiting Rules](https://developers.cloudflare.com/waf/rate-limiting-rules/) to throttle `POST /login` (e.g., 5 attempts per minute per IP).
- Consider adding [Cloudflare Turnstile](https://developers.cloudflare.com/turnstile/) (free CAPTCHA alternative) to the login form.
- Use a strong, long password in production.

---

### LOW-1: Missing security headers on responses

**File:** `worker-auth/worker.js:136-139, 143-145`
**Severity:** Low

Neither the login page nor the protected content responses include standard security headers:

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Content-Security-Policy` (at minimum `default-src 'self'`)
- `Referrer-Policy: strict-origin-when-cross-origin`

Without `X-Frame-Options` or a CSP `frame-ancestors` directive, the login page could be embedded in an iframe for clickjacking attacks.

**Recommendation:** Add a helper to set security headers on all responses:

```js
function securityHeaders(response) {
  const headers = new Headers(response.headers);
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('X-Frame-Options', 'DENY');
  headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  headers.set('Content-Security-Policy', "default-src 'self'; style-src 'unsafe-inline'");
  return new Response(response.body, { status: response.status, headers });
}
```

---

### LOW-2: Logout does not set `SameSite` attribute on cookie clear

**File:** `worker-auth/worker.js:61`
**Severity:** Low

The login flow sets `SameSite=Lax`, but the logout cookie-clear omits it:

```js
// Login (correct)
Set-Cookie: auth_session=...; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800

// Logout (missing SameSite)
Set-Cookie: auth_session=; Path=/; HttpOnly; Secure; Max-Age=0
```

While this is unlikely to cause a real issue (the cookie is being deleted), it's a good practice to use consistent cookie attributes to avoid browser quirks.

**Recommendation:** Add `SameSite=Lax` to the logout `Set-Cookie` header.

---

### LOW-3: Cookie parser uses dynamic RegExp without escaping cookie name

**File:** `worker-auth/worker.js:101`
**Severity:** Low

```js
const match = header.match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
```

The `name` parameter is interpolated directly into a regular expression. Since `name` is the hardcoded string `'auth_session'`, this is not exploitable. However, if the function were reused with a name containing regex special characters (e.g., `foo.bar`), it would malfunction.

**Recommendation:** Escape the cookie name or use simple string operations:

```js
function getCookie(request, name) {
  const header = request.headers.get('Cookie') || '';
  for (const part of header.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return v.join('=');
  }
  return null;
}
```

---

## Informational Notes

### INFO-1: Unused `next` form field

**File:** `worker-auth/worker.js:129, 46-53`

The login form includes a hidden `next` field, but `handleLogin()` always redirects to `/` regardless. This is dead code that increases the attack surface (see HIGH-2). It should either be implemented or removed.

### INFO-2: Compatibility date could be updated

**File:** `wrangler.toml:3`

The `compatibility_date` is set to `2024-01-01`. While this is fine for now, keeping it up to date ensures you benefit from newer security defaults and behaviors in the Workers runtime. Cloudflare recommends updating it periodically.

### INFO-3: Development secrets in `.dev.vars`

**File:** `.dev.vars`

The development password (`linkboi`) and auth secret are present in `.dev.vars`. This file is correctly gitignored, but:
- Ensure these values are never used in production.
- The auth secret should be regenerated if it is ever accidentally committed.
- The file currently exists in the repo's working directory — confirm it is not being tracked (it appears to be correctly excluded by `.gitignore`).

---

## Positive Findings

These aspects of the implementation are well done:

- **HMAC-SHA256 via Web Crypto API** — uses the platform's native cryptographic primitives rather than a third-party library. Correct use of `crypto.subtle.sign` and `crypto.subtle.verify`.
- **HttpOnly + Secure + SameSite cookies** — prevents the most common cookie theft vectors (XSS, network sniffing, CSRF).
- **Secrets stored in Cloudflare's encrypted secret store** — not in source code or environment files in production.
- **Graceful error handling in `verifyHmac()`** — the try/catch prevents crashes from malformed tokens.
- **Minimal attack surface** — zero dependencies means zero supply-chain risk.
- **`.dev.vars` is gitignored** — local secrets are excluded from version control.

---

## Remediation Priority

| Priority | Finding | Effort |
|----------|---------|--------|
| 1 | HIGH-2: XSS via `next` param (remove unused field) | 1 min |
| 2 | HIGH-1: XSS via `error` param (add escaping) | 5 min |
| 3 | MEDIUM-1: Server-side session expiry check | 10 min |
| 4 | LOW-1: Add security headers | 10 min |
| 5 | MEDIUM-3: Add Cloudflare rate limiting | 15 min |
| 6 | MEDIUM-2: Constant-time password comparison | 15 min |
| 7 | LOW-2: Consistent cookie attributes on logout | 1 min |
| 8 | LOW-3: Safer cookie parser | 5 min |
