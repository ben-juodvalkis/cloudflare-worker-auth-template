# Security Documentation

Detailed security architecture, threat model, and operational procedures for the Cloudflare Worker authentication system.

## Architecture Overview

A single Cloudflare Worker (`worker-auth/worker.js`) intercepts every incoming request. Unauthenticated visitors see a login page; authenticated visitors are served `index.html`. The browser never receives protected content without a valid session.

```
Request → Worker → Has valid cookie? → Yes → Serve index.html
                                      → No  → Show login page
```

### Request Flow

1. **Unauthenticated visitor** hits any path — worker returns the login form
2. **Login form POST** to `/login` — worker checks the password against `SITE_PASSWORD`
   - Wrong password: 500ms delay, return login page with error
   - Correct password: sign an HMAC token, set it as an `HttpOnly` cookie, redirect to `/`
3. **Authenticated visitor** hits any path — worker verifies the HMAC cookie and serves `index.html`
4. **Logout** via `POST /logout` — worker clears the cookie and redirects to `/login`

### Project Structure

```
├── index.html                # Protected page content (served after auth)
├── wrangler.toml             # Cloudflare Worker config + rate limiting binding
├── .dev.vars                 # Local secrets for wrangler dev (gitignored)
├── .gitignore
├── README.md
├── CLAUDE.md
├── documentation/            # Reference docs
│   └── security.md           # This file
└── worker-auth/
    └── worker.js             # Auth logic + login page template
```

## Authentication

### HMAC-SHA256 Signed Cookies

Sessions are signed using the Web Crypto API (`crypto.subtle`). No JWTs, no third-party libraries.

**Token format:** `auth:<timestamp>:<nonce>.<hmac-sha256-hex>`

- `auth` — fixed prefix
- `<timestamp>` — `Date.now()` at login time, used for session expiry checks
- `<nonce>` — `crypto.randomUUID()`, ensures unique tokens even for simultaneous logins
- `<hmac-sha256-hex>` — hex-encoded HMAC-SHA256 signature of the payload

**Verification:** Every request extracts the cookie, splits payload from signature, and calls `crypto.subtle.verify()` to check the HMAC. The timestamp is parsed to enforce the 7-day session maximum.

### Timing-Safe Password Comparison

Password comparison uses an HMAC-then-compare pattern rather than direct string equality:

1. Both the submitted password and the stored password are HMAC-signed with a fixed key
2. The resulting byte arrays are XOR-compared in constant time
3. This prevents timing side-channel attacks that could leak password characters

### Input Validation

- Missing or non-string password submissions are rejected before comparison
- Malformed cookies (bad hex, missing dot separator) are caught and rejected
- Error messages are HTML-escaped to prevent XSS

## Cookie Security

| Flag | Purpose |
|---|---|
| `HttpOnly` | JavaScript cannot access the cookie (blocks XSS-based theft) |
| `Secure` | Cookie is only sent over HTTPS |
| `SameSite=Lax` | Prevents cross-site request forgery in most cases |
| `Max-Age=604800` | Cookie expires after 7 days (server also validates timestamp) |

Session expiry is enforced both client-side (cookie `Max-Age`) and server-side (timestamp check against `SESSION_MAX_AGE_MS`).

## Rate Limiting

Login attempts are rate-limited using the Cloudflare Worker Rate Limiting API:

- **Limit:** 10 requests per 60-second window per IP
- **Scope:** `POST /login` only
- **Key:** `cf-connecting-ip` header (Cloudflare's true client IP)
- **Response:** HTTP 429 with "Too many attempts. Try again later."

This is configured in `wrangler.toml`:

```toml
[[rate_limiting]]
binding = "LOGIN_RATE_LIMITER"
namespace_id = "1001"
simple = { limit = 10, period = 60 }
```

In addition to rate limiting, failed login attempts include a **500ms server-side delay** to slow sequential brute-force attempts.

## HTTP Security Headers

All responses include the following headers via `withSecurityHeaders()`:

| Header | Value | Purpose |
|---|---|---|
| `X-Content-Type-Options` | `nosniff` | Prevents MIME-type sniffing |
| `X-Frame-Options` | `DENY` | Prevents clickjacking via iframes |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Limits referrer information leakage |
| `Content-Security-Policy` | `default-src 'self'; style-src 'unsafe-inline'` | Restricts resource loading origins |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | Enforces HTTPS for 1 year, prevents downgrade attacks |

### CSP Note

`style-src 'unsafe-inline'` is required because both the login page and protected page use inline `<style>` blocks. This is acceptable because there is no user-generated content in the application.

## CSRF Protection

- **Login:** The login form uses `SameSite=Lax` cookies, which prevents cross-site POST submissions from foreign origins in modern browsers.
- **Logout:** Uses `POST`-only with a form submission, preventing CSRF logout attacks via `<img>` or `<link>` tags that would work against GET-based logout endpoints.

## Secret Management

### Secrets Required

| Secret | Purpose |
|---|---|
| `SITE_PASSWORD` | The shared login password |
| `AUTH_SECRET` | HMAC signing key for session cookies |

### Storage

- **Production:** Stored as Cloudflare encrypted secrets. Not visible in the dashboard, not in source control. Only accessible to the worker at runtime via `env`.
- **Local development:** Stored in `.dev.vars` (gitignored). Format:
  ```
  SITE_PASSWORD=your-password-here
  AUTH_SECRET=<run: openssl rand -hex 32>
  ```

### Rotation

```bash
# Update the password
echo "new-password" | wrangler secret put SITE_PASSWORD

# Rotate the auth secret (invalidates ALL existing sessions)
openssl rand -hex 32 | wrangler secret put AUTH_SECRET

# List current secrets (names only, values are encrypted)
wrangler secret list
```

Rotating `AUTH_SECRET` is the only way to invalidate sessions. There is no server-side session store, so individual session revocation is not supported.

## Threat Model

### What This Protects Against

| Threat | Defense |
|---|---|
| Unauthorized content access | HMAC-signed session cookies verified on every request |
| Cookie theft via XSS | `HttpOnly` flag prevents JavaScript access |
| Cookie theft via network sniffing | `Secure` flag restricts to HTTPS; HSTS prevents downgrade |
| Cookie forgery | Requires knowledge of `AUTH_SECRET`, which never leaves Cloudflare |
| CSRF login/logout | `SameSite=Lax` cookies; POST-only logout |
| Brute-force password guessing | Rate limiting (10/min per IP) + 500ms delay per failure |
| Timing attacks on password check | HMAC-then-compare constant-time comparison |
| Clickjacking | `X-Frame-Options: DENY` |
| Content-type sniffing | `X-Content-Type-Options: nosniff` |
| Password in source code | Cloudflare encrypted secrets, `.dev.vars` gitignored |

### Known Limitations

- **Single shared password** — no user accounts, no roles, no audit trail of who logged in
- **No individual session revocation** — rotating `AUTH_SECRET` invalidates all sessions; there is no way to revoke a single session
- **No CAPTCHA/challenge** — rate limiting mitigates automated attacks, but there is no human-verification step
- **Inline styles require `unsafe-inline` in CSP** — acceptable given no user-generated content
- **No server-side session store** — session state is entirely in the signed cookie; the worker is stateless

## Operational Procedures

### Deploying

```bash
wrangler deploy
```

### Responding to a Suspected Compromise

1. **Rotate `AUTH_SECRET`** immediately to invalidate all sessions:
   ```bash
   openssl rand -hex 32 | wrangler secret put AUTH_SECRET
   ```
2. **Change `SITE_PASSWORD`:**
   ```bash
   echo "new-password" | wrangler secret put SITE_PASSWORD
   ```
3. Redeploy is not necessary — secret changes take effect immediately.

### Monitoring

- Cloudflare dashboard provides request analytics, error rates, and Worker metrics.
- Rate limiting counters are visible in Worker analytics when rate-limited requests return 429.
