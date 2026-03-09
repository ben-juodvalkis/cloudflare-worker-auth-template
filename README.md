# gabrielwagner — Password-Protected Cloudflare Worker

A single Cloudflare Worker that password-protects a static site. No frameworks, no dependencies, no database — just one `worker.js` file using the Web Crypto API.

## How It Works

The worker intercepts every incoming request. If the visitor doesn't have a valid session cookie, they see a login page. If they do, the worker serves `index.html`. The browser never receives protected content without authentication.

```
Request → Worker → Has valid cookie? → Yes → Serve index.html
                                      → No  → Show login page
```

### Request Flow

1. **Unauthenticated visitor** hits any path — worker returns the login form
2. **Login form POST** to `/login` — worker checks the password against `SITE_PASSWORD`
   - Wrong password: 500ms delay (brute-force mitigation), return login page with error
   - Correct password: sign an HMAC token, set it as an `HttpOnly` cookie, redirect to `/`
3. **Authenticated visitor** hits any path — worker verifies the HMAC cookie and serves `index.html`
4. **Logout** via `/logout` — worker clears the cookie and redirects to `/login`

## Project Structure

```
├── index.html                # Protected page content (served after auth)
├── wrangler.toml             # Cloudflare Worker config
├── .dev.vars                 # Local secrets for wrangler dev (gitignored)
├── .gitignore
├── README.md
├── documentation/            # Reference docs
└── worker-auth/
    └── worker.js             # Auth logic + login page template
```

## Setup

### Prerequisites

- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/) installed and authenticated

### Local Development

1. Edit `.dev.vars` with your desired password and a random secret:

   ```
   SITE_PASSWORD=your-password-here
   AUTH_SECRET=<run: openssl rand -hex 32>
   ```

2. Run locally:

   ```bash
   wrangler dev
   ```

### Production Deployment

1. Push secrets to Cloudflare:

   ```bash
   echo "your-password" | wrangler secret put SITE_PASSWORD
   echo "your-hex-secret" | wrangler secret put AUTH_SECRET
   ```

2. Deploy:

   ```bash
   wrangler deploy
   ```

### Changing Secrets

```bash
# Update the password
echo "new-password" | wrangler secret put SITE_PASSWORD

# Rotate the auth secret (invalidates all existing sessions)
openssl rand -hex 32 | wrangler secret put AUTH_SECRET

# List current secrets (names only, values are encrypted)
wrangler secret list
```

## Security Approach

### Authentication

- **HMAC-SHA256 signed cookies** — sessions are signed using the Web Crypto API (`crypto.subtle`). No JWTs, no third-party libraries. The token format is `payload.signature`, where the payload is `auth:<timestamp>` and the signature is a hex-encoded HMAC-SHA256 hash.
- **Server-side verification** — every request verifies the cookie signature against `AUTH_SECRET`. Forging a cookie requires knowing the secret, which never leaves Cloudflare's encrypted secret store.

### Cookie Security

| Flag | Purpose |
|---|---|
| `HttpOnly` | JavaScript cannot access the cookie (blocks XSS-based theft) |
| `Secure` | Cookie is only sent over HTTPS |
| `SameSite=Lax` | Prevents cross-site request forgery in most cases |
| `Max-Age=604800` | Session expires after 7 days |

### Brute-Force Mitigation

Failed login attempts introduce a **500ms server-side delay** before responding. This is a simple throttle that slows automated attacks without requiring rate-limit infrastructure.

### Secret Management

- `SITE_PASSWORD` and `AUTH_SECRET` are stored as **Cloudflare encrypted secrets** — they are not in source control, not visible in the dashboard, and only accessible to the worker at runtime via `env`.
- `.dev.vars` is gitignored and used only for local development.

### What This Does NOT Protect Against

- **Distributed brute-force attacks** — the 500ms delay helps, but for serious protection consider adding Cloudflare's rate limiting or Turnstile captcha.
- **Session revocation** — there's no server-side session store. To invalidate all sessions, rotate `AUTH_SECRET`. Individual session revocation is not supported.
- **Multi-user access control** — this is a single shared password. There are no user accounts or roles.

## Customization

### Changing the Protected Content

Edit `index.html` — that's the page visitors see after logging in. The worker imports it at build time via Wrangler's text module rule.

### Changing the Login Page

The login form is generated inline in the `loginPage()` function in `worker.js` (line 107). Modify the HTML/CSS there.

### Session Duration

Change `Max-Age=604800` in the `Set-Cookie` header inside `handleLogin()` (line 51). Value is in seconds — 604800 = 7 days.
