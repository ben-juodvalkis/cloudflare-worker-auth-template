# gabrielwagner

A password-protected personal site powered by a single Cloudflare Worker. No frameworks, no dependencies, no database — just `worker.js` using the Web Crypto API.

## Quick Start

1. Install the [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/) and authenticate.

2. Set up local secrets in `.dev.vars`:
   ```
   SITE_PASSWORD=your-password-here
   AUTH_SECRET=<run: openssl rand -hex 32>
   ```

3. Run locally:
   ```bash
   wrangler dev
   ```

4. Deploy:
   ```bash
   wrangler deploy
   ```

Push secrets to Cloudflare before your first deploy:
```bash
echo "your-password" | wrangler secret put SITE_PASSWORD
openssl rand -hex 32 | wrangler secret put AUTH_SECRET
```

## How It Works

The worker intercepts every request. Visitors without a valid HMAC-signed session cookie see a login page. Authenticated visitors are served `index.html`.

- Edit `index.html` to change the protected content.
- Edit `loginPage()` in `worker-auth/worker.js` to change the login page.
- Session duration is 7 days (configurable via `Max-Age` in `handleLogin()`).

## Documentation

- [Security architecture, threat model, and operational procedures](documentation/security.md)
- [Implementation reference](documentation/cloudflare-worker-auth-implementation-plan.md)
