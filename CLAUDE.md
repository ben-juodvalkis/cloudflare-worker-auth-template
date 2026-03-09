# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A password-protected personal site powered by a single Cloudflare Worker. No frameworks, no dependencies, no database — just `worker.js` using the Web Crypto API for HMAC-SHA256 cookie-based auth.

## Development Commands

All commands run from the `worker-auth/` directory:

```bash
# Local dev server (reads secrets from .dev.vars)
wrangler dev

# Deploy to Cloudflare
wrangler deploy

# Manage secrets
echo "value" | wrangler secret put SITE_PASSWORD
echo "value" | wrangler secret put AUTH_SECRET
openssl rand -hex 32 | wrangler secret put AUTH_SECRET  # rotate auth secret
```

There is no build step, test runner, or linter configured.

## Architecture

The worker intercepts every request and either serves the login page or the protected content:

- `worker-auth/worker.js` — Single entry point. Contains all auth logic (HMAC signing/verification via `crypto.subtle`), cookie parsing, the inline login page HTML template, and the content-serving function.
- `index.html` (repo root) — The protected page content. Imported by the worker at build time as a text module via Wrangler's `rules` config in `wrangler.toml`.
- `worker-auth/wrangler.toml` — Worker config. The `rules` block enables importing `.html` files as text modules.

### Request Flow

1. Unauthenticated → login form
2. `POST /login` → check password against `env.SITE_PASSWORD`, set HMAC-signed `auth_session` cookie on success (500ms delay on failure)
3. Authenticated → serve `index.html`
4. `/logout` → clear cookie, redirect to `/login`

### Secrets

Two environment secrets required (stored in Cloudflare's encrypted secret store, local dev uses `.dev.vars` which is gitignored):

- `SITE_PASSWORD` — the shared login password
- `AUTH_SECRET` — HMAC signing key for session cookies; rotating it invalidates all sessions
