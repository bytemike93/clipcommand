# Clip Command Service

Express service for the Twitch clip workflow: OAuth login for broadcasters, secure token storage, and a single endpoint to create clips on behalf of users.

## Features

- `/auth/twitch` OAuth flow (scope `clips:edit`) with anti-CSRF state cookie
- Stores encrypted access/refresh tokens in SQLite (`tokens.db`) and issues hashed API tokens
- `/twitch/clips/create/:apiToken` creates clips and refreshes tokens automatically
- Basic rate limiting (1 clip per 15s per IP)

## Requirements

- Node.js 18+
- SQLite (local `tokens.db`)
- `.env` with Twitch credentials and encryption key (see `.env.example`)

## Setup

```bash
npm install
cp .env.example .env     # fill in Twitch app + secrets
npm start                # default port 3001
```

## Environment

- `PORT` (default 3001)
- `TWITCH_CLIENT_ID` / `TWITCH_CLIENT_SECRET` / `TWITCH_REDIRECT_URI`
- `TOKEN_ENCRYPTION_KEY` – required for encrypting stored tokens
- `COOKIE_SECRET` – signs the OAuth state cookie
- `HTTP_TIMEOUT_MS` – optional axios timeout

## API

- `GET /auth/twitch` – start OAuth, redirects to Twitch
- `GET /auth/twitch/callback` – completes OAuth, stores tokens, redirects with `api_token`
- `POST /twitch/clips/create/:apiToken` – creates a clip for the associated broadcaster

## Deployment

- PM2 config: `ecosystem.config.js`
- Keep `tokens.db` and `TOKEN_ENCRYPTION_KEY` secure and backed up
- Behind HTTPS for OAuth callbacks; set correct `TWITCH_REDIRECT_URI`

## Tools

- `export_tokens.py` – exports users (Twitch IDs/logins) from `tokens.db` to `clipcommand-users.txt`
