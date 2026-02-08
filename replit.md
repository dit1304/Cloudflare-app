# Temp Email Bot for Telegram

## Overview
A Telegram bot for creating temporary email addresses and managing 2FA/OTP codes. Built with Cloudflare Workers, Hono.js framework, and Cloudflare D1 (SQLite) database.

## Tech Stack
- **Runtime**: Cloudflare Workers (local dev via Wrangler/Miniflare)
- **Framework**: Hono.js
- **Database**: Cloudflare D1 (SQLite, simulated locally)
- **Language**: TypeScript
- **Build Tool**: Wrangler CLI

## Project Structure
```
src/
  index.ts          - Main app: routes, bot logic, translations
  db/
    schema.sql      - D1 database schema
  handlers/
    admin-domain-handlers.ts - Admin domain management
    domain-handlers.ts       - User domain handlers
    email-handlers.ts        - Email processing handlers
  services/
    custom-domains.ts - Custom domain service
    database.ts       - Database operations
    otp.ts            - OTP generation
    telegram.ts       - Telegram API interactions
  types/
    index.ts          - TypeScript type definitions
  utils/
    domain-utils.ts   - Domain utility functions
    email-parser.ts   - Email parsing (Base64, QP, MIME)
    helpers.ts        - General helpers
    keyboards.ts      - Telegram keyboard builders
    translations.ts   - i18n translations
wrangler.toml         - Cloudflare Workers config
```

## Development
- Dev server: `npm run dev` (runs wrangler dev on port 5000, bound to 0.0.0.0)
- The D1 database is simulated locally by Miniflare
- Webhook endpoint: POST `/webhooks/telegram`
- Health check: GET `/`

## Configuration
- `wrangler.toml` contains non-sensitive env vars (domains, admin ID, etc.)
- Secrets (TELEGRAM_BOT_TOKEN) should be set via wrangler secret or `.dev.vars` file
- Database schema is in `src/db/schema.sql`

## Recent Changes
- 2026-02-09: Fixed custom domain activation bug - added missing `getDomainByName` import in admin-domain-handlers.ts, fixed `InlineKeyboardButton` type to support `url` property, fixed type casting in custom-domains.ts, fixed null/undefined mismatch in domain-handlers.ts
- 2026-02-08: Added comprehensive error handling to handleEmail, sendTelegramMessage, editTelegramMessage; HTML escaping for Telegram notifications; duplicate email graceful handling
- 2026-02-08: Initial Replit setup - configured wrangler dev for port 5000, added health check route, fixed missing extractLinks import
