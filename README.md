# 📧 Temp Email Bot untuk Telegram

Bot Telegram yang powerful untuk membuat email temporary dan mengelola 2FA/OTP codes. Berjalan di Cloudflare Workers dengan D1 Database.

## ✨ Fitur Utama

### 📧 Email Management
- **Buat Email Temporary**: Buat unlimited email addresses (free: max 3)
- **Multi-Domain Support**: Pilih dari berbagai domain yang tersedia
- **Real-time Notifications**: Notifikasi instant saat email masuk
- **Email Parser**: Decode otomatis untuk berbagai encoding (Base64, Quoted-Printable, RFC 2047)
- **Search & Filter**: Cari email berdasarkan sender, subject, atau content
- **Auto-Delete**: Atur auto-delete email otomatis (3, 7, 14, 30 hari, atau never)
- **Catch-All**: Email yang tidak terdaftar otomatis diteruskan ke admin

### 🔐 2FA/OTP Manager
- **Generate OTP**: Generate TOTP codes dari secret key
- **Save Secrets**: Simpan multiple 2FA secrets dengan nama
- **QR Code**: Generate QR code untuk import ke authenticator app
- **Backup**: Backup semua 2FA secrets
- **Auto-Refresh**: Lihat remaining time dan refresh otomatis

### 👤 User Management
- **Multi-Language**: Support Bahasa Indonesia dan English
- **Premium System**: Free tier dengan limits, Premium unlimited
- **Statistics**: Lihat usage statistics personal
- **Settings**: Customize auto-delete, language, timezone

### 🔧 Admin Features
- **Dashboard**: Statistik bot lengkap
- **User Management**: Lihat dan kelola users
- **Premium Control**: Upgrade/downgrade users
- **Blacklist**: Block spam senders
- **Broadcast**: Send message ke semua users
- **Cleanup**: Automatic cleanup untuk old emails

## 🚀 Tech Stack

- **Runtime**: Cloudflare Workers (Edge Computing)
- **Framework**: Hono.js (Lightweight & Fast)
- **Database**: Cloudflare D1 (SQLite at the Edge)
- **Language**: TypeScript dengan strict mode
- **CI/CD**: GitHub Actions
- **Integration**: 
  - Telegram Bot API
  - Cloudflare Email Routing
  - OTPAuth untuk TOTP generation

## 📋 Prerequisites

1. **Cloudflare Account** (free tier OK)
2. **Telegram Bot Token** dari [@BotFather](https://t.me/BotFather)
3. **Custom Domain** untuk email routing (gratis di Cloudflare)
4. **Node.js** 18+ untuk development

## 🛠️ Setup & Installation

### 1. Clone Repository

```bash
git clone <your-repo-url>
cd temp-email-bot-cf
```

### 2. Install Dependencies

```bash
npm install
```

### 3. Setup Cloudflare

#### 3.1 Create D1 Database

```bash
npx wrangler d1 create temp-email-db
```

Salin `database_id` yang muncul dan update di `wrangler.toml`

#### 3.2 Run Database Migration

```bash
npx wrangler d1 execute temp-email-db --file=./src/db/schema.sql
```

### 4. Configure Environment

#### 4.1 Update `wrangler.toml`

```toml
name = "temp-email-bot"
main = "src/index.ts"
compatibility_date = "2024-01-01"

[vars]
TEMP_EMAIL_DOMAIN = "yourdomain.com,yourdomain2.com"
ADMIN_USER_ID = "YOUR_TELEGRAM_USER_ID"
FALLBACK_EMAIL = "your-email@gmail.com"
WORKER_URL = "your-worker.workers.dev"

[[d1_databases]]
binding = "DB"
database_name = "temp-email-db"
database_id = "your-database-id-here"
```

#### 4.2 Add Secrets

```bash
npx wrangler secret put TELEGRAM_BOT_TOKEN
# Paste your bot token from @BotFather
```

### 5. Setup Email Routing

1. Go to Cloudflare Dashboard → Email → Email Routing
2. Enable Email Routing untuk domain Anda
3. Add destination address (fallback email)
4. Add Catch-All route ke Worker:
   - Pattern: `*@yourdomain.com`
   - Action: Send to Worker
   - Worker: `temp-email-bot`

### 6. Deploy

```bash
npm run deploy
```

### 7. Setup Telegram Webhook

Setelah deploy, set webhook:

```bash
curl -X POST "https://api.telegram.org/bot<YOUR_BOT_TOKEN>/setWebhook" \
  -H "Content-Type: application/json" \
  -d '{"url":"https://your-worker.workers.dev/webhooks/telegram"}'
```

## 📝 Configuration

### Environment Variables

| Variable | Type | Description | Required |
|----------|------|-------------|----------|
| `TELEGRAM_BOT_TOKEN` | Secret | Bot token dari BotFather | ✅ |
| `TEMP_EMAIL_DOMAIN` | Var | Domain untuk email (comma-separated) | ✅ |
| `ADMIN_USER_ID` | Var | Telegram User ID admin | ✅ |
| `FALLBACK_EMAIL` | Var | Email fallback untuk forwarding | ❌ |
| `WORKER_URL` | Var | URL Worker (untuk webhook) | ❌ |

### Limits (Free Tier)

```typescript
FREE_MAX_EMAILS: 3        // Max email addresses
FREE_MAX_2FA: 5           // Max 2FA secrets
FREE_MAX_INBOX: 50        // Max inbox messages
```

Edit di `src/types/index.ts` untuk customize limits.

## 🎮 Usage

### Basic Commands

```
/start   - Start bot dan language selection
/menu    - Show interactive menu
/help    - Show all commands

📧 Email:
/create <name>        - Create new email
/create name@domain   - Create with specific domain
/mails <name>         - Check inbox
/read <id>            - Read email
/list                 - List all emails
/search <query>       - Search emails
/domains              - Show available domains

🔐 2FA/OTP:
/2fa <secret>         - Generate OTP code
/2fa add <name> <secret> - Save secret
/2fa list             - List saved secrets
/qr <name>            - Generate QR code
/backup               - Backup all secrets

👤 Account:
/mystats              - Your statistics
/settings             - Settings (auto-delete)
/lang                 - Change language

🔧 Admin Only:
/stats                - Bot statistics
/users                - List users
/premium add <id>     - Add premium user
/blacklist            - Manage blacklist
/cleanup              - Clean old emails
/broadcast <message>  - Broadcast to all
```

### Interactive Menu

Bot menggunakan inline keyboard untuk navigasi yang mudah:
- Tap tombol untuk aksi cepat
- Message di-edit instead of spam
- Context-aware buttons

## 🏗️ Architecture

```
src/
├── index.ts                 # Entry point & main app
├── types/
│   └── index.ts            # TypeScript definitions
├── services/
│   ├── database.ts         # Database operations
│   ├── telegram.ts         # Telegram API client
│   └── otp.ts              # OTP/2FA generator
├── handlers/
│   ├── email-handlers.ts   # Email command handlers
│   └── ...                 # Other handlers
├── utils/
│   ├── email-parser.ts     # Enhanced email parsing
│   ├── helpers.ts          # Helper functions
│   ├── translations.ts     # i18n translations
│   └── keyboards.ts        # Inline keyboard builders
└── db/
    └── schema.sql          # Database schema
```

## 🔧 Development

### Local Development

```bash
npm run dev
```

### Run Migration

```bash
npm run db:migrate        # Local
npm run db:migrate:prod   # Production
```

### Type Checking

```bash
npx tsc --noEmit
```

## 🐛 Troubleshooting

### Email Decoding Issues

Bot sudah dilengkapi dengan advanced email parser yang support:
- ✅ Base64 encoding
- ✅ Quoted-Printable encoding
- ✅ RFC 2047 encoded headers
- ✅ Multiple charsets (UTF-8, ISO-8859-1, Windows-1252)
- ✅ Malformed emails

Jika masih ada masalah decoding, check:
1. Log di Cloudflare Workers dashboard
2. Raw email di fallback email
3. Report issue dengan sample email

### Webhook Not Working

```bash
# Check webhook status
curl "https://api.telegram.org/bot<TOKEN>/getWebhookInfo"

# Delete webhook
curl "https://api.telegram.org/bot<TOKEN>/deleteWebhook"

# Set webhook again
curl -X POST "https://api.telegram.org/bot<TOKEN>/setWebhook" \
  -H "Content-Type: application/json" \
  -d '{"url":"https://your-worker.workers.dev/webhooks/telegram"}'
```

### Email Not Received

1. Check Email Routing di Cloudflare Dashboard
2. Verify domain DNS settings
3. Check Catch-All route ke Worker
4. Check Worker logs

## 📊 Database Schema

```sql
users              - Telegram users
  ├── emails       - Email addresses (1:N)
  │   └── inbox    - Incoming emails (1:N)
  ├── totp_secrets - 2FA secrets (1:N)
  └── blacklist    - Blocked senders (1:N)
```

## 🚀 Performance

- **Edge Computing**: Sub-100ms response time globally
- **Serverless**: Auto-scaling, pay-per-use
- **Zero Maintenance**: No server to manage
- **Global CDN**: Cloudflare's edge network

## 🔒 Security

- ✅ Environment secrets (never committed)
- ✅ SQL injection protection (prepared statements)
- ✅ Rate limiting (recommended: implement with KV)
- ✅ Admin-only commands
- ✅ User isolation
- ⚠️ Add rate limiting for production use

## 📈 Monitoring

Monitor via Cloudflare Dashboard:
- Workers Analytics
- D1 Database metrics
- Error tracking
- Request logs

## 🤝 Contributing

1. Fork repository
2. Create feature branch
3. Commit changes
4. Push to branch
5. Create Pull Request

## 📄 License

MIT License - see LICENSE file

## 👨‍💻 Author

**Created & Maintained by:** [@kakatiri](https://t.me/kakatiri)

## 🙏 Credits

- [Hono.js](https://hono.dev/) - Web framework
- [OTPAuth](https://github.com/hectorm/otpauth) - TOTP library
- [Cloudflare Workers](https://workers.cloudflare.com/) - Edge platform

## 📞 Support

- 👨‍💻 Developer: [@kakatiri](https://t.me/kakatiri) on Telegram
- 🐛 Issues: GitHub Issues
- 💬 Discussions: GitHub Discussions

## 🗺️ Roadmap

- [ ] Rate limiting with KV
- [ ] Email forwarding dengan SMTP
- [ ] Webhook untuk external services
- [ ] Email attachments support
- [ ] Custom email rules/filters
- [ ] Web dashboard
- [ ] API endpoints
- [ ] Docker support
- [ ] Unit tests
- [ ] E2E tests

---

Made with ❤️ using Cloudflare Workers
