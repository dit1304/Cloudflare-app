import { Hono } from "hono";
import * as OTPAuth from "otpauth";

type Bindings = {
  DB: D1Database;
  TELEGRAM_BOT_TOKEN: string;
  TEMP_EMAIL_DOMAIN: string;
  ADMIN_USER_ID: string;
  FALLBACK_EMAIL: string;
};

const app = new Hono<{ Bindings: Bindings }>();

// ============ TELEGRAM WEBHOOK ============
app.post("/webhooks/telegram", async (c) => {
  const payload = await c.req.json();
  console.log("📨 Telegram webhook received:", JSON.stringify(payload));

  if (!payload.message?.text) {
    return c.text("OK", 200);
  }

  const telegramUserId = String(payload.message.from.id);
  const telegramUsername = payload.message.from.username || "";
  const chatId = payload.message.chat.id;
  const userMessage = payload.message.text.trim();

  try {
    await ensureUser(c.env.DB, telegramUserId, telegramUsername);
    const response = await processCommand(c.env, telegramUserId, userMessage);
    await sendTelegramMessage(c.env.TELEGRAM_BOT_TOKEN, chatId, response);
  } catch (error) {
    console.error("Error processing message:", error);
    await sendTelegramMessage(
      c.env.TELEGRAM_BOT_TOKEN,
      chatId,
      "❌ Maaf, terjadi kesalahan. Silakan coba lagi."
    );
  }

  return c.text("OK", 200);
});

// ============ EMAIL HANDLER (from Cloudflare Email Routing) ============
function parseFromHeader(fromHeader: string, rawFrom: string): string {
  // Try to extract display name from "From" header
  // Format: "Display Name <email@example.com>" or just "email@example.com"
  if (fromHeader) {
    const match = fromHeader.match(/^["']?([^"'<]+)["']?\s*<[^>]+>$/);
    if (match && match[1]) {
      const displayName = match[1].trim();
      // Return "Display Name (email)" format
      return `${displayName}`;
    }
  }
  // Fallback: clean up technical bounce addresses
  // msprvs1=xxx=bounces-xxx@domain -> just show domain
  if (rawFrom.includes('=') && rawFrom.includes('bounces')) {
    const domain = rawFrom.split('@')[1];
    return domain || rawFrom;
  }
  return rawFrom;
}

async function handleEmail(message: ForwardableEmailMessage, env: Bindings) {
  console.log(`📧 Email received: ${message.from} -> ${message.to}`);

  const toAddress = message.to.toLowerCase();
  const subject = message.headers.get("subject") || "(Tanpa subjek)";
  const fromHeader = message.headers.get("from") || "";
  const senderDisplay = parseFromHeader(fromHeader, message.from);
  const senderLower = message.from.toLowerCase();

  // Check global blacklist (managed by admin, applies to all)
  try {
    const blacklisted = await env.DB.prepare(
      "SELECT id FROM blacklist WHERE ? LIKE '%' || sender_pattern || '%'"
    ).bind(senderLower).first();

    if (blacklisted) {
      console.log(`🚫 Email blocked (blacklisted sender): ${message.from}`);
      return;
    }
  } catch (e) {
    console.error("Blacklist check error:", e);
  }

  const email = await env.DB.prepare(
    "SELECT e.id, e.user_id, u.telegram_user_id FROM emails e JOIN users u ON e.user_id = u.id WHERE LOWER(e.email_address) = ?"
  )
    .bind(toAddress)
    .first<{ id: number; user_id: number; telegram_user_id: string }>();

  if (!email) {
    console.log("Email address not found, creating catch-all entry:", toAddress);
    
    try {
      // Auto-create email for admin (catch-all)
      const adminUserId = await getOrCreateAdminUser(env.DB, env.ADMIN_USER_ID);
      const localPart = toAddress.split("@")[0];
      
      // Create the email address and assign to admin
      const emailResult = await env.DB.prepare(
        "INSERT INTO emails (user_id, email_address, local_part, is_active) VALUES (?, ?, ?, 1) RETURNING id"
      )
        .bind(adminUserId, toAddress, localPart)
        .first<{ id: number }>();
    
    if (emailResult) {
        const rawEmail = await new Response(message.raw).text();
        const body = extractEmailBody(rawEmail);
        
        // Save to inbox
        const inboxResult = await env.DB.prepare(
          "INSERT INTO inbox (email_id, sender, subject, body, headers) VALUES (?, ?, ?, ?, ?) RETURNING id"
        )
          .bind(emailResult.id, message.from, subject, body, JSON.stringify(Object.fromEntries(message.headers)))
          .first<{ id: number }>();
        
        // Forward to fallback as backup
        if (env.FALLBACK_EMAIL) {
          await message.forward(env.FALLBACK_EMAIL);
        }
        
        // Notify admin
        const botToken = env.TELEGRAM_BOT_TOKEN;
        if (botToken && env.ADMIN_USER_ID) {
          const msgId = inboxResult?.id || "";
          const notificationText = `📨 <b>Email Baru (Catch-All)</b>

📧 <b>Ke:</b> ${toAddress}
👤 <b>Dari:</b> ${senderDisplay}
📋 <b>Subjek:</b> ${subject}

📖 Baca: <code>/read ${msgId}</code>
📬 Inbox: <code>/mails ${localPart}</code>`;
          await sendTelegramMessage(botToken, parseInt(env.ADMIN_USER_ID), notificationText);
        }
      }
    } catch (e) {
      console.error("Catch-all email creation error:", e);
      // Still forward to fallback on error
      if (env.FALLBACK_EMAIL) {
        await message.forward(env.FALLBACK_EMAIL);
      }
    }
    return;
  }

  const rawEmail = await new Response(message.raw).text();
  const body = extractEmailBody(rawEmail);

  await env.DB.prepare(
    "INSERT INTO inbox (email_id, sender, subject, body, headers) VALUES (?, ?, ?, ?, ?)"
  )
    .bind(email.id, message.from, subject, body, JSON.stringify(Object.fromEntries(message.headers)))
    .run();

  const notificationText = `📬 <b>Email Baru!</b>

📧 <b>Ke:</b> ${toAddress}
👤 <b>Dari:</b> ${senderDisplay}
📋 <b>Subjek:</b> ${subject}

Ketik <code>/mails ${toAddress.split("@")[0]}</code> untuk membaca.`;

  const botToken = env.TELEGRAM_BOT_TOKEN;
  if (botToken) {
    await sendTelegramMessage(botToken, parseInt(email.telegram_user_id), notificationText);
  }
}

// ============ COMMAND PROCESSOR ============
async function processCommand(
  env: Bindings,
  telegramUserId: string,
  message: string
): Promise<string> {
  console.log("🤖 Processing command:", { telegramUserId, message });

  const parts = message.split(/\s+/);
  const command = parts[0].toLowerCase();
  const arg = parts.slice(1).join(" ").trim();

  const isAdmin = telegramUserId === env.ADMIN_USER_ID;

  switch (command) {
    case "/start":
    case "/help":
      return getHelpMessage(env.TEMP_EMAIL_DOMAIN);

    case "/create":
      return await handleCreate(env, telegramUserId, arg);

    case "/mails":
    case "/inbox":
      return await handleMails(env, telegramUserId, arg);

    case "/read":
      return await handleRead(env, telegramUserId, arg);

    case "/list":
      if (!isAdmin) {
        return `⛔ Perintah ini hanya untuk admin.`;
      }
      return await handleList(env, telegramUserId);

    case "/delete":
      if (!isAdmin) {
        return `⛔ Perintah ini hanya untuk admin.`;
      }
      return await handleDelete(env, telegramUserId, arg);

    case "/2fa":
    case "/otp":
      return await handle2FA(env, telegramUserId, arg);

    case "/search":
      return await handleSearch(env, telegramUserId, arg);

    case "/stats":
      if (!isAdmin) {
        return `⛔ Perintah ini hanya untuk admin.`;
      }
      return await handleStats(env);

    case "/blacklist":
      return await handleBlacklist(env, telegramUserId, arg);

    case "/forward":
    case "/export":
      return await handleForward(env, telegramUserId, arg);

    case "/cleanup":
      if (!isAdmin) {
        return `⛔ Perintah ini hanya untuk admin.`;
      }
      return await handleCleanup(env);

    default:
      return `❓ Perintah tidak dikenali.

Ketik /start untuk melihat panduan.`;
  }
}

// ============ COMMAND HANDLERS ============

// Generate OTP code from secret
function generateOTP(secret: string): { code: string; remaining: number } | null {
  try {
    const cleanSecret = secret.trim().replace(/ /g, '').toUpperCase();
    const totp = new OTPAuth.TOTP({
      algorithm: "SHA1",
      digits: 6,
      period: 30,
      secret: OTPAuth.Secret.fromBase32(cleanSecret)
    });
    const code = totp.generate();
    const now = Math.floor(Date.now() / 1000);
    const remaining = 30 - (now % 30);
    return { code, remaining };
  } catch (e) {
    return null;
  }
}

async function handle2FA(env: Bindings, telegramUserId: string, arg: string): Promise<string> {
  const parts = arg.split(/\s+/);
  const subCommand = parts[0]?.toLowerCase();
  const param1 = parts[1] || "";
  const param2 = parts.slice(2).join(" ") || "";

  const userId = await getUserId(env.DB, telegramUserId);
  if (!userId) {
    return `❌ Error: User tidak ditemukan.`;
  }

  // /2fa add nama secret
  if (subCommand === "add" || subCommand === "save") {
    if (!param1 || !param2) {
      return `⚠️ Format: <code>/2fa add nama SECRET_KEY</code>

Contoh: <code>/2fa add google JBSWY3DPEHPK3PXP</code>`;
    }
    const name = param1.toLowerCase();
    const secret = param2.replace(/ /g, '').toUpperCase();
    
    // Validate secret
    if (!generateOTP(secret)) {
      return `❌ Secret key tidak valid. Pastikan format Base32 benar.`;
    }

    try {
      await env.DB.prepare(
        "INSERT OR REPLACE INTO totp_secrets (user_id, name, secret) VALUES (?, ?, ?)"
      ).bind(userId, name, secret).run();
      
      return `✅ 2FA secret "<b>${name}</b>" berhasil disimpan!

📋 Lihat semua: <code>/2fa list</code>
🔢 Generate kode: <code>/2fa ${name}</code>`;
    } catch (e) {
      return `❌ Gagal menyimpan secret.`;
    }
  }

  // /2fa list
  if (subCommand === "list") {
    const result = await env.DB.prepare(
      "SELECT name, created_at FROM totp_secrets WHERE user_id = ? ORDER BY name"
    ).bind(userId).all();

    if (!result.results || result.results.length === 0) {
      return `📭 Belum ada 2FA secret tersimpan.

➕ Tambah: <code>/2fa add nama SECRET_KEY</code>`;
    }

    let response = `🔐 <b>Daftar 2FA Secret</b>\n\n`;
    for (const item of result.results as any[]) {
      response += `🔑 <b>${item.name}</b>\n`;
    }
    response += `\n━━━━━━━━━━━━━━━
🔢 Generate: <code>/2fa nama</code>
🗑️ Hapus: <code>/2fa del nama</code>`;
    return response;
  }

  // /2fa del nama
  if (subCommand === "del" || subCommand === "delete" || subCommand === "rm") {
    if (!param1) {
      return `⚠️ Format: <code>/2fa del nama</code>`;
    }
    const name = param1.toLowerCase();
    
    const result = await env.DB.prepare(
      "DELETE FROM totp_secrets WHERE user_id = ? AND name = ?"
    ).bind(userId, name).run();

    if (result.meta.changes === 0) {
      return `❌ Secret "<b>${name}</b>" tidak ditemukan.`;
    }
    return `✅ Secret "<b>${name}</b>" berhasil dihapus.`;
  }

  // /2fa (no args) - show help
  if (!arg) {
    return `🔐 <b>2FA/OTP Manager</b>

📋 <b>Perintah:</b>

<code>/2fa SECRET_KEY</code>
Generate kode OTP langsung

<code>/2fa add nama SECRET</code>
Simpan secret dengan nama

<code>/2fa list</code>
Lihat semua secret tersimpan

<code>/2fa nama</code>
Generate kode dari secret tersimpan

<code>/2fa del nama</code>
Hapus secret tersimpan`;
  }

  // /2fa nama - generate from saved secret
  const savedSecret = await env.DB.prepare(
    "SELECT secret FROM totp_secrets WHERE user_id = ? AND name = ?"
  ).bind(userId, subCommand).first<{ secret: string }>();

  if (savedSecret) {
    const otp = generateOTP(savedSecret.secret);
    if (otp) {
      return `🔐 <b>${subCommand}</b>

🔢 Kode OTP: <code>${otp.code}</code>
⏱️ Berlaku: ${otp.remaining} detik`;
    }
  }

  // /2fa SECRET_KEY - generate directly
  const secrets = arg.split('\n');
  let responseText = "";
  let successCount = 0;

  for (let secret of secrets) {
    secret = secret.trim().replace(/ /g, '').toUpperCase();
    if (secret.length < 8) continue;

    const otp = generateOTP(secret);
    if (otp) {
      responseText += `🔑 <code>${secret.substring(0, 8)}...</code>
🔢 Kode OTP: <code>${otp.code}</code>
⏱️ Berlaku: ${otp.remaining} detik

`;
      successCount++;
    } else {
      responseText += `❌ <code>${secret.substring(0, 8)}...</code> - Tidak valid

`;
    }
  }

  if (successCount === 0) {
    return `❌ Secret key tidak valid.

Pastikan format secret key benar (Base32).
Contoh: <code>/2fa JBSWY3DPEHPK3PXP</code>

💡 Atau simpan secret: <code>/2fa add nama SECRET</code>`;
  }

  return `🔐 <b>Kode OTP</b>

${responseText}━━━━━━━━━━━━━━━
💡 Kode berubah setiap 30 detik.
💾 Simpan: <code>/2fa add nama SECRET</code>`;
}

// Search emails
async function handleSearch(env: Bindings, telegramUserId: string, query: string): Promise<string> {
  if (!query) {
    return `🔍 <b>Cari Email</b>

Format: <code>/search kata_kunci</code>

Contoh:
<code>/search verifikasi</code>
<code>/search google</code>`;
  }

  const isAdmin = telegramUserId === env.ADMIN_USER_ID;
  const userId = await getUserId(env.DB, telegramUserId);
  if (!userId) return `❌ Error: User tidak ditemukan.`;

  const searchPattern = `%${query}%`;
  
  let result;
  if (isAdmin) {
    result = await env.DB.prepare(`
      SELECT i.id, i.sender, i.subject, i.received_at, e.email_address
      FROM inbox i
      JOIN emails e ON i.email_id = e.id
      WHERE i.sender LIKE ? OR i.subject LIKE ? OR i.body LIKE ?
      ORDER BY i.received_at DESC LIMIT 20
    `).bind(searchPattern, searchPattern, searchPattern).all();
  } else {
    result = await env.DB.prepare(`
      SELECT i.id, i.sender, i.subject, i.received_at, e.email_address
      FROM inbox i
      JOIN emails e ON i.email_id = e.id
      WHERE e.user_id = ? AND (i.sender LIKE ? OR i.subject LIKE ? OR i.body LIKE ?)
      ORDER BY i.received_at DESC LIMIT 20
    `).bind(userId, searchPattern, searchPattern, searchPattern).all();
  }

  if (!result.results || result.results.length === 0) {
    return `🔍 Tidak ditemukan hasil untuk "<b>${query}</b>"`;
  }

  let response = `🔍 <b>Hasil Pencarian: "${query}"</b>\n\n`;
  for (const msg of result.results as any[]) {
    response += `📧 <b>ID ${msg.id}</b> - ${msg.email_address.split('@')[0]}
👤 ${msg.sender.substring(0, 30)}
📋 ${(msg.subject || "(Tanpa subjek)").substring(0, 40)}

`;
  }
  response += `━━━━━━━━━━━━━━━
📖 Baca: <code>/read ID</code>`;
  return response;
}

// Statistics (admin only)
async function handleStats(env: Bindings): Promise<string> {
  const users = await env.DB.prepare("SELECT COUNT(*) as count FROM users").first<{ count: number }>();
  const emails = await env.DB.prepare("SELECT COUNT(*) as count FROM emails WHERE is_active = 1").first<{ count: number }>();
  const messages = await env.DB.prepare("SELECT COUNT(*) as count FROM inbox").first<{ count: number }>();
  const unread = await env.DB.prepare("SELECT COUNT(*) as count FROM inbox WHERE is_read = 0").first<{ count: number }>();
  const secrets = await env.DB.prepare("SELECT COUNT(*) as count FROM totp_secrets").first<{ count: number }>();
  const todayEmails = await env.DB.prepare(
    "SELECT COUNT(*) as count FROM inbox WHERE received_at >= datetime('now', '-1 day')"
  ).first<{ count: number }>();

  return `📊 <b>Statistik Bot</b>

👥 Total User: <b>${users?.count || 0}</b>
📧 Email Aktif: <b>${emails?.count || 0}</b>
📬 Total Pesan: <b>${messages?.count || 0}</b>
📩 Belum Dibaca: <b>${unread?.count || 0}</b>
🔐 2FA Secrets: <b>${secrets?.count || 0}</b>

📈 <b>Hari Ini:</b>
📨 Email Masuk: <b>${todayEmails?.count || 0}</b>`;
}

// Blacklist management
async function handleBlacklist(env: Bindings, telegramUserId: string, arg: string): Promise<string> {
  const isAdmin = telegramUserId === env.ADMIN_USER_ID;
  if (!isAdmin) {
    return `⛔ Perintah ini hanya untuk admin.`;
  }

  const userId = await getUserId(env.DB, telegramUserId);
  if (!userId) return `❌ Error: User tidak ditemukan.`;

  const parts = arg.split(/\s+/);
  const subCommand = parts[0]?.toLowerCase();
  const pattern = parts.slice(1).join(" ") || "";

  // /blacklist add pattern
  if (subCommand === "add") {
    if (!pattern) {
      return `⚠️ Format: <code>/blacklist add pola_email</code>

Contoh:
<code>/blacklist add spam@example.com</code>
<code>/blacklist add @spammer.com</code>`;
    }

    await env.DB.prepare(
      "INSERT INTO blacklist (user_id, sender_pattern) VALUES (?, ?)"
    ).bind(userId, pattern.toLowerCase()).run();

    return `✅ "<b>${pattern}</b>" ditambahkan ke blacklist.`;
  }

  // /blacklist del pattern
  if (subCommand === "del" || subCommand === "rm") {
    if (!pattern) {
      return `⚠️ Format: <code>/blacklist del pola</code>`;
    }

    const result = await env.DB.prepare(
      "DELETE FROM blacklist WHERE user_id = ? AND sender_pattern LIKE ?"
    ).bind(userId, `%${pattern}%`).run();

    if (result.meta.changes === 0) {
      return `❌ Pola tidak ditemukan di blacklist.`;
    }
    return `✅ Blacklist dihapus.`;
  }

  // /blacklist list (default)
  const result = await env.DB.prepare(
    "SELECT id, sender_pattern, created_at FROM blacklist WHERE user_id = ? ORDER BY created_at DESC"
  ).bind(userId).all();

  if (!result.results || result.results.length === 0) {
    return `📭 Blacklist kosong.

➕ Tambah: <code>/blacklist add email@spam.com</code>`;
  }

  let response = `🚫 <b>Blacklist Sender</b>\n\n`;
  for (const item of result.results as any[]) {
    response += `❌ ${item.sender_pattern}\n`;
  }
  response += `\n━━━━━━━━━━━━━━━
🗑️ Hapus: <code>/blacklist del pola</code>`;
  return response;
}

// Forward/Export email
async function handleForward(env: Bindings, telegramUserId: string, arg: string): Promise<string> {
  const parts = arg.split(/\s+/);
  const messageId = parts[0];
  const targetEmail = parts[1];

  if (!messageId || !targetEmail) {
    return `📤 <b>Forward Email</b>

Format: <code>/forward ID email@tujuan.com</code>

Contoh: <code>/forward 5 myemail@gmail.com</code>`;
  }

  const isAdmin = telegramUserId === env.ADMIN_USER_ID;
  const userId = await getUserId(env.DB, telegramUserId);
  if (!userId) return `❌ Error: User tidak ditemukan.`;

  let msg;
  if (isAdmin) {
    msg = await env.DB.prepare(
      "SELECT i.*, e.email_address FROM inbox i JOIN emails e ON i.email_id = e.id WHERE i.id = ?"
    ).bind(parseInt(messageId)).first();
  } else {
    msg = await env.DB.prepare(`
      SELECT i.*, e.email_address FROM inbox i 
      JOIN emails e ON i.email_id = e.id 
      WHERE i.id = ? AND e.user_id = ?
    `).bind(parseInt(messageId), userId).first();
  }

  if (!msg) {
    return `❌ Email dengan ID ${messageId} tidak ditemukan.`;
  }

  // For now, just show the info - actual forwarding would need email sending capability
  return `📤 <b>Forward Email</b>

📧 Dari: ${(msg as any).sender}
📋 Subjek: ${(msg as any).subject}
📨 Tujuan: ${targetEmail}

⚠️ Fitur forward email memerlukan SMTP.
💡 Untuk sementara, copy isi email dengan <code>/read ${messageId}</code>`;
}

// Cleanup old emails (admin only)
async function handleCleanup(env: Bindings): Promise<string> {
  // Delete emails older than 7 days
  const result = await env.DB.prepare(`
    DELETE FROM inbox WHERE received_at < datetime('now', '-7 days')
  `).run();

  // Delete unused email addresses (no messages for 30 days)
  const emailCleanup = await env.DB.prepare(`
    DELETE FROM emails WHERE id IN (
      SELECT e.id FROM emails e 
      LEFT JOIN inbox i ON e.id = i.email_id 
      WHERE i.id IS NULL AND e.created_at < datetime('now', '-30 days')
    )
  `).run();

  return `🧹 <b>Cleanup Selesai</b>

📧 Email dihapus: <b>${result.meta.changes}</b> (> 7 hari)
📪 Alamat dihapus: <b>${emailCleanup.meta.changes}</b> (tidak terpakai > 30 hari)`;
}

function getHelpMessage(domain: string): string {
  return `🎉 <b>Selamat datang di Temp Email Bot!</b>

Bot ini membantu kamu membuat email temporary dan mengelola kode 2FA.

━━━ 📧 <b>EMAIL</b> ━━━

<b>/create</b> <code>nama</code>
Buat email baru
→ <code>/create tokoku</code>

<b>/mails</b> <code>nama</code>
Cek inbox email
→ <code>/mails tokoku</code>

<b>/read</b> <code>id</code>
Baca isi email
→ <code>/read 5</code>

<b>/search</b> <code>kata</code>
Cari email
→ <code>/search verifikasi</code>

<b>/forward</b> <code>id email</code>
Forward email
→ <code>/forward 5 user@gmail.com</code>

━━━ 🔐 <b>2FA/OTP</b> ━━━

<b>/2fa</b> <code>secret</code>
Generate kode OTP
→ <code>/2fa JBSWY3DPEHPK3PXP</code>

<b>/2fa add</b> <code>nama secret</code>
Simpan secret
→ <code>/2fa add google SECRET</code>

<b>/2fa list</b>
Lihat secret tersimpan

<b>/2fa</b> <code>nama</code>
Generate dari secret tersimpan
→ <code>/2fa google</code>

━━━━━━━━━━━━━━━
💡 Email yang tidak terdaftar otomatis disimpan dan bisa dibaca di bot.`;
}

async function handleCreate(env: Bindings, telegramUserId: string, name: string): Promise<string> {
  if (!name) {
    return `⚠️ Masukkan nama untuk email.

Contoh: <code>/create tokoku</code>
→ Akan membuat <code>tokoku@${env.TEMP_EMAIL_DOMAIN}</code>`;
  }

  const localPart = name.toLowerCase().replace(/[^a-z0-9]/g, "");
  
  if (localPart.length < 3) {
    return `⚠️ Nama email minimal 3 karakter (huruf dan angka saja).`;
  }

  if (localPart.length > 30) {
    return `⚠️ Nama email maksimal 30 karakter.`;
  }

  const emailAddress = `${localPart}@${env.TEMP_EMAIL_DOMAIN}`;

  const existing = await env.DB.prepare("SELECT id FROM emails WHERE email_address = ?")
    .bind(emailAddress)
    .first();

  if (existing) {
    return `⚠️ Email <code>${emailAddress}</code> sudah digunakan.

Coba nama lain, contoh: <code>/create ${localPart}123</code>`;
  }

  const userId = await getUserId(env.DB, telegramUserId);
  if (!userId) {
    return `❌ Error: User tidak ditemukan.`;
  }

  await env.DB.prepare("INSERT INTO emails (user_id, email_address, local_part) VALUES (?, ?, ?)")
    .bind(userId, emailAddress, localPart)
    .run();

  return `✅ <b>Email berhasil dibuat!</b>

📧 <code>${emailAddress}</code>

Gunakan alamat ini untuk menerima email. Ketika ada email masuk, kamu akan mendapat notifikasi di sini.

📬 Cek inbox: <code>/mails ${localPart}</code>`;
}

async function handleMails(env: Bindings, telegramUserId: string, identifier: string): Promise<string> {
  if (!identifier) {
    return `⚠️ Masukkan nama email yang ingin dicek.

Contoh: <code>/mails tokoku</code>

📋 Lihat semua email: <code>/list</code>`;
  }

  const isAdmin = telegramUserId === env.ADMIN_USER_ID;
  const emailAddress = identifier.includes("@")
    ? identifier.toLowerCase()
    : `${identifier.toLowerCase()}@${env.TEMP_EMAIL_DOMAIN}`;

  let email;
  if (isAdmin) {
    // Admin can view any email
    email = await env.DB.prepare(
      "SELECT id, email_address FROM emails WHERE LOWER(email_address) = ? AND is_active = 1"
    )
      .bind(emailAddress)
      .first<{ id: number; email_address: string }>();
  } else {
    const userId = await getUserId(env.DB, telegramUserId);
    if (!userId) {
      return `❌ Error: User tidak ditemukan.`;
    }
    email = await env.DB.prepare(
      "SELECT id, email_address FROM emails WHERE user_id = ? AND LOWER(email_address) = ? AND is_active = 1"
    )
      .bind(userId, emailAddress)
      .first<{ id: number; email_address: string }>();
  }

  if (!email) {
    return `⚠️ Email <code>${emailAddress}</code> tidak ditemukan.

📋 Lihat semua email: <code>/list</code>`;
  }

  const result = await env.DB.prepare(
    `SELECT id, sender, subject, is_read, received_at FROM inbox 
     WHERE email_id = ? ORDER BY received_at DESC LIMIT 20`
  )
    .bind(email.id)
    .all();

  if (!result.results || result.results.length === 0) {
    return `📭 <b>Inbox kosong</b>

📧 <code>${email.email_address}</code>

Belum ada email masuk. Gunakan alamat di atas untuk menerima email.`;
  }

  let response = `📬 <b>Inbox: ${email.email_address}</b>

`;

  for (const msg of result.results as any[]) {
    const status = msg.is_read ? "📖" : "📩";
    const subject = msg.subject || "(Tanpa subjek)";
    response += `${status} <b>ID ${msg.id}</b>
👤 ${msg.sender}
📋 ${subject}
⏰ ${msg.received_at}

`;
  }

  response += `━━━━━━━━━━━━━━━
📖 Baca email: <code>/read ID</code>
Contoh: <code>/read ${(result.results[0] as any).id}</code>`;

  return response;
}

async function handleRead(env: Bindings, telegramUserId: string, messageId: string): Promise<string> {
  if (!messageId || isNaN(parseInt(messageId))) {
    return `⚠️ Masukkan ID email yang ingin dibaca.

Contoh: <code>/read 5</code>`;
  }

  const userId = await getUserId(env.DB, telegramUserId);
  if (!userId) {
    return `❌ Error: User tidak ditemukan.`;
  }

  const isAdmin = telegramUserId === env.ADMIN_USER_ID;

  // Admin can read any email, regular users only their own
  let msg;
  if (isAdmin) {
    msg = await env.DB.prepare(
      `SELECT i.*, e.email_address FROM inbox i 
       JOIN emails e ON i.email_id = e.id 
       WHERE i.id = ?`
    )
      .bind(parseInt(messageId))
      .first<{ id: number; sender: string; subject: string; body: string; email_address: string; received_at: string }>();
  } else {
    msg = await env.DB.prepare(
      `SELECT i.*, e.email_address FROM inbox i 
       JOIN emails e ON i.email_id = e.id 
       WHERE i.id = ? AND e.user_id = ?`
    )
      .bind(parseInt(messageId), userId)
      .first<{ id: number; sender: string; subject: string; body: string; email_address: string; received_at: string }>();
  }

  if (!msg) {
    return `⚠️ Email dengan ID ${messageId} tidak ditemukan atau bukan milik kamu.`;
  }

  await env.DB.prepare("UPDATE inbox SET is_read = 1 WHERE id = ?").bind(parseInt(messageId)).run();

  const rawBody = msg.body || "(Tidak ada isi)";
  const body = stripHtml(rawBody).substring(0, 3000);

  return `📧 <b>Email #${msg.id}</b>

📬 <b>Ke:</b> ${msg.email_address}
👤 <b>Dari:</b> ${msg.sender}
📋 <b>Subjek:</b> ${msg.subject || "(Tanpa subjek)"}
⏰ <b>Waktu:</b> ${msg.received_at}

━━━━━━━━━━━━━━━
${body}`;
}

async function handleList(env: Bindings, telegramUserId: string): Promise<string> {
  const isAdmin = telegramUserId === env.ADMIN_USER_ID;

  // Admin sees ALL emails, regular users see only their own
  let result;
  if (isAdmin) {
    result = await env.DB.prepare(
      `SELECT e.email_address, e.local_part, e.created_at, u.telegram_username,
       (SELECT COUNT(*) FROM inbox i WHERE i.email_id = e.id) as message_count,
       (SELECT COUNT(*) FROM inbox i WHERE i.email_id = e.id AND i.is_read = 0) as unread_count
       FROM emails e 
       JOIN users u ON e.user_id = u.id
       WHERE e.is_active = 1 ORDER BY e.created_at DESC`
    ).all();
  } else {
    const userId = await getUserId(env.DB, telegramUserId);
    if (!userId) {
      return `❌ Error: User tidak ditemukan.`;
    }
    result = await env.DB.prepare(
      `SELECT e.email_address, e.local_part, e.created_at, 
       (SELECT COUNT(*) FROM inbox i WHERE i.email_id = e.id) as message_count,
       (SELECT COUNT(*) FROM inbox i WHERE i.email_id = e.id AND i.is_read = 0) as unread_count
       FROM emails e WHERE e.user_id = ? AND e.is_active = 1 ORDER BY e.created_at DESC`
    )
      .bind(userId)
      .all();
  }

  const isAdminView = telegramUserId === env.ADMIN_USER_ID;

  if (!result.results || result.results.length === 0) {
    return isAdminView 
      ? `📭 <b>Belum ada email terdaftar.</b>`
      : `📭 <b>Kamu belum punya email.</b>

Buat email baru dengan:
<code>/create namaemailmu</code>`;
  }

  let response = isAdminView 
    ? `📋 <b>Semua Email (Admin View)</b>

`
    : `📋 <b>Daftar Email Kamu</b>

`;

  for (const email of result.results as any[]) {
    const unread = email.unread_count > 0 ? ` (📩 ${email.unread_count} baru)` : "";
    const owner = isAdminView && email.telegram_username ? ` [@${email.telegram_username}]` : "";
    response += `📧 <code>${email.email_address}</code>${unread}${owner}
   📬 ${email.message_count} pesan | 📅 ${email.created_at}

`;
  }

  response += `━━━━━━━━━━━━━━━
📬 Cek inbox: <code>/mails nama</code>
🗑 Hapus: <code>/delete nama</code>`;

  return response;
}

async function handleDelete(env: Bindings, telegramUserId: string, identifier: string): Promise<string> {
  if (!identifier) {
    return `⚠️ Masukkan nama email yang ingin dihapus.

Contoh: <code>/delete tokoku</code>`;
  }

  const userId = await getUserId(env.DB, telegramUserId);
  if (!userId) {
    return `❌ Error: User tidak ditemukan.`;
  }

  const emailAddress = identifier.includes("@")
    ? identifier.toLowerCase()
    : `${identifier.toLowerCase()}@${env.TEMP_EMAIL_DOMAIN}`;

  const email = await env.DB.prepare(
    "SELECT id FROM emails WHERE user_id = ? AND LOWER(email_address) = ?"
  )
    .bind(userId, emailAddress)
    .first<{ id: number }>();

  if (!email) {
    return `⚠️ Email <code>${emailAddress}</code> tidak ditemukan atau bukan milik kamu.`;
  }

  await env.DB.prepare("DELETE FROM inbox WHERE email_id = ?").bind(email.id).run();
  await env.DB.prepare("DELETE FROM emails WHERE id = ?").bind(email.id).run();

  return `✅ Email <code>${emailAddress}</code> berhasil dihapus beserta semua pesannya.`;
}

// ============ HELPERS ============
async function ensureUser(db: D1Database, telegramUserId: string, username?: string) {
  const existing = await db
    .prepare("SELECT id FROM users WHERE telegram_user_id = ?")
    .bind(telegramUserId)
    .first();

  if (!existing) {
    await db
      .prepare("INSERT INTO users (telegram_user_id, telegram_username) VALUES (?, ?)")
      .bind(telegramUserId, username || null)
      .run();
  }
}

async function getUserId(db: D1Database, telegramUserId: string): Promise<number | null> {
  const user = await db
    .prepare("SELECT id FROM users WHERE telegram_user_id = ?")
    .bind(telegramUserId)
    .first<{ id: number }>();
  return user?.id || null;
}

async function getOrCreateAdminUser(db: D1Database, adminTelegramId: string): Promise<number> {
  const existing = await db
    .prepare("SELECT id FROM users WHERE telegram_user_id = ?")
    .bind(adminTelegramId)
    .first<{ id: number }>();

  if (existing) {
    return existing.id;
  }

  const result = await db
    .prepare("INSERT INTO users (telegram_user_id, telegram_username) VALUES (?, ?) RETURNING id")
    .bind(adminTelegramId, "admin")
    .first<{ id: number }>();
  
  return result?.id || 0;
}

async function sendTelegramMessage(botToken: string, chatId: number, text: string) {
  const response = await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      chat_id: chatId,
      text: text,
      parse_mode: "HTML",
    }),
  });

  if (!response.ok) {
    console.error("Telegram API error:", await response.text());
  }
}

function extractEmailBody(rawEmail: string): string {
  // Try to extract plain text content between boundaries
  // Pattern: after "text/plain" ... before next boundary
  const plainTextMatch = rawEmail.match(/Content-Type:\s*text\/plain[^]*?charset="?[^"]*"?\s*([\s\S]*?)(?=--[0-9a-f]+|$)/i);
  
  if (plainTextMatch && plainTextMatch[1]) {
    const content = plainTextMatch[1]
      .replace(/Content-Transfer-Encoding:[^\n]*/gi, '')
      .replace(/--[0-9a-f]+[^\n]*/gi, '')
      .replace(/Content-Type:[^\n]*/gi, '')
      .trim();
    if (content && content.length > 0) {
      return stripHtml(content);
    }
  }
  
  // Try HTML content
  const htmlMatch = rawEmail.match(/Content-Type:\s*text\/html[^]*?charset="?[^"]*"?\s*([\s\S]*?)(?=--[0-9a-f]+|$)/i);
  
  if (htmlMatch && htmlMatch[1]) {
    const content = htmlMatch[1]
      .replace(/Content-Transfer-Encoding:[^\n]*/gi, '')
      .replace(/--[0-9a-f]+[^\n]*/gi, '')
      .replace(/Content-Type:[^\n]*/gi, '')
      .trim();
    if (content && content.length > 0) {
      return stripHtml(content);
    }
  }
  
  // Fallback: remove all MIME headers and boundaries
  let body = rawEmail
    .replace(/^[\s\S]*?\r?\n\r?\n/, '') // Remove email headers
    .replace(/--[0-9a-f]{20,}[^\n]*/gi, '') // Remove boundaries
    .replace(/Content-Type:[^\n]*/gi, '')
    .replace(/Content-Transfer-Encoding:[^\n]*/gi, '')
    .replace(/charset="?[^"\s]*"?/gi, '')
    .trim();
  
  return stripHtml(body);
}

function stripHtml(html: string): string {
  return html
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
    .replace(/<[^>]+>/g, '')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/=\r?\n/g, '') // Quoted-printable soft line breaks
    .replace(/=20/g, ' ') // Quoted-printable space
    .replace(/=3D/g, '=') // Quoted-printable equals
    .replace(/=([0-9A-Fa-f]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16))) // Other QP chars
    .replace(/\s+/g, ' ')
    .trim();
}

// ============ EXPORTS ============
export default {
  fetch: app.fetch,
  email: handleEmail,
};
