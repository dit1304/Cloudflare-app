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

  // Handle callback queries (inline button clicks)
  if (payload.callback_query) {
    const callbackQuery = payload.callback_query;
    const telegramUserId = String(callbackQuery.from.id);
    const telegramUsername = callbackQuery.from.username || "";
    const chatId = callbackQuery.message.chat.id;
    const messageId = callbackQuery.message.message_id;
    const callbackData = callbackQuery.data;

    try {
      await ensureUser(c.env.DB, telegramUserId, telegramUsername);
      
      // Answer callback query to remove loading state
      await fetch(`https://api.telegram.org/bot${c.env.TELEGRAM_BOT_TOKEN}/answerCallbackQuery`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ callback_query_id: callbackQuery.id })
      });

      // Process the callback
      const result = await processCallback(c.env, telegramUserId, callbackData, chatId, messageId);
      if (result) {
        await sendTelegramMessage(c.env.TELEGRAM_BOT_TOKEN, chatId, result);
      }
    } catch (error) {
      console.error("Error processing callback:", error);
    }
    return c.text("OK", 200);
  }

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
    if (typeof response === "object" && response.text) {
      await sendTelegramMessage(c.env.TELEGRAM_BOT_TOKEN, chatId, response.text, response.keyboard);
    } else {
      await sendTelegramMessage(c.env.TELEGRAM_BOT_TOKEN, chatId, response as string);
    }
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

// Response type for commands with optional keyboard
type CommandResponse = string | { text: string; keyboard?: any[][] };

// ============ COMMAND PROCESSOR ============
async function processCommand(
  env: Bindings,
  telegramUserId: string,
  message: string
): Promise<CommandResponse> {
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
    case "/c":
      return await handleCreate(env, telegramUserId, arg);

    case "/mails":
    case "/inbox":
    case "/m":
      return await handleMails(env, telegramUserId, arg);

    case "/read":
    case "/r":
      return await handleRead(env, telegramUserId, arg);

    case "/list":
    case "/e":
      if (!isAdmin) {
        return `⛔ Perintah ini hanya untuk admin.`;
      }
      return await handleList(env, telegramUserId);

    case "/delete":
    case "/d":
      if (!isAdmin) {
        return `⛔ Perintah ini hanya untuk admin.`;
      }
      return await handleDelete(env, telegramUserId, arg);

    case "/2fa":
    case "/otp":
    case "/a":
      return await handle2FA(env, telegramUserId, arg);

    case "/search":
    case "/s":
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

    case "/broadcast":
    case "/bc":
      if (!isAdmin) {
        return `⛔ Perintah ini hanya untuk admin.`;
      }
      return await handleBroadcast(env, telegramUserId, arg);

    case "/setting":
    case "/settings":
    case "/set":
      return await handleSettings(env, telegramUserId, arg);

    case "/mystats":
    case "/me":
      return await handleMyStats(env, telegramUserId);

    case "/backup":
      return await handleBackup(env, telegramUserId);

    case "/qr":
      return await handleQR(env, telegramUserId, arg);

    default:
      return `❓ Perintah tidak dikenali.

Ketik /start untuk melihat panduan.`;
  }
}

// ============ CALLBACK HANDLER (for inline buttons) ============
async function processCallback(
  env: Bindings,
  telegramUserId: string,
  callbackData: string,
  chatId: number,
  messageId: number
): Promise<string> {
  const [action, ...params] = callbackData.split(":");
  
  switch (action) {
    case "read":
      // Read email: read:ID
      return await handleRead(env, telegramUserId, params[0]);
    
    case "mails": {
      // Back to inbox: mails:emailName
      const result = await handleMails(env, telegramUserId, params[0]);
      return typeof result === 'string' ? result : result.text;
    }
    
    case "2fa": {
      // Generate 2FA: 2fa:name or 2fa:list
      const result = await handle2FA(env, telegramUserId, params[0]);
      return typeof result === 'string' ? result : result.text;
    }
    
    case "refresh": {
      // Refresh 2FA code: refresh:name
      const result = await handle2FA(env, telegramUserId, params[0]);
      return typeof result === 'string' ? result : result.text;
    }
    
    case "set":
      // Settings callback: set:autodelete:days
      if (params[0] === "autodelete") {
        const result = await handleSettings(env, telegramUserId, `autodelete ${params[1]}`);
        // handleSettings might return object or string - extract text for callbacks
        return typeof result === 'string' ? result : result.text;
      }
      return "";
    
    default:
      return "";
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

async function handle2FA(env: Bindings, telegramUserId: string, arg: string): Promise<CommandResponse> {
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
    const isAdmin = telegramUserId === env.ADMIN_USER_ID;
    
    // Admin can see all users' secrets
    if (isAdmin) {
      const result = await env.DB.prepare(
        `SELECT t.name, t.created_at, u.telegram_user_id, u.telegram_username 
         FROM totp_secrets t 
         JOIN users u ON t.user_id = u.id 
         ORDER BY u.telegram_user_id, t.name`
      ).all();

      if (!result.results || result.results.length === 0) {
        return `📭 Belum ada 2FA secret tersimpan di sistem.`;
      }

      let response = `🔐 <b>Daftar Semua 2FA Secret (Admin)</b>\n\n`;
      let currentUser = "";
      for (const item of result.results as any[]) {
        if (item.telegram_user_id !== currentUser) {
          currentUser = item.telegram_user_id;
          const username = item.telegram_username ? `@${item.telegram_username}` : "(no username)";
          response += `\n👤 <b>User ${currentUser}</b> ${username}\n`;
        }
        response += `  🔑 ${item.name}\n`;
      }
      return response;
    }
    
    // Regular user only sees their own
    const result = await env.DB.prepare(
      "SELECT name, created_at FROM totp_secrets WHERE user_id = ? ORDER BY name"
    ).bind(userId).all();

    if (!result.results || result.results.length === 0) {
      return `📭 Belum ada 2FA secret tersimpan.

➕ Tambah: <code>/2fa add nama SECRET_KEY</code>`;
    }

    let response = `🔐 <b>Daftar 2FA Secret</b>\n\n`;
    const secrets = result.results as any[];
    
    for (const item of secrets) {
      response += `🔑 <b>${item.name}</b>\n`;
    }
    response += `\n━━━━━━━━━━━━━━━
👆 Tap tombol untuk generate kode`;

    // Build keyboard with 2FA buttons (max 3 per row)
    const keyboard: any[][] = [];
    for (let i = 0; i < secrets.length; i += 3) {
      const row = secrets.slice(i, i + 3).map((item: any) => ({
        text: `🔢 ${item.name}`,
        callback_data: `2fa:${item.name}`
      }));
      keyboard.push(row);
    }

    return { text: response, keyboard };
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
  // Delete emails based on each user's auto_delete_days setting
  // Users with auto_delete_days = 0 are excluded (never delete)
  const result = await env.DB.prepare(`
    DELETE FROM inbox WHERE id IN (
      SELECT i.id FROM inbox i
      JOIN emails e ON i.email_id = e.id
      JOIN users u ON e.user_id = u.id
      WHERE u.auto_delete_days > 0
        AND i.received_at < datetime('now', '-' || COALESCE(u.auto_delete_days, 7) || ' days')
    )
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

📧 Email dihapus: <b>${result.meta.changes}</b> (berdasarkan setting user)
📪 Alamat dihapus: <b>${emailCleanup.meta.changes}</b> (tidak terpakai > 30 hari)`;
}

async function handleBroadcast(env: Bindings, adminChatId: string, message: string): Promise<string> {
  if (!message || message.trim() === "") {
    return `⚠️ <b>Format:</b> <code>/broadcast pesan</code>

Contoh: <code>/broadcast Bot akan maintenance jam 10 malam</code>`;
  }

  // Get all users
  const users = await env.DB.prepare("SELECT telegram_user_id FROM users").all();
  
  if (!users.results || users.results.length === 0) {
    return `❌ Tidak ada user terdaftar.`;
  }

  const botToken = env.TELEGRAM_BOT_TOKEN;
  const totalUsers = users.results.length;
  let success = 0;
  let failed = 0;
  let processed = 0;

  // Helper to generate progress bar
  const getProgressBar = (current: number, total: number): string => {
    const percentage = Math.round((current / total) * 100);
    const filled = Math.round(percentage / 10);
    const empty = 10 - filled;
    return "▓".repeat(filled) + "░".repeat(empty) + ` ${percentage}%`;
  };

  // Helper to generate status text
  const getStatusText = (done: boolean = false): string => {
    const progress = getProgressBar(processed, totalUsers);
    if (done) {
      return `📢 <b>Broadcast Selesai</b>

${progress}

✅ Terkirim: <b>${success}</b>
❌ Gagal: <b>${failed}</b>
📊 Total: <b>${totalUsers}</b> user`;
    }
    return `📢 <b>Broadcasting...</b>

${progress}

⏳ Proses: <b>${processed}</b>/<b>${totalUsers}</b>
✅ Berhasil: <b>${success}</b>
❌ Gagal: <b>${failed}</b>`;
  };

  // Send initial progress message
  const initialMsg = await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      chat_id: adminChatId,
      text: getStatusText(),
      parse_mode: "HTML"
    })
  });

  const initialResult = await initialMsg.json() as any;
  const messageId = initialResult.result?.message_id;

  const broadcastText = `📢 <b>Pengumuman</b>\n\n${message}`;

  // Update frequency: every 5 users or at least 3 updates total
  const updateEvery = Math.max(1, Math.min(5, Math.floor(totalUsers / 3)));

  for (const user of users.results as any[]) {
    try {
      const response = await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          chat_id: user.telegram_user_id,
          text: broadcastText,
          parse_mode: "HTML"
        })
      });
      
      if (response.ok) {
        success++;
      } else {
        failed++;
      }
    } catch (e) {
      failed++;
    }
    
    processed++;

    // Update progress message periodically
    if (messageId && (processed % updateEvery === 0 || processed === totalUsers)) {
      try {
        await fetch(`https://api.telegram.org/bot${botToken}/editMessageText`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            chat_id: adminChatId,
            message_id: messageId,
            text: processed === totalUsers ? getStatusText(true) : getStatusText(),
            parse_mode: "HTML"
          })
        });
      } catch (e) {
        // Ignore edit errors
      }
    }
  }

  // Return empty since we already sent the final message
  return "";
}

// ============ SETTINGS HANDLER ============
async function handleSettings(env: Bindings, telegramUserId: string, arg: string): Promise<CommandResponse> {
  const userId = await getUserId(env.DB, telegramUserId);
  
  // Get current settings
  const user = await env.DB.prepare(
    "SELECT auto_delete_days, language, timezone FROM users WHERE id = ?"
  ).bind(userId).first() as any;

  // Default values if columns don't exist yet
  const currentAutoDelete = user?.auto_delete_days ?? 7;
  const currentLang = user?.language ?? 'id';
  const currentTz = user?.timezone ?? 'Asia/Jakarta';

  if (!arg) {
    // Show current settings
    const keyboard = [
      [
        { text: "📅 Auto-delete: 3 hari", callback_data: "set:autodelete:3" },
        { text: "7 hari", callback_data: "set:autodelete:7" }
      ],
      [
        { text: "14 hari", callback_data: "set:autodelete:14" },
        { text: "30 hari", callback_data: "set:autodelete:30" }
      ],
      [
        { text: "♾️ Tidak pernah", callback_data: "set:autodelete:0" }
      ]
    ];

    return {
      text: `⚙️ <b>Pengaturan Akun</b>

📅 <b>Auto-delete email:</b> ${currentAutoDelete === 0 ? 'Tidak pernah' : currentAutoDelete + ' hari'}
🌐 <b>Bahasa:</b> ${currentLang === 'id' ? 'Indonesia' : 'English'}
🕐 <b>Timezone:</b> ${currentTz}

━━━━━━━━━━━━━━━
<b>Ubah pengaturan:</b>
<code>/set autodelete 7</code> - Auto-hapus 7 hari
<code>/set autodelete 0</code> - Tidak auto-hapus

👇 Atau tap tombol di bawah:`,
      keyboard
    };
  }

  const parts = arg.toLowerCase().split(/\s+/);
  const setting = parts[0];
  const value = parts[1];

  if (setting === "autodelete" || setting === "auto") {
    if (!value) {
      return `⚠️ Format: <code>/set autodelete HARI</code>
      
Contoh: <code>/set autodelete 7</code> (hapus email >7 hari)
Contoh: <code>/set autodelete 0</code> (tidak pernah hapus)`;
    }

    const days = parseInt(value);
    if (isNaN(days) || days < 0 || days > 365) {
      return `⚠️ Masukkan angka 0-365 hari.`;
    }

    await env.DB.prepare(
      "UPDATE users SET auto_delete_days = ? WHERE id = ?"
    ).bind(days, userId).run();

    return `✅ Auto-delete diset ke <b>${days === 0 ? 'tidak pernah' : days + ' hari'}</b>.

Email yang lebih tua dari ${days} hari akan otomatis dihapus saat cleanup.`;
  }

  return `⚠️ Pengaturan tidak dikenali.

Gunakan: <code>/set autodelete HARI</code>`;
}

// ============ MY STATS HANDLER ============
async function handleMyStats(env: Bindings, telegramUserId: string): Promise<string> {
  const userId = await getUserId(env.DB, telegramUserId);

  // Get user info and settings
  const user = await env.DB.prepare(
    "SELECT telegram_username, auto_delete_days, created_at FROM users WHERE id = ?"
  ).bind(userId).first() as any;

  // Get email count
  const emailCount = await env.DB.prepare(
    "SELECT COUNT(*) as count FROM emails WHERE user_id = ?"
  ).bind(userId).first() as any;

  // Get inbox count (total and unread)
  const inboxStats = await env.DB.prepare(`
    SELECT 
      COUNT(*) as total,
      SUM(CASE WHEN is_read = 0 THEN 1 ELSE 0 END) as unread
    FROM inbox i
    JOIN emails e ON i.email_id = e.id
    WHERE e.user_id = ?
  `).bind(userId).first() as any;

  // Get 2FA count
  const totpCount = await env.DB.prepare(
    "SELECT COUNT(*) as count FROM totp_secrets WHERE user_id = ?"
  ).bind(userId).first() as any;

  // Get email addresses
  const emails = await env.DB.prepare(
    "SELECT email_address FROM emails WHERE user_id = ? AND is_active = 1"
  ).bind(userId).all();

  const autoDeleteText = (user?.auto_delete_days ?? 7) === 0 
    ? 'Tidak pernah' 
    : `${user?.auto_delete_days ?? 7} hari`;

  let response = `📊 <b>Statistik Akun Kamu</b>

👤 <b>User ID:</b> ${telegramUserId}
${user?.telegram_username ? `📛 <b>Username:</b> @${user.telegram_username}` : ''}
📅 <b>Bergabung:</b> ${user?.created_at?.split('T')[0] || 'N/A'}

━━━ 📧 <b>EMAIL</b> ━━━
📬 <b>Alamat aktif:</b> ${emailCount?.count || 0}
📨 <b>Total email:</b> ${inboxStats?.total || 0}
📩 <b>Belum dibaca:</b> ${inboxStats?.unread || 0}

━━━ 🔐 <b>2FA</b> ━━━
🔑 <b>Secret tersimpan:</b> ${totpCount?.count || 0}

━━━ ⚙️ <b>PENGATURAN</b> ━━━
📅 <b>Auto-delete:</b> ${autoDeleteText}`;

  if (emails.results && emails.results.length > 0) {
    response += `\n\n📧 <b>Alamat Email:</b>`;
    for (const e of emails.results as any[]) {
      response += `\n• <code>${e.email_address}</code>`;
    }
  }

  return response;
}

// ============ BACKUP HANDLER ============
async function handleBackup(env: Bindings, telegramUserId: string): Promise<string> {
  const userId = await getUserId(env.DB, telegramUserId);

  // Get all 2FA secrets
  const secrets = await env.DB.prepare(
    "SELECT name, secret, created_at FROM totp_secrets WHERE user_id = ? ORDER BY name"
  ).bind(userId).all();

  if (!secrets.results || secrets.results.length === 0) {
    return `📭 Tidak ada 2FA secret untuk di-backup.

➕ Tambah secret: <code>/2fa add nama SECRET</code>`;
  }

  // Format as text backup
  let backup = `🔐 BACKUP 2FA SECRETS
📅 ${new Date().toISOString().split('T')[0]}
👤 User: ${telegramUserId}
━━━━━━━━━━━━━━━━━━━━━━

`;

  for (const item of secrets.results as any[]) {
    backup += `📛 ${item.name}
🔑 ${item.secret}
📅 ${item.created_at?.split('T')[0] || 'N/A'}
──────────────────

`;
  }

  backup += `Total: ${secrets.results.length} secret(s)

⚠️ SIMPAN BACKUP INI DI TEMPAT AMAN!
Jangan bagikan ke siapapun.`;

  return `<pre>${backup}</pre>`;
}

// ============ QR CODE HANDLER ============
async function handleQR(env: Bindings, telegramUserId: string, arg: string): Promise<string> {
  if (!arg) {
    return `⚠️ Format: <code>/qr nama_secret</code>

Contoh: <code>/qr google</code>

Ini akan generate QR code untuk secret tersimpan.`;
  }

  const userId = await getUserId(env.DB, telegramUserId);
  const name = arg.toLowerCase().trim();

  // Get secret from database
  const result = await env.DB.prepare(
    "SELECT secret FROM totp_secrets WHERE user_id = ? AND name = ?"
  ).bind(userId, name).first() as any;

  if (!result) {
    return `❌ Secret "<b>${name}</b>" tidak ditemukan.

📋 Lihat daftar: <code>/2fa list</code>`;
  }

  // Generate otpauth URI
  const otpauthUri = `otpauth://totp/${encodeURIComponent(name)}?secret=${result.secret}&issuer=TempEmailBot`;
  
  // Use QR Server API (free, no auth required)
  const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=${encodeURIComponent(otpauthUri)}`;

  // Send QR code as photo to Telegram
  try {
    await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendPhoto`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id: telegramUserId,
        photo: qrUrl,
        caption: `🔳 QR Code untuk: ${name}\n\n📱 Scan dengan app authenticator\n\n🔗 Manual entry:\n${result.secret}\n\n⚠️ Jangan bagikan QR ini!`,
        parse_mode: "HTML"
      })
    });
  } catch (e) {
    console.error("Failed to send QR photo:", e);
    return `🔳 <b>QR Code untuk: ${name}</b>

📱 <a href="${qrUrl}">📲 Klik untuk lihat QR Code</a>

🔗 <b>Manual entry:</b>
<code>${result.secret}</code>

⚠️ Jangan bagikan!`;
  }

  // Return empty since we sent the photo
  return "";
}

function getHelpMessage(domain: string): string {
  return `🎉 <b>Selamat datang di Temp Email Bot!</b>

Bot ini membantu kamu membuat email temporary dan mengelola kode 2FA.

━━━ 📧 <b>EMAIL</b> ━━━

<b>/create</b> atau <b>/c</b> <code>nama</code>
Buat email baru
→ <code>/c tokoku</code>

<b>/mails</b> atau <b>/m</b> <code>nama</code>
Cek inbox email
→ <code>/m tokoku</code>

<b>/read</b> atau <b>/r</b> <code>id</code>
Baca isi email
→ <code>/r 5</code>

<b>/search</b> atau <b>/s</b> <code>kata</code>
Cari email
→ <code>/s verifikasi</code>

━━━ 🔐 <b>2FA/OTP</b> ━━━

<b>/2fa</b> atau <b>/a</b> <code>secret</code>
Generate kode OTP
→ <code>/a JBSWY3DPEHPK3PXP</code>

<b>/2fa add</b> <code>nama secret</code>
Simpan secret
→ <code>/a add google SECRET</code>

<b>/2fa list</b> atau <b>/a list</b>
Lihat secret tersimpan

<b>/qr</b> <code>nama</code>
QR code untuk authenticator
→ <code>/qr google</code>

<b>/backup</b>
Backup semua 2FA secrets

━━━ 👤 <b>AKUN</b> ━━━

<b>/mystats</b> atau <b>/me</b>
Statistik akunmu

<b>/setting</b>
Pengaturan (auto-delete, dll)

━━━ ⚡ <b>SHORTCUT</b> ━━━
<code>/c</code> create, <code>/m</code> mails, <code>/r</code> read
<code>/s</code> search, <code>/a</code> 2fa, <code>/me</code> stats`;
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

async function handleMails(env: Bindings, telegramUserId: string, identifier: string): Promise<CommandResponse> {
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

  // Build keyboard with read buttons (max 5 per row, max 3 rows)
  const keyboard: any[][] = [];
  const messages = result.results as any[];
  
  for (let i = 0; i < Math.min(messages.length, 15); i += 5) {
    const row = messages.slice(i, i + 5).map((msg: any) => ({
      text: `📖 ${msg.id}`,
      callback_data: `read:${msg.id}`
    }));
    keyboard.push(row);
  }

  for (const msg of messages) {
    const status = msg.is_read ? "📖" : "📩";
    const subject = msg.subject || "(Tanpa subjek)";
    const shortSubject = subject.length > 30 ? subject.substring(0, 30) + "..." : subject;
    response += `${status} <b>ID ${msg.id}</b> - ${shortSubject}
`;
  }

  response += `
━━━━━━━━━━━━━━━
👆 Tap tombol di atas untuk baca email`;

  const localPart = email.email_address.split("@")[0];
  keyboard.push([
    { text: "🔄 Refresh", callback_data: `mails:${localPart}` }
  ]);

  return { text: response, keyboard };
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

async function sendTelegramMessage(botToken: string, chatId: number, text: string, keyboard?: any) {
  const body: any = {
    chat_id: chatId,
    text: text,
    parse_mode: "HTML",
  };
  
  if (keyboard) {
    body.reply_markup = { inline_keyboard: keyboard };
  }
  
  const response = await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
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
