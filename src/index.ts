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

  const email = await env.DB.prepare(
    "SELECT e.id, e.user_id, u.telegram_user_id FROM emails e JOIN users u ON e.user_id = u.id WHERE LOWER(e.email_address) = ?"
  )
    .bind(toAddress)
    .first<{ id: number; user_id: number; telegram_user_id: string }>();

  if (!email) {
    console.log("Email address not found, creating catch-all entry:", toAddress);
    
    // Auto-create email for admin (catch-all)
    const adminUserId = await getOrCreateAdminUser(env.DB, env.ADMIN_USER_ID);
    
    // Create the email address and assign to admin
    const emailResult = await env.DB.prepare(
      "INSERT INTO emails (user_id, email_address, is_active) VALUES (?, ?, 1) RETURNING id"
    )
      .bind(adminUserId, toAddress)
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
        const localPart = toAddress.split("@")[0];
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
      return handle2FA(arg);

    default:
      return `❓ Perintah tidak dikenali.

Ketik /start untuk melihat panduan.`;
  }
}

// ============ COMMAND HANDLERS ============
function handle2FA(secretInput: string): string {
  if (!secretInput) {
    return `🔐 <b>Generator Kode 2FA/OTP</b>

Kirimkan secret key 2FA kamu untuk mendapatkan kode OTP.

📋 <b>Cara Pakai:</b>
<code>/2fa SECRET_KEY</code>

Contoh:
<code>/2fa JBSWY3DPEHPK3PXP</code>

💡 Bisa kirim beberapa secret sekaligus (pisahkan dengan baris baru):
<code>/2fa SECRET1
SECRET2
SECRET3</code>`;
  }

  const secrets = secretInput.split('\n');
  let responseText = "";
  let successCount = 0;

  for (let secret of secrets) {
    secret = secret.trim().replace(/ /g, '').toUpperCase();
    
    if (secret.length < 8) continue;

    try {
      const totp = new OTPAuth.TOTP({
        algorithm: "SHA1",
        digits: 6,
        period: 30,
        secret: OTPAuth.Secret.fromBase32(secret)
      });

      const code = totp.generate();
      const now = Math.floor(Date.now() / 1000);
      const remaining = 30 - (now % 30);
      
      responseText += `🔑 <code>${secret.substring(0, 8)}...</code>
🔢 Kode OTP: <code>${code}</code>
⏱️ Berlaku: ${remaining} detik

`;
      successCount++;
    } catch (e) {
      responseText += `❌ <code>${secret.substring(0, 8)}...</code> - Secret tidak valid

`;
    }
  }

  if (successCount === 0) {
    return `❌ Secret key tidak valid.

Pastikan format secret key benar (Base32).
Contoh: <code>JBSWY3DPEHPK3PXP</code>`;
  }

  return `🔐 <b>Kode OTP</b>

${responseText}━━━━━━━━━━━━━━━
💡 Kode akan berubah setiap 30 detik.`;
}

function getHelpMessage(domain: string): string {
  return `🎉 <b>Selamat datang di Temp Email Bot!</b>

Bot ini membantu kamu membuat email temporary untuk menerima email tanpa menggunakan email asli.

📋 <b>Cara Pakai:</b>

📧 <b>/create</b> <code>nama</code>
Buat email baru. Contoh:
<code>/create tokoku</code>
→ Membuat <code>tokoku@${domain}</code>

📬 <b>/mails</b> <code>nama</code>
Cek inbox email. Contoh:
<code>/mails tokoku</code>

📖 <b>/read</b> <code>id</code>
Baca isi email. Contoh:
<code>/read 5</code>

🔐 <b>/2fa</b> <code>secret</code>
Generate kode OTP. Contoh:
<code>/2fa JBSWY3DPEHPK3PXP</code>

━━━━━━━━━━━━━━━
💡 <b>Tips:</b> Gunakan email temporary untuk daftar akun, verifikasi, atau tes!`;
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
