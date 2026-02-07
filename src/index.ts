import { Hono } from "hono";
import * as OTPAuth from "otpauth";
import { extractEmailBody, parseFromHeader, stripHtml } from "./utils/email-parser";
import { log, logError } from "./utils/helpers";

type Bindings = {
  DB: D1Database;
  TELEGRAM_BOT_TOKEN: string;
  TEMP_EMAIL_DOMAIN: string;
  ADMIN_USER_ID: string;
  FALLBACK_EMAIL: string;
  WORKER_URL?: string;
};

type Language = "id" | "en";

const TRANSLATIONS = {
  id: {
    welcome_choose_lang: `🌍 <b>Pilih Bahasa / Choose Language</b>

Silakan pilih bahasa yang ingin kamu gunakan:
Please select your preferred language:`,
    lang_set: "✅ Bahasa berhasil diubah ke Bahasa Indonesia!",
    welcome_title: "🎉 <b>Selamat datang di Temp Email Bot!</b>",
    welcome_desc: "Bot ini membantu kamu membuat email temporary dan mengelola kode 2FA.",
    email_section: "📧 <b>EMAIL</b>",
    create_desc: "Buat email baru",
    create_example: "→",
    mails_desc: "Cek inbox email",
    read_desc: "Baca isi email",
    search_desc: "Cari email",
    twofa_section: "🔐 <b>2FA/OTP</b>",
    twofa_desc: "Generate kode OTP",
    twofa_add_desc: "Simpan secret",
    twofa_list_desc: "Lihat secret tersimpan",
    qr_desc: "QR code untuk authenticator",
    backup_desc: "Backup semua 2FA secrets",
    account_section: "👤 <b>AKUN</b>",
    mystats_desc: "Statistik akunmu",
    settings_desc: "Pengaturan (auto-delete, dll)",
    lang_desc: "Ganti bahasa",
    shortcuts: "⚡ <b>SHORTCUT</b>",
    admin_section: "🔧 <b>ADMIN</b>",
    list_desc: "Lihat semua email terdaftar",
    stats_desc: "Statistik bot",
    blacklist_desc: "Kelola pengirim yang diblokir",
    cleanup_desc: "Hapus email lama (sesuai setting user)",
    delete_desc: "Hapus alamat email",
    broadcast_desc: "Kirim pesan ke semua user",
    users_desc: "Lihat daftar user",
    premium_desc: "Kelola user premium",
    domains_desc: "Lihat domain tersedia",
    cmd_not_found: "❓ Perintah tidak dikenali.\n\nKetik /start untuk melihat panduan.",
    user_not_found: "❌ Error: User tidak ditemukan.",
    admin_only: "⛔ Perintah ini hanya untuk admin.",
    enter_email_name: "⚠️ Masukkan nama email yang ingin dicek.",
    example: "Contoh",
    see_all_emails: "📋 Lihat semua email",
    email_not_found: "⚠️ Email tidak ditemukan.",
    no_emails: "📭 Belum ada email masuk.",
    from: "Dari",
    subject: "Subjek",
    date: "Tanggal",
    email_created: "✅ Email berhasil dibuat!",
    email_exists: "⚠️ Email sudah ada.",
    check_inbox: "Cek inbox",
    limit_reached_email: "⚠️ Limit email tercapai! Maksimal {limit} email untuk user gratis.\n\n💎 Upgrade ke Premium untuk unlimited email.",
    limit_reached_2fa: "⚠️ Limit 2FA tercapai! Maksimal {limit} 2FA secrets untuk user gratis.\n\n💎 Upgrade ke Premium untuk unlimited 2FA.",
    // Menu translations
    menu_title: "📱 <b>Menu Utama</b>",
    menu_desc: "Pilih menu di bawah:",
    menu_email: "📧 Email",
    menu_2fa: "🔐 2FA/OTP",
    menu_account: "👤 Akun",
    menu_help: "❓ Bantuan",
    back_to_menu: "🔙 Menu Utama",
    // Sub-menu buttons
    btn_create_email: "➕ Buat Email",
    btn_list_email: "📋 Daftar Email",
    btn_search_email: "🔍 Cari Email",
    btn_domains: "🌐 Domain",
    btn_generate_code: "🔢 Generate Kode",
    btn_list_secret: "📋 Daftar Secret",
    btn_add_secret: "➕ Tambah Secret",
    btn_qr_code: "🔳 QR Code",
    btn_backup: "💾 Backup",
    btn_stats: "📊 Statistik",
    btn_settings: "⚙️ Pengaturan",
    btn_language: "🌐 Bahasa",
    btn_refresh: "🔄 Refresh",
    btn_read_email: "📖 Baca Email",
    btn_back_inbox: "📬 Kembali ke Inbox",
    email_menu_title: "📧 <b>Menu Email</b>",
    twofa_menu_title: "🔐 <b>Menu 2FA/OTP</b>",
    account_menu_title: "👤 <b>Menu Akun</b>",
    admin_menu_title: "🔧 <b>Menu Admin</b>",
    choose_action: "Pilih aksi:",
    // Admin menu buttons
    btn_admin: "🔧 Admin",
    btn_bot_stats: "📊 Statistik Bot",
    btn_user_list: "👥 Daftar Users",
    btn_premium: "⭐ Premium",
    btn_blacklist: "🚫 Blacklist",
    btn_cleanup: "🧹 Cleanup",
    btn_broadcast: "📢 Broadcast",
    // Action prompts
    prompt_create_email: "➕ <b>Buat Email Baru</b>\n\nKetik nama email yang ingin dibuat:\n<code>/create namaemailmu</code>\n\nContoh: <code>/create tokoku</code>",
    prompt_search_email: "🔍 <b>Cari Email</b>\n\nKetik kata kunci untuk mencari:\n<code>/search kata_kunci</code>\n\nContoh: <code>/search verifikasi</code>",
    prompt_2fa_generate: "🔢 <b>Generate Kode OTP</b>\n\nKetik nama secret atau kode langsung:\n<code>/2fa nama_secret</code>\n<code>/2fa SECRET_KEY</code>\n\nContoh: <code>/2fa google</code>",
    prompt_2fa_add: "➕ <b>Tambah Secret 2FA</b>\n\nFormat: <code>/2fa add nama SECRET_KEY</code>\n\nContoh: <code>/2fa add google JBSWY3DPEHPK3PXP</code>",
    prompt_qr: "🔳 <b>Generate QR Code</b>\n\nKetik nama secret untuk generate QR:\n<code>/qr nama_secret</code>\n\nContoh: <code>/qr google</code>",
    prompt_language: "🌐 <b>Ganti Bahasa</b>\n\nPilih bahasa:",
    prompt_broadcast: "📢 <b>Broadcast Message</b>\n\nKetik pesan yang ingin dikirim ke semua user:\n<code>/broadcast pesan_anda</code>\n\nContoh: <code>/broadcast Bot akan maintenance jam 10</code>",
  },
  en: {
    welcome_choose_lang: `🌍 <b>Choose Language / Pilih Bahasa</b>

Please select your preferred language:
Silakan pilih bahasa yang ingin kamu gunakan:`,
    lang_set: "✅ Language successfully changed to English!",
    welcome_title: "🎉 <b>Welcome to Temp Email Bot!</b>",
    welcome_desc: "This bot helps you create temporary emails and manage 2FA codes.",
    email_section: "📧 <b>EMAIL</b>",
    create_desc: "Create new email",
    create_example: "→",
    mails_desc: "Check email inbox",
    read_desc: "Read email content",
    search_desc: "Search emails",
    twofa_section: "🔐 <b>2FA/OTP</b>",
    twofa_desc: "Generate OTP code",
    twofa_add_desc: "Save secret",
    twofa_list_desc: "View saved secrets",
    qr_desc: "QR code for authenticator",
    backup_desc: "Backup all 2FA secrets",
    account_section: "👤 <b>ACCOUNT</b>",
    mystats_desc: "Your account stats",
    settings_desc: "Settings (auto-delete, etc)",
    lang_desc: "Change language",
    shortcuts: "⚡ <b>SHORTCUTS</b>",
    admin_section: "🔧 <b>ADMIN</b>",
    list_desc: "View all registered emails",
    stats_desc: "Bot statistics",
    blacklist_desc: "Manage blocked senders",
    cleanup_desc: "Delete old emails (per user setting)",
    delete_desc: "Delete email address",
    broadcast_desc: "Send message to all users",
    users_desc: "View user list",
    premium_desc: "Manage premium users",
    domains_desc: "View available domains",
    cmd_not_found: "❓ Command not recognized.\n\nType /start to see the guide.",
    user_not_found: "❌ Error: User not found.",
    admin_only: "⛔ This command is for admin only.",
    enter_email_name: "⚠️ Enter the email name to check.",
    example: "Example",
    see_all_emails: "📋 See all emails",
    email_not_found: "⚠️ Email not found.",
    no_emails: "📭 No emails yet.",
    from: "From",
    subject: "Subject",
    date: "Date",
    email_created: "✅ Email created successfully!",
    email_exists: "⚠️ Email already exists.",
    check_inbox: "Check inbox",
    limit_reached_email: "⚠️ Email limit reached! Maximum {limit} emails for free users.\n\n💎 Upgrade to Premium for unlimited emails.",
    limit_reached_2fa: "⚠️ 2FA limit reached! Maximum {limit} 2FA secrets for free users.\n\n💎 Upgrade to Premium for unlimited 2FA.",
    // Menu translations
    menu_title: "📱 <b>Main Menu</b>",
    menu_desc: "Choose menu below:",
    menu_email: "📧 Email",
    menu_2fa: "🔐 2FA/OTP",
    menu_account: "👤 Account",
    menu_help: "❓ Help",
    back_to_menu: "🔙 Main Menu",
    // Sub-menu buttons
    btn_create_email: "➕ Create Email",
    btn_list_email: "📋 Email List",
    btn_search_email: "🔍 Search Email",
    btn_domains: "🌐 Domains",
    btn_generate_code: "🔢 Generate Code",
    btn_list_secret: "📋 Secret List",
    btn_add_secret: "➕ Add Secret",
    btn_qr_code: "🔳 QR Code",
    btn_backup: "💾 Backup",
    btn_stats: "📊 Statistics",
    btn_settings: "⚙️ Settings",
    btn_language: "🌐 Language",
    btn_refresh: "🔄 Refresh",
    btn_read_email: "📖 Read Email",
    btn_back_inbox: "📬 Back to Inbox",
    email_menu_title: "📧 <b>Email Menu</b>",
    twofa_menu_title: "🔐 <b>2FA/OTP Menu</b>",
    account_menu_title: "👤 <b>Account Menu</b>",
    admin_menu_title: "🔧 <b>Admin Menu</b>",
    choose_action: "Choose action:",
    // Admin menu buttons
    btn_admin: "🔧 Admin",
    btn_bot_stats: "📊 Bot Stats",
    btn_user_list: "👥 User List",
    btn_premium: "⭐ Premium",
    btn_blacklist: "🚫 Blacklist",
    btn_cleanup: "🧹 Cleanup",
    btn_broadcast: "📢 Broadcast",
    // Action prompts
    prompt_create_email: "➕ <b>Create New Email</b>\n\nType the email name you want to create:\n<code>/create youremailname</code>\n\nExample: <code>/create myshop</code>",
    prompt_search_email: "🔍 <b>Search Email</b>\n\nType keyword to search:\n<code>/search keyword</code>\n\nExample: <code>/search verification</code>",
    prompt_2fa_generate: "🔢 <b>Generate OTP Code</b>\n\nType secret name or code directly:\n<code>/2fa secret_name</code>\n<code>/2fa SECRET_KEY</code>\n\nExample: <code>/2fa google</code>",
    prompt_2fa_add: "➕ <b>Add 2FA Secret</b>\n\nFormat: <code>/2fa add name SECRET_KEY</code>\n\nExample: <code>/2fa add google JBSWY3DPEHPK3PXP</code>",
    prompt_qr: "🔳 <b>Generate QR Code</b>\n\nType secret name to generate QR:\n<code>/qr secret_name</code>\n\nExample: <code>/qr google</code>",
    prompt_language: "🌐 <b>Change Language</b>\n\nSelect language:",
    prompt_broadcast: "📢 <b>Broadcast Message</b>\n\nType message to send to all users:\n<code>/broadcast your_message</code>\n\nExample: <code>/broadcast Maintenance at 10 PM</code>",
  }
};

function t(lang: Language, key: keyof typeof TRANSLATIONS.id): string {
  return TRANSLATIONS[lang][key] || TRANSLATIONS.id[key];
}

const app = new Hono<{ Bindings: Bindings }>();

// Helper function to get list of domains
function getDomains(env: Bindings): string[] {
  return env.TEMP_EMAIL_DOMAIN.split(",").map(d => d.trim()).filter(d => d.length > 0);
}

// ============ INLINE KEYBOARD BUILDERS ============

// Build main menu keyboard
function buildMainMenuKeyboard(lang: Language, isAdmin: boolean): any {
  const keyboard: any[][] = [
    [
      { text: t(lang, "menu_email"), callback_data: "menu:email" },
      { text: t(lang, "menu_2fa"), callback_data: "menu:2fa" }
    ],
    [
      { text: t(lang, "menu_account"), callback_data: "menu:account" },
      { text: t(lang, "menu_help"), callback_data: "menu:help" }
    ]
  ];
  
  if (isAdmin) {
    keyboard.push([
      { text: t(lang, "btn_admin"), callback_data: "menu:admin" }
    ]);
  }
  
  return { inline_keyboard: keyboard };
}

// Build email menu keyboard
function buildEmailMenuKeyboard(lang: Language): any {
  const keyboard = [
    [
      { text: t(lang, "btn_create_email"), callback_data: "action:create_prompt" },
      { text: t(lang, "btn_list_email"), callback_data: "action:list" }
    ],
    [
      { text: t(lang, "btn_search_email"), callback_data: "action:search_prompt" },
      { text: t(lang, "btn_domains"), callback_data: "action:domains" }
    ],
    [
      { text: t(lang, "back_to_menu"), callback_data: "menu:main" }
    ]
  ];
  return { inline_keyboard: keyboard };
}

// Build 2FA menu keyboard
function build2FAMenuKeyboard(lang: Language): any {
  const keyboard = [
    [
      { text: t(lang, "btn_generate_code"), callback_data: "action:2fa_generate_prompt" },
      { text: t(lang, "btn_list_secret"), callback_data: "action:2fa_list" }
    ],
    [
      { text: t(lang, "btn_add_secret"), callback_data: "action:2fa_add_prompt" },
      { text: t(lang, "btn_qr_code"), callback_data: "action:qr_prompt" }
    ],
    [
      { text: t(lang, "btn_backup"), callback_data: "action:backup" }
    ],
    [
      { text: t(lang, "back_to_menu"), callback_data: "menu:main" }
    ]
  ];
  return { inline_keyboard: keyboard };
}

// Build account menu keyboard
function buildAccountMenuKeyboard(lang: Language): any {
  const keyboard = [
    [
      { text: t(lang, "btn_stats"), callback_data: "action:mystats" },
      { text: t(lang, "btn_settings"), callback_data: "action:settings" }
    ],
    [
      { text: t(lang, "btn_language"), callback_data: "action:lang" }
    ],
    [
      { text: t(lang, "back_to_menu"), callback_data: "menu:main" }
    ]
  ];
  return { inline_keyboard: keyboard };
}

// Build admin menu keyboard
function buildAdminMenuKeyboard(lang: Language): any {
  const keyboard = [
    [
      { text: t(lang, "btn_bot_stats"), callback_data: "admin:stats" },
      { text: t(lang, "btn_user_list"), callback_data: "admin:users" }
    ],
    [
      { text: t(lang, "btn_premium"), callback_data: "admin:premium" },
      { text: t(lang, "btn_blacklist"), callback_data: "admin:blacklist" }
    ],
    [
      { text: t(lang, "btn_cleanup"), callback_data: "admin:cleanup" },
      { text: t(lang, "btn_broadcast"), callback_data: "admin:broadcast_prompt" }
    ],
    [
      { text: t(lang, "back_to_menu"), callback_data: "menu:main" }
    ]
  ];
  return { inline_keyboard: keyboard };
}

// Build back button only
function buildBackButton(target: string, lang: Language): any {
  return {
    inline_keyboard: [[
      { text: t(lang, "back_to_menu"), callback_data: target }
    ]]
  };
}

// Handle /domains command
function handleDomains(env: Bindings): string {
  const domains = getDomains(env);
  
  if (domains.length === 0) {
    return `❌ Tidak ada domain yang dikonfigurasi.`;
  }
  
  if (domains.length === 1) {
    return `🌐 <b>Domain Tersedia</b>

📧 <code>${domains[0]}</code>

Buat email: <code>/create nama</code>`;
  }
  
  let response = `🌐 <b>Domain Tersedia</b>\n\n`;
  domains.forEach((domain, index) => {
    const badge = index === 0 ? " ⭐ (default)" : "";
    response += `📧 <code>${domain}</code>${badge}\n`;
  });
  
  response += `\n━━━━━━━━━━━━━━━
Buat email dengan domain tertentu:
<code>/create nama@${domains[0]}</code>`;
  
  if (domains.length >= 2) {
    response += `\n<code>/create nama@${domains[1]}</code>`;
  }
  
  return response;
}

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
      await ensureUser(c.env.DB, telegramUserId, telegramUsername, c.env);
      
      // Answer callback query to remove loading state
      await fetch(`https://api.telegram.org/bot${c.env.TELEGRAM_BOT_TOKEN}/answerCallbackQuery`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ callback_query_id: callbackQuery.id })
      });

      // Process the callback - edit existing message instead of sending new one
      const result = await processCallback(c.env, telegramUserId, callbackData, chatId, messageId);
      if (result) {
        if (typeof result === 'object' && result.text) {
          await editTelegramMessage(c.env.TELEGRAM_BOT_TOKEN, chatId, messageId, result.text, result.keyboard);
        } else {
          await editTelegramMessage(c.env.TELEGRAM_BOT_TOKEN, chatId, messageId, result as string);
        }
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
    await ensureUser(c.env.DB, telegramUserId, telegramUsername, c.env);
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
// Note: parseFromHeader is now imported from utils/email-parser

async function handleEmail(message: ForwardableEmailMessage, env: Bindings) {
  console.log(`📧 Email received: ${message.from} -> ${message.to}`);

  const toAddress = message.to.toLowerCase();
  const subject = message.headers.get("subject") || "(Tanpa subjek)";
  const fromHeader = message.headers.get("from") || "";
  const senderDisplay = parseFromHeader(fromHeader, message.from);
  const senderLower = message.from.toLowerCase();

  // Check global blacklist
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

  let email = await env.DB.prepare(
    "SELECT e.id, e.user_id, u.telegram_user_id FROM emails e JOIN users u ON e.user_id = u.id WHERE LOWER(e.email_address) = ?"
  )
    .bind(toAddress)
    .first<{ id: number; user_id: number; telegram_user_id: string }>();

  if (!email) {
    console.log("Email address not found, creating catch-all entry:", toAddress);
    
    try {
      const adminUserId = await getOrCreateAdminUser(env.DB, env.ADMIN_USER_ID);
      const localPart = toAddress.split("@")[0];
      
      const emailResult = await env.DB.prepare(
        "INSERT INTO emails (user_id, email_address, local_part, is_active) VALUES (?, ?, ?, 1) RETURNING id"
      )
        .bind(adminUserId, toAddress, localPart)
        .first<{ id: number }>();
    
    if (emailResult) {
        const rawEmail = await new Response(message.raw).text();
        const body = extractEmailBody(rawEmail);
        
        const inboxResult = await env.DB.prepare(
          "INSERT INTO inbox (email_id, sender, subject, body, headers) VALUES (?, ?, ?, ?, ?) RETURNING id"
        )
          .bind(emailResult.id, message.from, subject, body, JSON.stringify(Object.fromEntries(message.headers)))
          .first<{ id: number }>();
        
        if (env.FALLBACK_EMAIL) {
          await message.forward(env.FALLBACK_EMAIL);
        }
        
        const botToken = env.TELEGRAM_BOT_TOKEN;
        if (botToken && env.ADMIN_USER_ID) {
          const msgId = inboxResult?.id || "";
          const catchAllBody = body ? body.substring(0, 3000).trim() : "";
          const notificationText = `📨 <b>Email Baru (Catch-All)</b>

📧 <b>Ke:</b> ${toAddress}
👤 <b>Dari:</b> ${senderDisplay}
📋 <b>Subjek:</b> ${subject}

${catchAllBody}${body && body.length > 3000 ? "\n\n<i>... (pesan terpotong)</i>" : ""}`;
          
          // Add inline button to read
          const keyboard = {
            inline_keyboard: [[
              { text: "📖 Baca Email", callback_data: `read:${msgId}` }
            ]]
          };
          await sendTelegramMessage(botToken, parseInt(env.ADMIN_USER_ID), notificationText, keyboard);
        }
      }
    } catch (e) {
      console.error("Catch-all email creation error:", e);
      if (env.FALLBACK_EMAIL) {
        await message.forward(env.FALLBACK_EMAIL);
      }
    }
    return;
  }

  const rawEmail = await new Response(message.raw).text();
  const body = extractEmailBody(rawEmail);
  const links = extractLinks(rawEmail);

  const inboxResult = await env.DB.prepare(
    "INSERT INTO inbox (email_id, sender, subject, body, headers) VALUES (?, ?, ?, ?, ?) RETURNING id"
  )
    .bind(email.id, message.from, subject, body, JSON.stringify(Object.fromEntries(message.headers)))
    .first<{ id: number }>();

  if (env.FALLBACK_EMAIL) {
    try {
      await message.forward(env.FALLBACK_EMAIL);
      console.log("Email forwarded to backup:", env.FALLBACK_EMAIL);
    } catch (e) {
      console.error("Failed to forward email:", e);
    }
  }

  const bodyPreview = body ? body.substring(0, 3000).trim() : "";
  
  let notificationText = `📬 <b>Email Baru!</b>

📧 <b>Ke:</b> ${toAddress}
👤 <b>Dari:</b> ${senderDisplay}
📋 <b>Subjek:</b> ${subject}

${bodyPreview}${body && body.length > 3000 ? "\n\n<i>... (pesan terpotong)</i>" : ""}`;

  const msgId = inboxResult?.id || "";
  const localPart = toAddress.split("@")[0];
  
  // Build keyboard with action buttons
  const keyboard = {
    inline_keyboard: [
      [
        { text: "📖 Baca Email", callback_data: `read:${msgId}` },
        { text: "📬 Inbox", callback_data: `mails:${localPart}` }
      ]
    ]
  };

  const botToken = env.TELEGRAM_BOT_TOKEN;
  if (botToken) {
    await sendTelegramMessage(botToken, parseInt(email.telegram_user_id), notificationText, keyboard);
  }
}

// Response type for commands with optional keyboard
type CommandResponse = string | { text: string; keyboard?: any };

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
  const userLang = await getUserLanguage(env.DB, telegramUserId);
  const lang = getLang(userLang);
  
  switch (command) {
    case "/start": {
      // Always show language selection first on /start
      return {
        text: `🌍 <b>Pilih Bahasa / Choose Language</b>

Silakan pilih bahasa yang ingin kamu gunakan.
Please select your preferred language.`,
        keyboard: {
          inline_keyboard: [
            [
              { text: "🇮🇩 Bahasa Indonesia", callback_data: "lang:id" },
              { text: "🇬🇧 English", callback_data: "lang:en" }
            ]
          ]
        }
      };
    }
    
    case "/menu": {
      // Show main menu with inline buttons
      return {
        text: `${t(lang, "welcome_title")}

${t(lang, "welcome_desc")}

${t(lang, "menu_desc")}`,
        keyboard: buildMainMenuKeyboard(lang, isAdmin)
      };
    }
    
    case "/menu":
      return {
        text: `${t(lang, "menu_title")}

${t(lang, "menu_desc")}`,
        keyboard: buildMainMenuKeyboard(lang, isAdmin)
      };
    
    case "/help":
      return await getHelpMessage(env.DB, getDomains(env), isAdmin, telegramUserId);
    
    case "/lang":
    case "/language": {
      return {
        text: `🌍 <b>${lang === "id" ? "Ganti Bahasa" : "Change Language"}</b>

${lang === "id" ? "Pilih bahasa:" : "Select language:"}`,
        keyboard: {
          inline_keyboard: [
            [
              { text: "🇮🇩 Bahasa Indonesia", callback_data: "lang:id" },
              { text: "🇬🇧 English", callback_data: "lang:en" }
            ]
          ]
        }
      };
    }

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
      return await handleList(env, telegramUserId);

    case "/delete":
    case "/d":
      if (!isAdmin) {
        return t(lang, "admin_only");
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
        return t(lang, "admin_only");
      }
      return await handleStats(env);

    case "/blacklist":
      return await handleBlacklist(env, telegramUserId, arg);

    case "/forward":
    case "/export":
      return await handleForward(env, telegramUserId, arg);

    case "/cleanup":
      if (!isAdmin) {
        return t(lang, "admin_only");
      }
      return await handleCleanup(env);

    case "/broadcast":
    case "/bc":
      if (!isAdmin) {
        return t(lang, "admin_only");
      }
      return await handleBroadcast(env, telegramUserId, arg);

    case "/users":
    case "/u":
      if (!isAdmin) {
        return t(lang, "admin_only");
      }
      return await handleUsers(env, arg);

    case "/premium":
    case "/p":
      if (!isAdmin) {
        return t(lang, "admin_only");
      }
      return await handlePremium(env, arg);

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

    case "/domains":
      return handleDomains(env);

    default:
      // Show menu for unrecognized commands
      return {
        text: t(lang, "cmd_not_found"),
        keyboard: buildMainMenuKeyboard(lang, isAdmin)
      };
  }
}

// ============ CALLBACK HANDLER (for inline buttons) ============
async function processCallback(
  env: Bindings,
  telegramUserId: string,
  callbackData: string,
  chatId: number,
  messageId: number
): Promise<CommandResponse> {
  const [action, ...params] = callbackData.split(":");
  const isAdmin = telegramUserId === env.ADMIN_USER_ID;
  const lang = getLang(await getUserLanguage(env.DB, telegramUserId));
  
  switch (action) {
    // ========== MENU NAVIGATION ==========
    case "menu":
      switch (params[0]) {
        case "main":
          return {
            text: `${t(lang, "menu_title")}\n\n${t(lang, "menu_desc")}`,
            keyboard: buildMainMenuKeyboard(lang, isAdmin)
          };
        
        case "email":
          return {
            text: `${t(lang, "email_menu_title")}\n\n${t(lang, "choose_action")}`,
            keyboard: buildEmailMenuKeyboard(lang)
          };
        
        case "2fa":
          return {
            text: `${t(lang, "twofa_menu_title")}\n\n${t(lang, "choose_action")}`,
            keyboard: build2FAMenuKeyboard(lang)
          };
        
        case "account":
          return {
            text: `${t(lang, "account_menu_title")}\n\n${t(lang, "choose_action")}`,
            keyboard: buildAccountMenuKeyboard(lang)
          };
        
        case "help":
          return await getHelpMessage(env.DB, getDomains(env), isAdmin, telegramUserId);
        
        case "admin":
          if (!isAdmin) return "";
          return {
            text: `${t(lang, "admin_menu_title")}\n\n${t(lang, "choose_action")}`,
            keyboard: buildAdminMenuKeyboard(lang)
          };
      }
      return "";
    
    // ========== EMAIL ACTIONS ==========
    case "action":
      switch (params[0]) {
        case "create_prompt":
          return {
            text: t(lang, "prompt_create_email"),
            keyboard: buildBackButton("menu:email", lang)
          };
        
        case "list": {
          const result = await handleList(env, telegramUserId);
          if (typeof result === 'string') {
            return { text: result, keyboard: buildBackButton("menu:email", lang) };
          }
          return result;
        }
        
        case "search_prompt":
          return {
            text: t(lang, "prompt_search_email"),
            keyboard: buildBackButton("menu:email", lang)
          };
        
        case "domains":
          return {
            text: handleDomains(env),
            keyboard: buildBackButton("menu:email", lang)
          };
        
        // 2FA Actions
        case "2fa_generate_prompt":
          return {
            text: t(lang, "prompt_2fa_generate"),
            keyboard: buildBackButton("menu:2fa", lang)
          };
        
        case "2fa_list": {
          const result = await handle2FA(env, telegramUserId, "list");
          if (typeof result === 'string') {
            return { text: result, keyboard: buildBackButton("menu:2fa", lang) };
          }
          // Add back button to existing keyboard
          if (result.keyboard) {
            result.keyboard.inline_keyboard.push([
              { text: t(lang, "back_to_menu"), callback_data: "menu:2fa" }
            ]);
          }
          return result;
        }
        
        case "2fa_add_prompt":
          return {
            text: t(lang, "prompt_2fa_add"),
            keyboard: buildBackButton("menu:2fa", lang)
          };
        
        case "qr_prompt":
          return {
            text: t(lang, "prompt_qr"),
            keyboard: buildBackButton("menu:2fa", lang)
          };
        
        case "backup": {
          const result = await handleBackup(env, telegramUserId);
          return { text: result, keyboard: buildBackButton("menu:2fa", lang) };
        }
        
        // Account Actions
        case "mystats": {
          const result = await handleMyStats(env, telegramUserId);
          return { text: result, keyboard: buildBackButton("menu:account", lang) };
        }
        
        case "settings": {
          const result = await handleSettings(env, telegramUserId, "");
          if (typeof result === 'string') {
            return { text: result, keyboard: buildBackButton("menu:account", lang) };
          }
          // Add back button to settings keyboard
          if (result.keyboard) {
            result.keyboard.inline_keyboard.push([
              { text: t(lang, "back_to_menu"), callback_data: "menu:account" }
            ]);
          }
          return result;
        }
        
        case "lang":
          return {
            text: t(lang, "prompt_language"),
            keyboard: {
              inline_keyboard: [
                [
                  { text: "🇮🇩 Bahasa Indonesia", callback_data: "lang:id" },
                  { text: "🇬🇧 English", callback_data: "lang:en" }
                ],
                [
                  { text: t(lang, "back_to_menu"), callback_data: "menu:account" }
                ]
              ]
            }
          };
      }
      return "";
    
    // ========== ADMIN ACTIONS ==========
    case "admin":
      if (!isAdmin) return "";
      
      switch (params[0]) {
        case "stats": {
          const result = await handleStats(env);
          return { text: result, keyboard: buildBackButton("menu:admin", lang) };
        }
        
        case "users": {
          const result = await handleUsers(env, "1");
          return { text: result, keyboard: buildBackButton("menu:admin", lang) };
        }
        
        case "premium": {
          const result = await handlePremium(env, "list");
          return { text: result, keyboard: buildBackButton("menu:admin", lang) };
        }
        
        case "blacklist": {
          const result = await handleBlacklist(env, telegramUserId, "list");
          return { text: result, keyboard: buildBackButton("menu:admin", lang) };
        }
        
        case "cleanup": {
          const result = await handleCleanup(env);
          return { text: result, keyboard: buildBackButton("menu:admin", lang) };
        }
        
        case "broadcast_prompt":
          return {
            text: t(lang, "prompt_broadcast"),
            keyboard: buildBackButton("menu:admin", lang)
          };
      }
      return "";
    
    // ========== EXISTING CALLBACKS ==========
    case "read":
      return await handleRead(env, telegramUserId, params[0]);
    
    case "mails": {
      const result = await handleMails(env, telegramUserId, params[0]);
      return typeof result === 'string' ? result : result;
    }
    
    case "2fa": {
      const result = await handle2FA(env, telegramUserId, params[0]);
      return typeof result === 'string' ? result : result;
    }
    
    case "refresh": {
      const result = await handle2FA(env, telegramUserId, params[0]);
      return typeof result === 'string' ? result : result;
    }
    
    case "set":
      if (params[0] === "autodelete") {
        const result = await handleSettings(env, telegramUserId, `autodelete ${params[1]}`);
        return typeof result === 'string' ? result : result;
      }
      return "";
    
    case "create": {
      const localPart = params[0];
      const domain = params[1];
      const result = await handleCreate(env, telegramUserId, `${localPart}@${domain}`);
      return typeof result === 'string' ? result : result;
    }
    
    case "lang": {
      const newLang = params[0] as Language;
      if (newLang === "id" || newLang === "en") {
        await setUserLanguage(env.DB, telegramUserId, newLang);
        return {
          text: `${t(newLang, "lang_set")}\n\n${t(newLang, "menu_title")}\n\n${t(newLang, "menu_desc")}`,
          keyboard: buildMainMenuKeyboard(newLang, isAdmin)
        };
      }
      return "";
    }
    
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
    
    if (!generateOTP(secret)) {
      return `❌ Secret key tidak valid. Pastikan format Base32 benar.`;
    }

    const isAdmin = telegramUserId === env.ADMIN_USER_ID;
    if (!isAdmin) {
      const existingSecret = await env.DB.prepare(
        "SELECT id FROM totp_secrets WHERE user_id = ? AND name = ?"
      ).bind(userId, name).first();
      
      if (!existingSecret) {
        const limits = await checkUserLimits(env.DB, telegramUserId, '2fa');
        if (!limits.allowed) {
          return `⚠️ <b>Batas 2FA Secret Tercapai</b>

Kamu sudah memiliki <b>${limits.current}/${limits.max}</b> secret.

🗑️ Hapus secret lama dengan <code>/2fa del nama</code>

⭐ Atau upgrade ke <b>Premium</b> untuk unlimited 2FA secrets!`;
        }
      }
    }

    try {
      await env.DB.prepare(
        "INSERT OR REPLACE INTO totp_secrets (user_id, name, secret) VALUES (?, ?, ?)"
      ).bind(userId, name, secret).run();
      
      return {
        text: `✅ 2FA secret "<b>${name}</b>" berhasil disimpan!

📋 Lihat semua: <code>/2fa list</code>
🔢 Generate kode: <code>/2fa ${name}</code>`,
        keyboard: {
          inline_keyboard: [
            [
              { text: `🔢 Generate ${name}`, callback_data: `2fa:${name}` },
              { text: "📋 Daftar", callback_data: "action:2fa_list" }
            ]
          ]
        }
      };
    } catch (e) {
      return `❌ Gagal menyimpan secret.`;
    }
  }

  // /2fa list
  if (subCommand === "list") {
    const isAdmin = telegramUserId === env.ADMIN_USER_ID;
    
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
    
    const result = await env.DB.prepare(
      "SELECT name, created_at FROM totp_secrets WHERE user_id = ? ORDER BY name"
    ).bind(userId).all();

    if (!result.results || result.results.length === 0) {
      return {
        text: `📭 Belum ada 2FA secret tersimpan.

➕ Tambah: <code>/2fa add nama SECRET_KEY</code>`,
        keyboard: {
          inline_keyboard: [[
            { text: "➕ Tambah Secret", callback_data: "action:2fa_add_prompt" }
          ]]
        }
      };
    }

    let response = `🔐 <b>Daftar 2FA Secret</b>\n\n`;
    const secrets = result.results as any[];
    
    for (const item of secrets) {
      response += `🔑 <b>${item.name}</b>\n`;
    }
    response += `\n━━━━━━━━━━━━━━━
👇 Tap tombol untuk generate kode`;

    // Build keyboard with 2FA buttons (max 3 per row)
    const keyboard: any[][] = [];
    for (let i = 0; i < secrets.length; i += 3) {
      const row = secrets.slice(i, i + 3).map((item: any) => ({
        text: `🔢 ${item.name}`,
        callback_data: `2fa:${item.name}`
      }));
      keyboard.push(row);
    }
    
    // Add actions row
    keyboard.push([
      { text: "➕ Tambah", callback_data: "action:2fa_add_prompt" },
      { text: "💾 Backup", callback_data: "action:backup" }
    ]);

    return { text: response, keyboard: { inline_keyboard: keyboard } };
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

  // /2fa (no args) - show help with keyboard
  if (!arg) {
    return {
      text: `🔐 <b>2FA/OTP Manager</b>

Pilih aksi di bawah atau gunakan command:

<code>/2fa SECRET_KEY</code> - Generate kode OTP
<code>/2fa add nama SECRET</code> - Simpan secret
<code>/2fa list</code> - Lihat semua secret
<code>/2fa nama</code> - Generate dari secret tersimpan`,
      keyboard: build2FAMenuKeyboard(getLang(await getUserLanguage(env.DB, telegramUserId)))
    };
  }

  // /2fa nama - generate from saved secret
  const savedSecret = await env.DB.prepare(
    "SELECT secret FROM totp_secrets WHERE user_id = ? AND name = ?"
  ).bind(userId, subCommand).first<{ secret: string }>();

  if (savedSecret) {
    const otp = generateOTP(savedSecret.secret);
    if (otp) {
      return {
        text: `🔐 <b>${subCommand}</b>

🔢 Kode OTP: <code>${otp.code}</code>
⏱️ Berlaku: ${otp.remaining} detik`,
        keyboard: {
          inline_keyboard: [[
            { text: "🔄 Refresh", callback_data: `refresh:${subCommand}` },
            { text: "📋 Daftar", callback_data: "action:2fa_list" }
          ]]
        }
      };
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
async function handleSearch(env: Bindings, telegramUserId: string, query: string): Promise<CommandResponse> {
  if (!query) {
    return {
      text: `🔍 <b>Cari Email</b>

Format: <code>/search kata_kunci</code>

Contoh:
<code>/search verifikasi</code>
<code>/search google</code>`,
      keyboard: buildBackButton("menu:email", getLang(await getUserLanguage(env.DB, telegramUserId)))
    };
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
  const messages = result.results as any[];
  
  // Build keyboard with read buttons
  const keyboard: any[][] = [];
  for (let i = 0; i < Math.min(messages.length, 10); i += 5) {
    const row = messages.slice(i, i + 5).map((msg: any) => ({
      text: `📖 ${msg.id}`,
      callback_data: `read:${msg.id}`
    }));
    keyboard.push(row);
  }
  
  for (const msg of messages) {
    response += `📧 <b>ID ${msg.id}</b> - ${msg.email_address.split('@')[0]}
👤 ${msg.sender.substring(0, 30)}
📋 ${(msg.subject || "(Tanpa subjek)").substring(0, 40)}

`;
  }
  response += `━━━━━━━━━━━━━━━
👆 Tap tombol untuk baca email`;

  return { text: response, keyboard: { inline_keyboard: keyboard } };
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
    const lang = getLang(await getUserLanguage(env.DB, telegramUserId));
    return t(lang, "admin_only");
  }

  const userId = await getUserId(env.DB, telegramUserId);
  if (!userId) return `❌ Error: User tidak ditemukan.`;

  const parts = arg.split(/\s+/);
  const subCommand = parts[0]?.toLowerCase();
  const pattern = parts.slice(1).join(" ") || "";

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

  return `📤 <b>Forward Email</b>

📧 Dari: ${(msg as any).sender}
📋 Subjek: ${(msg as any).subject}
📨 Tujuan: ${targetEmail}

⚠️ Fitur forward email memerlukan SMTP.
💡 Untuk sementara, copy isi email dengan <code>/read ${messageId}</code>`;
}

// Cleanup old emails (admin only)
async function handleCleanup(env: Bindings): Promise<string> {
  const result = await env.DB.prepare(`
    DELETE FROM inbox WHERE id IN (
      SELECT i.id FROM inbox i
      JOIN emails e ON i.email_id = e.id
      JOIN users u ON e.user_id = u.id
      WHERE u.auto_delete_days > 0
        AND i.received_at < datetime('now', '-' || COALESCE(u.auto_delete_days, 7) || ' days')
    )
  `).run();

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

  const users = await env.DB.prepare("SELECT telegram_user_id FROM users").all();
  
  if (!users.results || users.results.length === 0) {
    return `❌ Tidak ada user terdaftar.`;
  }

  const botToken = env.TELEGRAM_BOT_TOKEN;
  const totalUsers = users.results.length;
  let success = 0;
  let failed = 0;
  let processed = 0;

  const getProgressBar = (current: number, total: number): string => {
    const percentage = Math.round((current / total) * 100);
    const filled = Math.round(percentage / 10);
    const empty = 10 - filled;
    return "▓".repeat(filled) + "░".repeat(empty) + ` ${percentage}%`;
  };

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

  return "";
}

// ============ SETTINGS HANDLER ============
async function handleSettings(env: Bindings, telegramUserId: string, arg: string): Promise<CommandResponse> {
  const userId = await getUserId(env.DB, telegramUserId);
  
  const user = await env.DB.prepare(
    "SELECT auto_delete_days, language, timezone FROM users WHERE id = ?"
  ).bind(userId).first() as any;

  const currentAutoDelete = user?.auto_delete_days ?? 7;
  const currentLang = user?.language ?? 'id';
  const currentTz = user?.timezone ?? 'Asia/Jakarta';

  if (!arg) {
    const keyboard = {
      inline_keyboard: [
        [
          { text: "3 hari", callback_data: "set:autodelete:3" },
          { text: "7 hari", callback_data: "set:autodelete:7" },
          { text: "14 hari", callback_data: "set:autodelete:14" }
        ],
        [
          { text: "30 hari", callback_data: "set:autodelete:30" },
          { text: "♾️ Tidak pernah", callback_data: "set:autodelete:0" }
        ]
      ]
    };

    return {
      text: `⚙️ <b>Pengaturan Akun</b>

📅 <b>Auto-delete email:</b> ${currentAutoDelete === 0 ? 'Tidak pernah' : currentAutoDelete + ' hari'}
🌐 <b>Bahasa:</b> ${currentLang === 'id' ? 'Indonesia' : 'English'}
🕐 <b>Timezone:</b> ${currentTz}

━━━━━━━━━━━━━━━
📅 <b>Pilih durasi auto-delete:</b>`,
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

// ============ PREMIUM HANDLER (admin only) ============
async function handlePremium(env: Bindings, arg: string): Promise<string> {
  const parts = arg.split(/\s+/);
  const subCommand = parts[0]?.toLowerCase();
  const targetId = parts[1] || "";

  if (!arg || subCommand === "list") {
    const result = await env.DB.prepare(`
      SELECT telegram_user_id, telegram_username, created_at 
      FROM users WHERE is_premium = 1 ORDER BY created_at DESC
    `).all();

    if (!result.results || result.results.length === 0) {
      return `📭 Belum ada user premium.

➕ Tambah: <code>/premium add TELEGRAM_ID</code>`;
    }

    let response = `⭐ <b>Daftar User Premium</b>\n\n`;
    for (const user of result.results as any[]) {
      const username = user.telegram_username ? `@${user.telegram_username}` : "(no username)";
      response += `👤 ${username}\n   ID: <code>${user.telegram_user_id}</code>\n\n`;
    }
    response += `━━━━━━━━━━━━━━━
➕ Tambah: <code>/premium add ID</code>
➖ Hapus: <code>/premium del ID</code>`;
    return response;
  }

  if (subCommand === "add" || subCommand === "set") {
    if (!targetId) {
      return `⚠️ Format: <code>/premium add TELEGRAM_ID</code>`;
    }

    const user = await env.DB.prepare(
      "SELECT id, telegram_username FROM users WHERE telegram_user_id = ?"
    ).bind(targetId).first<{ id: number; telegram_username: string }>();

    if (!user) {
      return `❌ User dengan ID <code>${targetId}</code> tidak ditemukan.`;
    }

    await env.DB.prepare("UPDATE users SET is_premium = 1 WHERE telegram_user_id = ?").bind(targetId).run();

    const username = user.telegram_username ? `@${user.telegram_username}` : "(no username)";
    
    try {
      await sendTelegramMessage(env.TELEGRAM_BOT_TOKEN, parseInt(targetId), 
        `🎉 <b>Selamat!</b>\n\nAkun kamu telah di-upgrade ke <b>Premium</b>!\n\n⭐ Benefit:\n• Unlimited email\n• Unlimited 2FA secrets\n• Unlimited inbox\n• Prioritas support`);
    } catch (e) {
      console.error("Failed to notify user:", e);
    }

    return `✅ User ${username} (<code>${targetId}</code>) sekarang <b>Premium</b>!`;
  }

  if (subCommand === "del" || subCommand === "rm" || subCommand === "remove") {
    if (!targetId) {
      return `⚠️ Format: <code>/premium del TELEGRAM_ID</code>`;
    }

    const result = await env.DB.prepare(
      "UPDATE users SET is_premium = 0 WHERE telegram_user_id = ?"
    ).bind(targetId).run();

    if (result.meta.changes === 0) {
      return `❌ User dengan ID <code>${targetId}</code> tidak ditemukan.`;
    }

    return `✅ Status premium user <code>${targetId}</code> dicabut.`;
  }

  if (subCommand === "check" || subCommand === "info") {
    if (!targetId) {
      return `⚠️ Format: <code>/premium check TELEGRAM_ID</code>`;
    }

    const user = await env.DB.prepare(`
      SELECT telegram_username, is_premium,
        (SELECT COUNT(*) FROM emails WHERE user_id = users.id) as email_count,
        (SELECT COUNT(*) FROM totp_secrets WHERE user_id = users.id) as totp_count
      FROM users WHERE telegram_user_id = ?
    `).bind(targetId).first<any>();

    if (!user) {
      return `❌ User dengan ID <code>${targetId}</code> tidak ditemukan.`;
    }

    const username = user.telegram_username ? `@${user.telegram_username}` : "(no username)";
    const status = user.is_premium === 1 ? "⭐ Premium" : "👤 Free";
    const limits = user.is_premium === 1 
      ? "Unlimited" 
      : `${user.email_count}/${LIMITS.FREE_MAX_EMAILS} email, ${user.totp_count}/${LIMITS.FREE_MAX_2FA} 2FA`;

    return `👤 <b>Info User</b>

${username}
ID: <code>${targetId}</code>
Status: ${status}
Usage: ${limits}`;
  }

  return `⭐ <b>Premium Management</b>

<code>/premium list</code> - Lihat semua premium user
<code>/premium add ID</code> - Jadikan user premium
<code>/premium del ID</code> - Cabut status premium
<code>/premium check ID</code> - Cek status user

📊 Limit Free User:
• Max ${LIMITS.FREE_MAX_EMAILS} email
• Max ${LIMITS.FREE_MAX_2FA} 2FA secrets
• Max ${LIMITS.FREE_MAX_INBOX} inbox`;
}

// ============ USERS HANDLER (admin only) ============
async function handleUsers(env: Bindings, arg: string): Promise<string> {
  const page = parseInt(arg) || 1;
  const perPage = 20;
  const offset = (page - 1) * perPage;

  const totalResult = await env.DB.prepare("SELECT COUNT(*) as count FROM users").first<{ count: number }>();
  const total = totalResult?.count || 0;
  const totalPages = Math.ceil(total / perPage);

  if (total === 0) {
    return `📭 Belum ada user terdaftar.`;
  }

  const users = await env.DB.prepare(`
    SELECT 
      u.id,
      u.telegram_user_id,
      u.telegram_username,
      u.created_at,
      u.auto_delete_days,
      (SELECT COUNT(*) FROM emails WHERE user_id = u.id) as email_count,
      (SELECT COUNT(*) FROM inbox i JOIN emails e ON i.email_id = e.id WHERE e.user_id = u.id) as inbox_count,
      (SELECT COUNT(*) FROM totp_secrets WHERE user_id = u.id) as totp_count
    FROM users u
    ORDER BY u.created_at DESC
    LIMIT ? OFFSET ?
  `).bind(perPage, offset).all();

  if (!users.results || users.results.length === 0) {
    return `❌ Halaman ${page} tidak ditemukan.`;
  }

  let response = `👥 <b>Daftar Pengguna Bot</b>\n`;
  response += `📊 Total: <b>${total}</b> user (Halaman ${page}/${totalPages})\n\n`;

  for (const user of users.results as any[]) {
    const username = user.telegram_username ? `@${user.telegram_username}` : "(no username)";
    const joinDate = new Date(user.created_at).toLocaleDateString('id-ID');
    
    response += `👤 <b>${username}</b>\n`;
    response += `   ID: <code>${user.telegram_user_id}</code>\n`;
    response += `   📧 ${user.email_count} email | 📬 ${user.inbox_count} pesan | 🔐 ${user.totp_count} 2FA\n`;
    response += `   📅 Bergabung: ${joinDate}\n\n`;
  }

  response += `━━━━━━━━━━━━━━━\n`;
  if (totalPages > 1) {
    response += `📄 Halaman lain: <code>/users 2</code>, <code>/users 3</code>, dst.`;
  }

  return response;
}

// ============ MY STATS HANDLER ============
async function handleMyStats(env: Bindings, telegramUserId: string): Promise<string> {
  const userId = await getUserId(env.DB, telegramUserId);

  const user = await env.DB.prepare(
    "SELECT telegram_username, auto_delete_days, created_at FROM users WHERE id = ?"
  ).bind(userId).first() as any;

  const emailCount = await env.DB.prepare(
    "SELECT COUNT(*) as count FROM emails WHERE user_id = ?"
  ).bind(userId).first() as any;

  const inboxStats = await env.DB.prepare(`
    SELECT 
      COUNT(*) as total,
      SUM(CASE WHEN is_read = 0 THEN 1 ELSE 0 END) as unread
    FROM inbox i
    JOIN emails e ON i.email_id = e.id
    WHERE e.user_id = ?
  `).bind(userId).first() as any;

  const totpCount = await env.DB.prepare(
    "SELECT COUNT(*) as count FROM totp_secrets WHERE user_id = ?"
  ).bind(userId).first() as any;

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

  const secrets = await env.DB.prepare(
    "SELECT name, secret, created_at FROM totp_secrets WHERE user_id = ? ORDER BY name"
  ).bind(userId).all();

  if (!secrets.results || secrets.results.length === 0) {
    return `📭 Tidak ada 2FA secret untuk di-backup.

➕ Tambah secret: <code>/2fa add nama SECRET</code>`;
  }

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

  const result = await env.DB.prepare(
    "SELECT secret FROM totp_secrets WHERE user_id = ? AND name = ?"
  ).bind(userId, name).first() as any;

  if (!result) {
    return `❌ Secret "<b>${name}</b>" tidak ditemukan.

📋 Lihat daftar: <code>/2fa list</code>`;
  }

  const otpauthUri = `otpauth://totp/${encodeURIComponent(name)}?secret=${result.secret}&issuer=TempEmailBot`;
  const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=${encodeURIComponent(otpauthUri)}`;

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

  return "";
}

async function getHelpMessage(db: D1Database, domains: string[], isAdmin: boolean, telegramUserId: string): Promise<CommandResponse> {
  const lang = getLang(await getUserLanguage(db, telegramUserId));
  const defaultDomain = domains[0] || "example.com";
  const or = lang === "id" ? "atau" : "or";
  const multiDomainInfo = domains.length > 1 
    ? `\n<b>/domains</b> - ${t(lang, "domains_desc")}` 
    : "";
  
  let message = `${t(lang, "welcome_title")}

${t(lang, "welcome_desc")}

━━━ ${t(lang, "email_section")} ━━━

<b>/create</b> ${or} <b>/c</b> <code>nama</code>
${t(lang, "create_desc")} (→ <code>nama@${defaultDomain}</code>)${multiDomainInfo}

<b>/mails</b> ${or} <b>/m</b> <code>nama</code>
${t(lang, "mails_desc")}

<b>/search</b> ${or} <b>/s</b> <code>kata</code>
${t(lang, "search_desc")}

━━━ ${t(lang, "twofa_section")} ━━━

<b>/2fa</b> ${or} <b>/a</b> <code>secret</code>
${t(lang, "twofa_desc")}

<b>/2fa add</b> <code>nama secret</code>
${t(lang, "twofa_add_desc")}

<b>/2fa list</b>
${t(lang, "twofa_list_desc")}

━━━ ${t(lang, "account_section")} ━━━

<b>/mystats</b> ${or} <b>/me</b>
${t(lang, "mystats_desc")}

<b>/setting</b>
${t(lang, "settings_desc")}

━━━━━━━━━━━━━━━
💡 Gunakan /menu untuk navigasi dengan tombol`;

  if (isAdmin) {
    message += `

━━━ ${t(lang, "admin_section")} ━━━
/stats, /users, /premium, /blacklist, /cleanup, /broadcast`;
  }

  return {
    text: message,
    keyboard: buildMainMenuKeyboard(lang, isAdmin)
  };
}

async function handleCreate(env: Bindings, telegramUserId: string, name: string): Promise<CommandResponse> {
  const domains = getDomains(env);
  const lang = getLang(await getUserLanguage(env.DB, telegramUserId));
  
  if (domains.length === 0) {
    return `❌ Error: Tidak ada domain yang dikonfigurasi. Hubungi admin.`;
  }
  
  const defaultDomain = domains[0];

  if (!name) {
    let example = `<code>/create tokoku</code>`;
    if (domains.length > 1) {
      example += `\n<code>/create tokoku@${domains[1]}</code> (pilih domain)`;
    }
    return {
      text: `⚠️ Masukkan nama untuk email.

Contoh: ${example}
→ Akan membuat <code>tokoku@${defaultDomain}</code>`,
      keyboard: buildBackButton("menu:email", lang)
    };
  }

  let localPart: string;
  let selectedDomain: string;
  
  if (name.includes("@")) {
    const parts = name.split("@");
    localPart = parts[0].toLowerCase().replace(/[^a-z0-9]/g, "");
    const requestedDomain = parts[1]?.toLowerCase().trim();
    
    if (requestedDomain && domains.map(d => d.toLowerCase()).includes(requestedDomain)) {
      selectedDomain = requestedDomain;
    } else if (requestedDomain) {
      return `⚠️ Domain <b>${requestedDomain}</b> tidak tersedia.

📋 Domain tersedia:
${domains.map(d => `• <code>${d}</code>`).join("\n")}

Contoh: <code>/create ${localPart}@${defaultDomain}</code>`;
    } else {
      selectedDomain = defaultDomain;
    }
  } else {
    localPart = name.toLowerCase().replace(/[^a-z0-9]/g, "");
    selectedDomain = defaultDomain;
  }
  
  if (localPart.length < 3) {
    return `⚠️ Nama email minimal 3 karakter (huruf dan angka saja).`;
  }

  if (localPart.length > 30) {
    return `⚠️ Nama email maksimal 30 karakter.`;
  }

  // If multiple domains and no domain specified, show keyboard
  if (domains.length > 1 && !name.includes("@")) {
    const keyboard = domains.map(domain => [{
      text: `📧 ${localPart}@${domain}`,
      callback_data: `create:${localPart}:${domain}`
    }]);
    keyboard.push([{ text: t(lang, "back_to_menu"), callback_data: "menu:email" }]);
    
    return {
      text: `📧 <b>Pilih domain untuk: ${localPart}</b>\n\n👇 Tap untuk memilih:`,
      keyboard: { inline_keyboard: keyboard }
    };
  }

  const emailAddress = `${localPart}@${selectedDomain}`;

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

  const isAdmin = telegramUserId === env.ADMIN_USER_ID;
  if (!isAdmin) {
    const limits = await checkUserLimits(env.DB, telegramUserId, 'email');
    if (!limits.allowed) {
      return `⚠️ <b>Batas Email Tercapai</b>

Kamu sudah memiliki <b>${limits.current}/${limits.max}</b> email.

🗑️ Hapus email lama dengan <code>/delete nama</code>

⭐ Atau upgrade ke <b>Premium</b> untuk unlimited email!`;
    }
  }

  await env.DB.prepare("INSERT INTO emails (user_id, email_address, local_part) VALUES (?, ?, ?)")
    .bind(userId, emailAddress, localPart)
    .run();

  return {
    text: `✅ <b>Email berhasil dibuat!</b>

📧 <code>${emailAddress}</code>

Gunakan alamat ini untuk menerima email. Ketika ada email masuk, kamu akan mendapat notifikasi di sini.`,
    keyboard: {
      inline_keyboard: [
        [
          { text: "📬 Cek Inbox", callback_data: `mails:${localPart}` },
          { text: "📋 Daftar Email", callback_data: "action:list" }
        ],
        [
          { text: t(lang, "back_to_menu"), callback_data: "menu:email" }
        ]
      ]
    }
  };
}

async function handleMails(env: Bindings, telegramUserId: string, identifier: string): Promise<CommandResponse> {
  const domains = getDomains(env);
  const defaultDomain = domains[0] || "example.com";
  const lang = getLang(await getUserLanguage(env.DB, telegramUserId));
  
  if (!identifier) {
    return {
      text: `⚠️ Masukkan nama email yang ingin dicek.

Contoh: <code>/mails tokoku</code>

📋 Lihat semua email: <code>/list</code>`,
      keyboard: buildBackButton("menu:email", lang)
    };
  }

  const isAdmin = telegramUserId === env.ADMIN_USER_ID;
  
  let emailAddress: string;
  if (identifier.includes("@")) {
    emailAddress = identifier.toLowerCase();
  } else {
    const userId = await getUserId(env.DB, telegramUserId);
    if (userId) {
      const found = await env.DB.prepare(
        "SELECT email_address FROM emails WHERE user_id = ? AND LOWER(email_address) LIKE ? AND is_active = 1"
      ).bind(userId, `${identifier.toLowerCase()}@%`).first<{ email_address: string }>();
      
      if (found) {
        emailAddress = found.email_address;
      } else {
        emailAddress = `${identifier.toLowerCase()}@${defaultDomain}`;
      }
    } else {
      emailAddress = `${identifier.toLowerCase()}@${defaultDomain}`;
    }
  }

  let email;
  if (isAdmin) {
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
    return {
      text: `⚠️ Email <code>${emailAddress}</code> tidak ditemukan.

📋 Lihat semua email: <code>/list</code>`,
      keyboard: buildBackButton("menu:email", lang)
    };
  }

  const result = await env.DB.prepare(
    `SELECT id, sender, subject, is_read, received_at FROM inbox 
     WHERE email_id = ? ORDER BY received_at DESC LIMIT 20`
  )
    .bind(email.id)
    .all();

  if (!result.results || result.results.length === 0) {
    return {
      text: `📭 <b>Inbox kosong</b>

📧 <code>${email.email_address}</code>

Belum ada email masuk. Gunakan alamat di atas untuk menerima email.`,
      keyboard: {
        inline_keyboard: [
          [{ text: "🔄 Refresh", callback_data: `mails:${emailAddress.split("@")[0]}` }],
          [{ text: t(lang, "back_to_menu"), callback_data: "menu:email" }]
        ]
      }
    };
  }

  let response = `📬 <b>Inbox: ${email.email_address}</b>

`;

  const keyboard: any[][] = [];
  const messages = result.results as any[];
  
  // Read buttons (max 5 per row, max 3 rows)
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
👆 Tap tombol untuk baca email`;

  const localPart = email.email_address.split("@")[0];
  keyboard.push([
    { text: "🔄 Refresh", callback_data: `mails:${localPart}` }
  ]);
  keyboard.push([
    { text: t(lang, "back_to_menu"), callback_data: "menu:email" }
  ]);

  return { text: response, keyboard: { inline_keyboard: keyboard } };
}

async function handleRead(env: Bindings, telegramUserId: string, messageId: string): Promise<CommandResponse> {
  const lang = getLang(await getUserLanguage(env.DB, telegramUserId));
  
  if (!messageId || isNaN(parseInt(messageId))) {
    return {
      text: `⚠️ Masukkan ID email yang ingin dibaca.

Contoh: <code>/read 5</code>`,
      keyboard: buildBackButton("menu:email", lang)
    };
  }

  const userId = await getUserId(env.DB, telegramUserId);
  if (!userId) {
    return `❌ Error: User tidak ditemukan.`;
  }

  const isAdmin = telegramUserId === env.ADMIN_USER_ID;

  let msg;
  if (isAdmin) {
    msg = await env.DB.prepare(
      `SELECT i.*, e.email_address, e.local_part FROM inbox i 
       JOIN emails e ON i.email_id = e.id 
       WHERE i.id = ?`
    )
      .bind(parseInt(messageId))
      .first<{ id: number; sender: string; subject: string; body: string; email_address: string; local_part: string; received_at: string }>();
  } else {
    msg = await env.DB.prepare(
      `SELECT i.*, e.email_address, e.local_part FROM inbox i 
       JOIN emails e ON i.email_id = e.id 
       WHERE i.id = ? AND e.user_id = ?`
    )
      .bind(parseInt(messageId), userId)
      .first<{ id: number; sender: string; subject: string; body: string; email_address: string; local_part: string; received_at: string }>();
  }

  if (!msg) {
    return `⚠️ Email dengan ID ${messageId} tidak ditemukan atau bukan milik kamu.`;
  }

  await env.DB.prepare("UPDATE inbox SET is_read = 1 WHERE id = ?").bind(parseInt(messageId)).run();

  let rawBody = msg.body || "(Tidak ada isi)";
  
  if (isBase64(rawBody)) {
    rawBody = decodeBase64(rawBody);
  }
  
  const base64Match = rawBody.match(/([A-Za-z0-9+/]{100,}=*)/);
  if (base64Match && isBase64(base64Match[1])) {
    try {
      const decoded = decodeBase64(base64Match[1]);
      if (decoded.includes('<') || /[a-zA-Z]{3,}/.test(decoded)) {
        rawBody = decoded;
      }
    } catch {}
  }
  
  const body = stripHtml(rawBody).substring(0, 3000);

  return {
    text: `📧 <b>Email #${msg.id}</b>

📬 <b>Ke:</b> ${msg.email_address}
👤 <b>Dari:</b> ${msg.sender}
📋 <b>Subjek:</b> ${msg.subject || "(Tanpa subjek)"}
⏰ <b>Waktu:</b> ${msg.received_at}

━━━━━━━━━━━━━━━
${body}`,
    keyboard: {
      inline_keyboard: [
        [
          { text: "📬 Kembali ke Inbox", callback_data: `mails:${msg.local_part}` }
        ],
        [
          { text: t(lang, "back_to_menu"), callback_data: "menu:email" }
        ]
      ]
    }
  };
}

async function handleList(env: Bindings, telegramUserId: string): Promise<CommandResponse> {
  const isAdmin = telegramUserId === env.ADMIN_USER_ID;
  const lang = getLang(await getUserLanguage(env.DB, telegramUserId));

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
    return {
      text: isAdminView 
        ? `📭 <b>Belum ada email terdaftar.</b>`
        : `📭 <b>Kamu belum punya email.</b>

Buat email baru dengan:
<code>/create namaemailmu</code>`,
      keyboard: {
        inline_keyboard: [
          [{ text: "➕ Buat Email Baru", callback_data: "action:create_prompt" }],
          [{ text: t(lang, "back_to_menu"), callback_data: "menu:email" }]
        ]
      }
    };
  }

  let response = isAdminView 
    ? `📋 <b>Semua Email (Admin View)</b>

`
    : `📋 <b>Daftar Email Kamu</b>

`;

  // Build keyboard with inbox buttons
  const keyboard: any[][] = [];
  const emails = result.results as any[];
  
  for (let i = 0; i < Math.min(emails.length, 9); i += 3) {
    const row = emails.slice(i, i + 3).map((email: any) => ({
      text: `📬 ${email.local_part}${email.unread_count > 0 ? ` (${email.unread_count})` : ''}`,
      callback_data: `mails:${email.local_part}`
    }));
    keyboard.push(row);
  }

  for (const email of emails) {
    const unread = email.unread_count > 0 ? ` (📩 ${email.unread_count} baru)` : "";
    const owner = isAdminView && email.telegram_username ? ` [@${email.telegram_username}]` : "";
    response += `📧 <code>${email.email_address}</code>${unread}${owner}
   📬 ${email.message_count} pesan

`;
  }

  response += `━━━━━━━━━━━━━━━
👆 Tap tombol untuk cek inbox`;

  keyboard.push([{ text: "➕ Buat Email Baru", callback_data: "action:create_prompt" }]);
  keyboard.push([{ text: t(lang, "back_to_menu"), callback_data: "menu:email" }]);

  return { text: response, keyboard: { inline_keyboard: keyboard } };
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
async function ensureUser(db: D1Database, telegramUserId: string, username?: string, env?: Bindings): Promise<{ isNew: boolean }> {
  const existing = await db
    .prepare("SELECT id FROM users WHERE telegram_user_id = ?")
    .bind(telegramUserId)
    .first();

  if (!existing) {
    await db
      .prepare("INSERT INTO users (telegram_user_id, telegram_username) VALUES (?, ?)")
      .bind(telegramUserId, username || null)
      .run();
    
    if (env && env.ADMIN_USER_ID && telegramUserId !== env.ADMIN_USER_ID) {
      const usernameDisplay = username ? `@${username}` : "(no username)";
      const alertText = `🆕 <b>User Baru Bergabung!</b>

👤 ${usernameDisplay}
🆔 ID: <code>${telegramUserId}</code>
📅 Waktu: ${new Date().toLocaleString('id-ID', { timeZone: 'Asia/Jakarta' })}`;
      
      try {
        await sendTelegramMessage(env.TELEGRAM_BOT_TOKEN, parseInt(env.ADMIN_USER_ID), alertText);
      } catch (e) {
        console.error("Failed to send new user alert:", e);
      }
    }
    
    return { isNew: true };
  }
  
  if (username) {
    await db
      .prepare("UPDATE users SET telegram_username = ? WHERE telegram_user_id = ?")
      .bind(username, telegramUserId)
      .run();
  }
  
  return { isNew: false };
}

async function getUserId(db: D1Database, telegramUserId: string): Promise<number | null> {
  const user = await db
    .prepare("SELECT id FROM users WHERE telegram_user_id = ?")
    .bind(telegramUserId)
    .first<{ id: number }>();
  return user?.id || null;
}

async function getUserLanguage(db: D1Database, telegramUserId: string): Promise<Language | null> {
  const user = await db
    .prepare("SELECT language FROM users WHERE telegram_user_id = ?")
    .bind(telegramUserId)
    .first<{ language: string | null }>();
  return (user?.language as Language) || null;
}

function getLang(lang: Language | null): Language {
  return lang || "id";
}

async function setUserLanguage(db: D1Database, telegramUserId: string, lang: Language): Promise<void> {
  await db
    .prepare("UPDATE users SET language = ? WHERE telegram_user_id = ?")
    .bind(lang, telegramUserId)
    .run();
}

const LIMITS = {
  FREE_MAX_EMAILS: 3,
  FREE_MAX_2FA: 5,
  FREE_MAX_INBOX: 50,
};

async function checkPremiumStatus(db: D1Database, telegramUserId: string): Promise<{ isPremium: boolean; userId: number | null }> {
  const user = await db
    .prepare("SELECT id, is_premium FROM users WHERE telegram_user_id = ?")
    .bind(telegramUserId)
    .first<{ id: number; is_premium: number }>();
  return { 
    isPremium: user?.is_premium === 1, 
    userId: user?.id || null 
  };
}

async function checkUserLimits(db: D1Database, telegramUserId: string, type: 'email' | '2fa' | 'inbox'): Promise<{ allowed: boolean; current: number; max: number; isPremium: boolean }> {
  const { isPremium, userId } = await checkPremiumStatus(db, telegramUserId);
  
  if (isPremium || !userId) {
    return { allowed: true, current: 0, max: -1, isPremium };
  }
  
  let current = 0;
  let max = 0;
  
  switch (type) {
    case 'email':
      const emailCount = await db.prepare("SELECT COUNT(*) as count FROM emails WHERE user_id = ?").bind(userId).first<{ count: number }>();
      current = emailCount?.count || 0;
      max = LIMITS.FREE_MAX_EMAILS;
      break;
    case '2fa':
      const tfaCount = await db.prepare("SELECT COUNT(*) as count FROM totp_secrets WHERE user_id = ?").bind(userId).first<{ count: number }>();
      current = tfaCount?.count || 0;
      max = LIMITS.FREE_MAX_2FA;
      break;
    case 'inbox':
      const inboxCount = await db.prepare("SELECT COUNT(*) as count FROM inbox i JOIN emails e ON i.email_id = e.id WHERE e.user_id = ?").bind(userId).first<{ count: number }>();
      current = inboxCount?.count || 0;
      max = LIMITS.FREE_MAX_INBOX;
      break;
  }
  
  return { allowed: current < max, current, max, isPremium };
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
    if (keyboard.inline_keyboard) {
      body.reply_markup = keyboard;
    } else {
      body.reply_markup = { inline_keyboard: keyboard };
    }
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

// Edit existing message instead of sending new one (prevents chat spam)
async function editTelegramMessage(botToken: string, chatId: number, messageId: number, text: string, keyboard?: any) {
  const body: any = {
    chat_id: chatId,
    message_id: messageId,
    text: text,
    parse_mode: "HTML",
  };
  
  if (keyboard) {
    if (keyboard.inline_keyboard) {
      body.reply_markup = keyboard;
    } else {
      body.reply_markup = { inline_keyboard: keyboard };
    }
  }
  
  const response = await fetch(`https://api.telegram.org/bot${botToken}/editMessageText`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    console.error("Telegram editMessage error:", await response.text());
  }
}

// ============ EMAIL PARSING FUNCTIONS ============
// All email parsing functions are now imported from utils/email-parser
// The new parser provides:
// - Better charset detection (UTF-8, ISO-8859-1, Windows-1252, etc.)
// - RFC 2047 encoded header support
// - Improved Base64 and Quoted-Printable decoding
// - Better handling of malformed emails
// - More accurate MIME part extraction

// ============ EXPORTS ============
export default {
  fetch: app.fetch,
  email: handleEmail,
};
