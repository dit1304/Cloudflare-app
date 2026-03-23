/**
 * Email-related command handlers
 */

import type { Bindings, CommandResponse, Language } from '../types';
import { getDomains, validateEmailLocalPart, sanitizeLocalPart, isAdmin } from '../utils/helpers';
import { getUserId, checkUserLimits, createEmail, getUserEmails, getUserLanguage } from '../services/database';
import { t, getLang } from '../utils/translations';
import { buildBackButton, buildMainMenuKeyboard } from '../utils/keyboards';
import { getSenderDisplayFromHeaders, stripHtml } from '../utils/email-parser';

/**
 * Handle /create command - Create new email
 */
export async function handleCreate(
  env: Bindings,
  telegramUserId: string,
  name: string
): Promise<CommandResponse> {
  const domains = getDomains(env);
  const lang = getLang(await getUserLanguage(env.DB, telegramUserId));

  if (domains.length === 0) {
    return {
      text: `❌ Error: Tidak ada domain yang dikonfigurasi. Hubungi admin.`,
      keyboard: buildBackButton("menu:email", lang)
    };
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
    localPart = sanitizeLocalPart(parts[0]);
    const requestedDomain = parts[1]?.toLowerCase().trim();

    if (requestedDomain && domains.map(d => d.toLowerCase()).includes(requestedDomain)) {
      selectedDomain = requestedDomain;
    } else if (requestedDomain) {
      return {
        text: `⚠️ Domain <b>${requestedDomain}</b> tidak tersedia.

📋 Domain tersedia:
${domains.map(d => `• <code>${d}</code>`).join("\n")}

Contoh: <code>/create ${localPart}@${defaultDomain}</code>`,
        keyboard: buildBackButton("menu:email", lang)
      };
    } else {
      selectedDomain = defaultDomain;
    }
  } else {
    localPart = sanitizeLocalPart(name);
    selectedDomain = defaultDomain;
  }

  // Validate local part
  const validation = validateEmailLocalPart(localPart);
  if (!validation.valid) {
    return {
      text: `⚠️ ${validation.error}`,
      keyboard: buildBackButton("menu:email", lang)
    };
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
  const userId = await getUserId(env.DB, telegramUserId);
  if (!userId) {
    return { text: `❌ Error: User tidak ditemukan.` };
  }

  // Check limits for non-admin users
  if (!isAdmin(telegramUserId, env)) {
    const limits = await checkUserLimits(env.DB, telegramUserId, 'email');
    if (!limits.allowed) {
      return {
        text: `⚠️ <b>Batas Email Tercapai</b>

Kamu sudah memiliki <b>${limits.current}/${limits.max}</b> email.

🗑️ Hapus email lama dengan <code>/delete nama</code>

⭐ Atau upgrade ke <b>Premium</b> untuk unlimited email!`,
        keyboard: buildBackButton("menu:email", lang)
      };
    }
  }

  // Create email
  const result = await createEmail(env.DB, userId, emailAddress, localPart);
  if (!result.success) {
    return {
      text: `⚠️ Email <code>${emailAddress}</code> sudah digunakan.

Coba nama lain, contoh: <code>/create ${localPart}123</code>`,
      keyboard: buildBackButton("menu:email", lang)
    };
  }

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

/**
 * Handle /list command - List all emails
 */
export async function handleList(
  env: Bindings,
  telegramUserId: string
): Promise<CommandResponse> {
  const lang = getLang(await getUserLanguage(env.DB, telegramUserId));
  const userIsAdmin = isAdmin(telegramUserId, env);

  let result;
  if (userIsAdmin) {
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
      return { text: `❌ Error: User tidak ditemukan.` };
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

  if (!result.results || result.results.length === 0) {
    return {
      text: userIsAdmin
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

  let response = userIsAdmin
    ? `📋 <b>Semua Email (Admin View)</b>\n\n`
    : `📋 <b>Daftar Email Kamu</b>\n\n`;

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
    const owner = userIsAdmin && email.telegram_username ? ` [@${email.telegram_username}]` : "";
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

/**
 * Handle /mails command - Check inbox
 */
export async function handleMails(
  env: Bindings,
  telegramUserId: string,
  identifier: string
): Promise<CommandResponse> {
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

  const userIsAdmin = isAdmin(telegramUserId, env);

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
  if (userIsAdmin) {
    email = await env.DB.prepare(
      "SELECT id, email_address FROM emails WHERE LOWER(email_address) = ? AND is_active = 1"
    )
      .bind(emailAddress)
      .first<{ id: number; email_address: string }>();
  } else {
    const userId = await getUserId(env.DB, telegramUserId);
    if (!userId) {
      return { text: `❌ Error: User tidak ditemukan.` };
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

  let response = `📬 <b>Inbox: ${email.email_address}</b>\n\n`;

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
    response += `${status} <b>ID ${msg.id}</b> - ${shortSubject}\n`;
  }

  response += `\n━━━━━━━━━━━━━━━\n👆 Tap tombol untuk baca email`;

  const localPart = email.email_address.split("@")[0];
  keyboard.push([{ text: "🔄 Refresh", callback_data: `mails:${localPart}` }]);
  keyboard.push([{ text: t(lang, "back_to_menu"), callback_data: "menu:email" }]);

  return { text: response, keyboard: { inline_keyboard: keyboard } };
}

/**
 * Handle /read command - Read email
 */
export async function handleRead(
  env: Bindings,
  telegramUserId: string,
  messageId: string
): Promise<CommandResponse> {
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
    return { text: `❌ Error: User tidak ditemukan.` };
  }

  const userIsAdmin = isAdmin(telegramUserId, env);

  let msg;
  if (userIsAdmin) {
    msg = await env.DB.prepare(
      `SELECT i.*, e.email_address, e.local_part FROM inbox i 
       JOIN emails e ON i.email_id = e.id 
       WHERE i.id = ?`
    )
      .bind(parseInt(messageId))
      .first<{
        id: number;
        sender: string;
        subject: string;
        body: string;
        headers?: string;
        email_address: string;
        local_part: string;
        received_at: string;
      }>();
  } else {
    msg = await env.DB.prepare(
      `SELECT i.*, e.email_address, e.local_part FROM inbox i 
       JOIN emails e ON i.email_id = e.id 
       WHERE i.id = ? AND e.user_id = ?`
    )
      .bind(parseInt(messageId), userId)
      .first<{
        id: number;
        sender: string;
        subject: string;
        body: string;
        headers?: string;
        email_address: string;
        local_part: string;
        received_at: string;
      }>();
  }

  if (!msg) {
    return {
      text: `⚠️ Email dengan ID ${messageId} tidak ditemukan atau bukan milik kamu.`,
      keyboard: buildBackButton("menu:email", lang)
    };
  }

  // Mark as read
  await env.DB.prepare("UPDATE inbox SET is_read = 1 WHERE id = ?")
    .bind(parseInt(messageId))
    .run();

  const senderDisplay = getSenderDisplayFromHeaders(msg.sender, msg.headers);
  const body = stripHtml(msg.body || "(Tidak ada isi)").substring(0, 3000);

  return {
    text: `📧 <b>Email #${msg.id}</b>

📬 <b>Ke:</b> ${msg.email_address}
👤 <b>Dari:</b> ${senderDisplay}
📋 <b>Subjek:</b> ${msg.subject || "(Tanpa subjek)"}
⏰ <b>Waktu:</b> ${msg.received_at}

━━━━━━━━━━━━━━━
${body}`,
    keyboard: {
      inline_keyboard: [
        [{ text: "📬 Kembali ke Inbox", callback_data: `mails:${msg.local_part}` }],
        [{ text: t(lang, "back_to_menu"), callback_data: "menu:email" }]
      ]
    }
  };
}

/**
 * Handle /delete command - Delete email (admin only)
 */
export async function handleDelete(
  env: Bindings,
  telegramUserId: string,
  identifier: string
): Promise<string> {
  if (!identifier) {
    return `⚠️ Masukkan nama email yang ingin dihapus.

Contoh: <code>/delete tokoku</code>`;
  }

  const userId = await getUserId(env.DB, telegramUserId);
  if (!userId) {
    return `❌ Error: User tidak ditemukan.`;
  }

  const domains = getDomains(env);
  const emailAddress = identifier.includes("@")
    ? identifier.toLowerCase()
    : `${identifier.toLowerCase()}@${domains[0]}`;

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

/**
 * Handle /search command - Search emails
 */
export async function handleSearch(
  env: Bindings,
  telegramUserId: string,
  query: string
): Promise<CommandResponse> {
  const lang = getLang(await getUserLanguage(env.DB, telegramUserId));

  if (!query) {
    return {
      text: `🔍 <b>Cari Email</b>

Format: <code>/search kata_kunci</code>

Contoh:
<code>/search verifikasi</code>
<code>/search google</code>`,
      keyboard: buildBackButton("menu:email", lang)
    };
  }

  const userIsAdmin = isAdmin(telegramUserId, env);
  const userId = await getUserId(env.DB, telegramUserId);
  if (!userId) return { text: `❌ Error: User tidak ditemukan.` };

  const searchPattern = `%${query}%`;

  let result;
  if (userIsAdmin) {
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
    return {
      text: `🔍 Tidak ditemukan hasil untuk "<b>${query}</b>"`,
      keyboard: buildBackButton("menu:email", lang)
    };
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

  keyboard.push([{ text: t(lang, "back_to_menu"), callback_data: "menu:email" }]);

  return { text: response, keyboard: { inline_keyboard: keyboard } };
}

/**
 * Handle /domains command - Show available domains
 */
export function handleDomains(env: Bindings): string {
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
