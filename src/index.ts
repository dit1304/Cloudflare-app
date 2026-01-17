import { Hono } from "hono";
import OpenAI from "openai";

type Bindings = {
  DB: D1Database;
  TELEGRAM_BOT_TOKEN: string;
  OPENAI_API_KEY: string;
  TEMP_EMAIL_DOMAIN: string;
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
  const userMessage = payload.message.text;

  try {
    const response = await processWithAgent(c.env, telegramUserId, telegramUsername, userMessage);
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

// ============ EMAIL INCOMING WEBHOOK ============
app.post("/webhooks/email", async (c) => {
  console.log("📧 Email webhook received");
  return c.text("OK", 200);
});

// ============ EMAIL HANDLER (from Cloudflare Email Routing) ============
async function handleEmail(message: ForwardableEmailMessage, env: Bindings) {
  console.log(`📧 Email received: ${message.from} -> ${message.to}`);

  const toAddress = message.to.toLowerCase();
  const subject = message.headers.get("subject") || "(Tanpa subjek)";

  const email = await env.DB.prepare(
    "SELECT e.id, e.user_id, u.telegram_user_id FROM emails e JOIN users u ON e.user_id = u.id WHERE LOWER(e.email_address) = ?"
  )
    .bind(toAddress)
    .first<{ id: number; user_id: number; telegram_user_id: string }>();

  if (!email) {
    console.log("Email address not found:", toAddress);
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
👤 <b>Dari:</b> ${message.from}
📋 <b>Subjek:</b> ${subject}

Ketik "cek inbox ${toAddress.split("@")[0]}" untuk membaca.`;

  const botToken = env.TELEGRAM_BOT_TOKEN;
  if (botToken) {
    await sendTelegramMessage(botToken, parseInt(email.telegram_user_id), notificationText);
  }
}

// ============ AI AGENT ============
async function processWithAgent(
  env: Bindings,
  telegramUserId: string,
  telegramUsername: string,
  userMessage: string
): Promise<string> {
  console.log("🤖 Processing with agent:", { telegramUserId, userMessage });

  await ensureUser(env.DB, telegramUserId, telegramUsername);

  const openai = new OpenAI({ apiKey: env.OPENAI_API_KEY });

  const tools: OpenAI.Chat.Completions.ChatCompletionTool[] = [
    {
      type: "function",
      function: {
        name: "createEmail",
        description: "Membuat alamat email temporary baru untuk user",
        parameters: {
          type: "object",
          properties: {
            customName: {
              type: "string",
              description: "Nama custom untuk email (opsional). Jika tidak ada, akan generate random.",
            },
          },
        },
      },
    },
    {
      type: "function",
      function: {
        name: "listEmails",
        description: "Menampilkan semua alamat email yang dimiliki user",
        parameters: { type: "object", properties: {} },
      },
    },
    {
      type: "function",
      function: {
        name: "checkInbox",
        description: "Melihat pesan masuk di email tertentu",
        parameters: {
          type: "object",
          properties: {
            emailIdentifier: {
              type: "string",
              description: "Alamat email lengkap atau local part saja",
            },
          },
          required: ["emailIdentifier"],
        },
      },
    },
    {
      type: "function",
      function: {
        name: "getEmailDetail",
        description: "Membaca isi lengkap sebuah email",
        parameters: {
          type: "object",
          properties: {
            messageId: {
              type: "number",
              description: "ID pesan email yang ingin dibaca",
            },
          },
          required: ["messageId"],
        },
      },
    },
    {
      type: "function",
      function: {
        name: "deleteEmail",
        description: "Menghapus alamat email beserta semua pesannya",
        parameters: {
          type: "object",
          properties: {
            emailIdentifier: {
              type: "string",
              description: "Alamat email lengkap atau local part yang ingin dihapus",
            },
          },
          required: ["emailIdentifier"],
        },
      },
    },
  ];

  const systemPrompt = `Kamu adalah bot Telegram untuk layanan Temporary Email dalam Bahasa Indonesia.

KEMAMPUAN:
- Buat email temporary baru (createEmail)
- Lihat daftar email (listEmails)
- Cek inbox email (checkInbox)
- Baca detail email (getEmailDetail)
- Hapus email (deleteEmail)

ATURAN:
- Selalu gunakan Bahasa Indonesia
- Gunakan emoji untuk mempercantik respons
- Format respons agar mudah dibaca
- Jika user minta buat email, langsung panggil createEmail
- Domain email: ${env.TEMP_EMAIL_DOMAIN}

Konteks user:
- Telegram User ID: ${telegramUserId}
- Username: ${telegramUsername || "tidak tersedia"}`;

  const messages: OpenAI.Chat.Completions.ChatCompletionMessageParam[] = [
    { role: "system", content: systemPrompt },
    { role: "user", content: userMessage },
  ];

  let response = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    messages,
    tools,
    tool_choice: "auto",
  });

  let maxSteps = 5;
  while (response.choices[0].message.tool_calls && maxSteps > 0) {
    const toolCalls = response.choices[0].message.tool_calls;
    messages.push(response.choices[0].message);

    for (const toolCall of toolCalls) {
      const result = await executeTool(
        env,
        telegramUserId,
        toolCall.function.name,
        JSON.parse(toolCall.function.arguments || "{}")
      );
      messages.push({
        role: "tool",
        tool_call_id: toolCall.id,
        content: JSON.stringify(result),
      });
    }

    response = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages,
      tools,
      tool_choice: "auto",
    });
    maxSteps--;
  }

  return response.choices[0].message.content || "Maaf, saya tidak bisa memproses permintaan ini.";
}

// ============ TOOL EXECUTOR ============
async function executeTool(
  env: Bindings,
  telegramUserId: string,
  toolName: string,
  args: Record<string, any>
): Promise<any> {
  console.log(`🔧 Executing tool: ${toolName}`, args);

  switch (toolName) {
    case "createEmail":
      return await createEmail(env, telegramUserId, args.customName);
    case "listEmails":
      return await listEmails(env, telegramUserId);
    case "checkInbox":
      return await checkInbox(env, telegramUserId, args.emailIdentifier);
    case "getEmailDetail":
      return await getEmailDetail(env, telegramUserId, args.messageId);
    case "deleteEmail":
      return await deleteEmail(env, telegramUserId, args.emailIdentifier);
    default:
      return { error: "Tool tidak dikenal" };
  }
}

// ============ TOOLS IMPLEMENTATION ============
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

function generateRandomString(length: number): string {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  let result = "";
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

async function createEmail(env: Bindings, telegramUserId: string, customName?: string) {
  const userId = await getUserId(env.DB, telegramUserId);
  if (!userId) return { success: false, message: "User tidak ditemukan" };

  const localPart = customName?.toLowerCase().replace(/[^a-z0-9]/g, "") || generateRandomString(10);
  const emailAddress = `${localPart}@${env.TEMP_EMAIL_DOMAIN}`;

  const existing = await env.DB.prepare("SELECT id FROM emails WHERE email_address = ?")
    .bind(emailAddress)
    .first();

  if (existing) {
    return { success: false, message: "Alamat email sudah digunakan. Coba nama lain." };
  }

  await env.DB.prepare("INSERT INTO emails (user_id, email_address, local_part) VALUES (?, ?, ?)")
    .bind(userId, emailAddress, localPart)
    .run();

  return {
    success: true,
    emailAddress,
    message: `Email ${emailAddress} berhasil dibuat!`,
  };
}

async function listEmails(env: Bindings, telegramUserId: string) {
  const userId = await getUserId(env.DB, telegramUserId);
  if (!userId) return { success: false, emails: [], message: "User tidak ditemukan" };

  const result = await env.DB.prepare(
    `SELECT e.email_address, e.created_at, 
     (SELECT COUNT(*) FROM inbox i WHERE i.email_id = e.id) as message_count,
     (SELECT COUNT(*) FROM inbox i WHERE i.email_id = e.id AND i.is_read = 0) as unread_count
     FROM emails e WHERE e.user_id = ? AND e.is_active = 1 ORDER BY e.created_at DESC`
  )
    .bind(userId)
    .all();

  return {
    success: true,
    emails: result.results,
    count: result.results.length,
  };
}

async function checkInbox(env: Bindings, telegramUserId: string, emailIdentifier: string) {
  const userId = await getUserId(env.DB, telegramUserId);
  if (!userId) return { success: false, messages: [], message: "User tidak ditemukan" };

  const emailAddress = emailIdentifier.includes("@")
    ? emailIdentifier.toLowerCase()
    : `${emailIdentifier.toLowerCase()}@${env.TEMP_EMAIL_DOMAIN}`;

  const email = await env.DB.prepare(
    "SELECT id FROM emails WHERE user_id = ? AND LOWER(email_address) = ? AND is_active = 1"
  )
    .bind(userId, emailAddress)
    .first<{ id: number }>();

  if (!email) {
    return { success: false, messages: [], message: "Email tidak ditemukan atau bukan milik kamu" };
  }

  const result = await env.DB.prepare(
    `SELECT id, sender, subject, is_read, received_at FROM inbox 
     WHERE email_id = ? ORDER BY received_at DESC LIMIT 20`
  )
    .bind(email.id)
    .all();

  return {
    success: true,
    emailAddress,
    messages: result.results,
    count: result.results.length,
  };
}

async function getEmailDetail(env: Bindings, telegramUserId: string, messageId: number) {
  const userId = await getUserId(env.DB, telegramUserId);
  if (!userId) return { success: false, message: "User tidak ditemukan" };

  const msg = await env.DB.prepare(
    `SELECT i.*, e.email_address FROM inbox i 
     JOIN emails e ON i.email_id = e.id 
     WHERE i.id = ? AND e.user_id = ?`
  )
    .bind(messageId, userId)
    .first();

  if (!msg) {
    return { success: false, message: "Pesan tidak ditemukan atau bukan milik kamu" };
  }

  await env.DB.prepare("UPDATE inbox SET is_read = 1 WHERE id = ?").bind(messageId).run();

  return { success: true, email: msg };
}

async function deleteEmail(env: Bindings, telegramUserId: string, emailIdentifier: string) {
  const userId = await getUserId(env.DB, telegramUserId);
  if (!userId) return { success: false, message: "User tidak ditemukan" };

  const emailAddress = emailIdentifier.includes("@")
    ? emailIdentifier.toLowerCase()
    : `${emailIdentifier.toLowerCase()}@${env.TEMP_EMAIL_DOMAIN}`;

  const email = await env.DB.prepare(
    "SELECT id FROM emails WHERE user_id = ? AND LOWER(email_address) = ?"
  )
    .bind(userId, emailAddress)
    .first<{ id: number }>();

  if (!email) {
    return { success: false, message: "Email tidak ditemukan atau bukan milik kamu" };
  }

  await env.DB.prepare("DELETE FROM inbox WHERE email_id = ?").bind(email.id).run();
  await env.DB.prepare("DELETE FROM emails WHERE id = ?").bind(email.id).run();

  return { success: true, message: `Email ${emailAddress} berhasil dihapus` };
}

// ============ HELPERS ============
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
  const parts = rawEmail.split("\r\n\r\n");
  return parts.length > 1 ? parts.slice(1).join("\r\n\r\n") : rawEmail;
}

// ============ EXPORTS ============
export default {
  fetch: app.fetch,
  email: handleEmail,
};
