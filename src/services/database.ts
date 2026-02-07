/**
 * Database service layer
 */

import type {
  User,
  Email,
  InboxMessage,
  TOTPSecret,
  Language,
  UserLimits,
  PremiumStatus,
  Bindings
} from '../types';
import { LIMITS } from '../types';
import { logError } from '../utils/helpers';

/**
 * Ensure user exists in database
 */
export async function ensureUser(
  db: D1Database,
  telegramUserId: string,
  username?: string,
  env?: Bindings
): Promise<{ isNew: boolean }> {
  try {
    const existing = await db
      .prepare("SELECT id FROM users WHERE telegram_user_id = ?")
      .bind(telegramUserId)
      .first();

    if (!existing) {
      await db
        .prepare("INSERT INTO users (telegram_user_id, telegram_username) VALUES (?, ?)")
        .bind(telegramUserId, username || null)
        .run();

      // Notify admin of new user
      if (env && env.ADMIN_USER_ID && telegramUserId !== env.ADMIN_USER_ID) {
        const { sendTelegramMessage } = await import('./telegram');
        const usernameDisplay = username ? `@${username}` : "(no username)";
        const alertText = `🆕 <b>User Baru Bergabung!</b>

👤 ${usernameDisplay}
🆔 ID: <code>${telegramUserId}</code>
📅 Waktu: ${new Date().toLocaleString('id-ID', { timeZone: 'Asia/Jakarta' })}`;

        try {
          await sendTelegramMessage(
            env.TELEGRAM_BOT_TOKEN,
            parseInt(env.ADMIN_USER_ID),
            alertText
          );
        } catch (error) {
          logError('Failed to send new user alert', error);
        }
      }

      return { isNew: true };
    }

    // Update username if changed
    if (username) {
      await db
        .prepare("UPDATE users SET telegram_username = ? WHERE telegram_user_id = ?")
        .bind(username, telegramUserId)
        .run();
    }

    return { isNew: false };
  } catch (error) {
    logError('ensureUser error', error);
    throw error;
  }
}

/**
 * Get user ID from telegram user ID
 */
export async function getUserId(
  db: D1Database,
  telegramUserId: string
): Promise<number | null> {
  try {
    const user = await db
      .prepare("SELECT id FROM users WHERE telegram_user_id = ?")
      .bind(telegramUserId)
      .first<{ id: number }>();
    return user?.id || null;
  } catch (error) {
    logError('getUserId error', error);
    return null;
  }
}

/**
 * Get user language preference
 */
export async function getUserLanguage(
  db: D1Database,
  telegramUserId: string
): Promise<Language | null> {
  try {
    const user = await db
      .prepare("SELECT language FROM users WHERE telegram_user_id = ?")
      .bind(telegramUserId)
      .first<{ language: string | null }>();
    return (user?.language as Language) || null;
  } catch (error) {
    logError('getUserLanguage error', error);
    return null;
  }
}

/**
 * Set user language preference
 */
export async function setUserLanguage(
  db: D1Database,
  telegramUserId: string,
  lang: Language
): Promise<void> {
  try {
    await db
      .prepare("UPDATE users SET language = ? WHERE telegram_user_id = ?")
      .bind(lang, telegramUserId)
      .run();
  } catch (error) {
    logError('setUserLanguage error', error);
    throw error;
  }
}

/**
 * Check if user is premium
 */
export async function checkPremiumStatus(
  db: D1Database,
  telegramUserId: string
): Promise<PremiumStatus> {
  try {
    const user = await db
      .prepare("SELECT id, is_premium FROM users WHERE telegram_user_id = ?")
      .bind(telegramUserId)
      .first<{ id: number; is_premium: number }>();
    return {
      isPremium: user?.is_premium === 1,
      userId: user?.id || null
    };
  } catch (error) {
    logError('checkPremiumStatus error', error);
    return { isPremium: false, userId: null };
  }
}

/**
 * Check user limits (email, 2FA, inbox)
 */
export async function checkUserLimits(
  db: D1Database,
  telegramUserId: string,
  type: 'email' | '2fa' | 'inbox'
): Promise<UserLimits> {
  try {
    const { isPremium, userId } = await checkPremiumStatus(db, telegramUserId);

    if (isPremium || !userId) {
      return { allowed: true, current: 0, max: -1, isPremium };
    }

    let current = 0;
    let max = 0;

    switch (type) {
      case 'email': {
        const result = await db
          .prepare("SELECT COUNT(*) as count FROM emails WHERE user_id = ?")
          .bind(userId)
          .first<{ count: number }>();
        current = result?.count || 0;
        max = LIMITS.FREE_MAX_EMAILS;
        break;
      }
      case '2fa': {
        const result = await db
          .prepare("SELECT COUNT(*) as count FROM totp_secrets WHERE user_id = ?")
          .bind(userId)
          .first<{ count: number }>();
        current = result?.count || 0;
        max = LIMITS.FREE_MAX_2FA;
        break;
      }
      case 'inbox': {
        const result = await db
          .prepare(
            "SELECT COUNT(*) as count FROM inbox i JOIN emails e ON i.email_id = e.id WHERE e.user_id = ?"
          )
          .bind(userId)
          .first<{ count: number }>();
        current = result?.count || 0;
        max = LIMITS.FREE_MAX_INBOX;
        break;
      }
    }

    return { allowed: current < max, current, max, isPremium };
  } catch (error) {
    logError('checkUserLimits error', error);
    return { allowed: false, current: 0, max: 0, isPremium: false };
  }
}

/**
 * Get or create admin user
 */
export async function getOrCreateAdminUser(
  db: D1Database,
  adminTelegramId: string
): Promise<number> {
  try {
    const existing = await db
      .prepare("SELECT id FROM users WHERE telegram_user_id = ?")
      .bind(adminTelegramId)
      .first<{ id: number }>();

    if (existing) {
      return existing.id;
    }

    const result = await db
      .prepare(
        "INSERT INTO users (telegram_user_id, telegram_username, is_premium) VALUES (?, ?, 1) RETURNING id"
      )
      .bind(adminTelegramId, "admin")
      .first<{ id: number }>();

    return result?.id || 0;
  } catch (error) {
    logError('getOrCreateAdminUser error', error);
    return 0;
  }
}

/**
 * Create email address
 */
export async function createEmail(
  db: D1Database,
  userId: number,
  emailAddress: string,
  localPart: string
): Promise<{ success: boolean; emailId?: number; error?: string }> {
  try {
    // Check if email already exists
    const existing = await db
      .prepare("SELECT id FROM emails WHERE email_address = ?")
      .bind(emailAddress)
      .first();

    if (existing) {
      return { success: false, error: 'Email already exists' };
    }

    const result = await db
      .prepare(
        "INSERT INTO emails (user_id, email_address, local_part) VALUES (?, ?, ?) RETURNING id"
      )
      .bind(userId, emailAddress, localPart)
      .first<{ id: number }>();

    return { success: true, emailId: result?.id };
  } catch (error) {
    logError('createEmail error', error);
    return { success: false, error: 'Database error' };
  }
}

/**
 * Get user's emails
 */
export async function getUserEmails(
  db: D1Database,
  userId: number
): Promise<Email[]> {
  try {
    const result = await db
      .prepare(
        "SELECT * FROM emails WHERE user_id = ? AND is_active = 1 ORDER BY created_at DESC"
      )
      .bind(userId)
      .all();

    return (result.results as Email[]) || [];
  } catch (error) {
    logError('getUserEmails error', error);
    return [];
  }
}

/**
 * Save inbox message
 */
export async function saveInboxMessage(
  db: D1Database,
  emailId: number,
  sender: string,
  subject: string,
  body: string,
  headers: string
): Promise<number | null> {
  try {
    const result = await db
      .prepare(
        "INSERT INTO inbox (email_id, sender, subject, body, headers) VALUES (?, ?, ?, ?, ?) RETURNING id"
      )
      .bind(emailId, sender, subject, body, headers)
      .first<{ id: number }>();

    return result?.id || null;
  } catch (error) {
    logError('saveInboxMessage error', error);
    return null;
  }
}

/**
 * Mark message as read
 */
export async function markAsRead(
  db: D1Database,
  messageId: number
): Promise<void> {
  try {
    await db
      .prepare("UPDATE inbox SET is_read = 1 WHERE id = ?")
      .bind(messageId)
      .run();
  } catch (error) {
    logError('markAsRead error', error);
  }
}

/**
 * Check if sender is blacklisted
 */
export async function isBlacklisted(
  db: D1Database,
  sender: string
): Promise<boolean> {
  try {
    const senderLower = sender.toLowerCase();
    const result = await db
      .prepare("SELECT id FROM blacklist WHERE ? LIKE '%' || sender_pattern || '%'")
      .bind(senderLower)
      .first();

    return !!result;
  } catch (error) {
    logError('isBlacklisted error', error);
    return false;
  }
}
