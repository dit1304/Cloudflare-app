/**
 * Type definitions for the Temp Email Bot
 */

export type Language = "id" | "en";

export interface Bindings {
  DB: D1Database;
  TELEGRAM_BOT_TOKEN: string;
  TEMP_EMAIL_DOMAIN: string;
  ADMIN_USER_ID: string;
  FALLBACK_EMAIL: string;
  WORKER_URL?: string;
}

export interface User {
  id: number;
  telegram_user_id: string;
  telegram_username: string | null;
  auto_delete_days: number;
  language: Language;
  timezone: string;
  is_premium: number;
  created_at: string;
}

export interface Email {
  id: number;
  user_id: number;
  email_address: string;
  local_part: string;
  is_active: number;
  created_at: string;
}

export interface InboxMessage {
  id: number;
  email_id: number;
  sender: string;
  subject: string;
  body: string;
  headers: string;
  is_read: number;
  received_at: string;
}

export interface TOTPSecret {
  id: number;
  user_id: number;
  name: string;
  secret: string;
  created_at: string;
}

export interface BlacklistEntry {
  id: number;
  user_id: number;
  sender_pattern: string;
  created_at: string;
}

export interface CustomDomain {
  id: number;
  user_id: number;
  domain: string;
  status: 'pending' | 'approved' | 'rejected' | 'active' | 'suspended';
  requested_at: string;
  request_note: string | null;
  reviewed_by: number | null;
  reviewed_at: string | null;
  admin_note: string | null;
  verification_code: string | null;
  dns_verified: number;
  verified_at: string | null;
  activated_at: string | null;
}

export interface CommandResponse {
  text: string;
  keyboard?: InlineKeyboard;
}

export interface InlineKeyboard {
  inline_keyboard: InlineKeyboardButton[][];
}

export interface InlineKeyboardButton {
  text: string;
  callback_data: string;
}

export interface UserLimits {
  allowed: boolean;
  current: number;
  max: number;
  isPremium: boolean;
}

export interface PremiumStatus {
  isPremium: boolean;
  userId: number | null;
}

export interface OTPResult {
  code: string;
  remaining: number;
}

export const LIMITS = {
  FREE_MAX_EMAILS: 3,
  FREE_MAX_2FA: 5,
  FREE_MAX_INBOX: 50,
} as const;

export const RATE_LIMITS = {
  COMMANDS_PER_MINUTE: 20,
  COMMANDS_PER_HOUR: 100,
} as const;
