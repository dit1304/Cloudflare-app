/**
 * Telegram API service
 */

import type { InlineKeyboard } from '../types';
import { logError, retryWithBackoff } from '../utils/helpers';

/**
 * Send message to Telegram
 */
export async function sendTelegramMessage(
  botToken: string,
  chatId: number,
  text: string,
  keyboard?: InlineKeyboard
): Promise<boolean> {
  try {
    const body: any = {
      chat_id: chatId,
      text: text,
      parse_mode: "HTML",
    };

    if (keyboard) {
      body.reply_markup = keyboard;
    }

    const response = await retryWithBackoff(
      () =>
        fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        }),
      3,
      1000
    );

    if (!response.ok) {
      const errorText = await response.text();
      logError('Telegram API error', errorText);
      return false;
    }

    return true;
  } catch (error) {
    logError('sendTelegramMessage error', error);
    return false;
  }
}

/**
 * Edit existing message
 */
export async function editTelegramMessage(
  botToken: string,
  chatId: number,
  messageId: number,
  text: string,
  keyboard?: InlineKeyboard
): Promise<boolean> {
  try {
    const body: any = {
      chat_id: chatId,
      message_id: messageId,
      text: text,
      parse_mode: "HTML",
    };

    if (keyboard) {
      body.reply_markup = keyboard;
    }

    const response = await fetch(
      `https://api.telegram.org/bot${botToken}/editMessageText`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      }
    );

    if (!response.ok) {
      const errorText = await response.text();
      // Don't log "message is not modified" errors
      if (!errorText.includes('message is not modified')) {
        logError('Telegram editMessage error', errorText);
      }
      return false;
    }

    return true;
  } catch (error) {
    logError('editTelegramMessage error', error);
    return false;
  }
}

/**
 * Send photo to Telegram
 */
export async function sendTelegramPhoto(
  botToken: string,
  chatId: number,
  photoUrl: string,
  caption?: string,
  keyboard?: InlineKeyboard
): Promise<boolean> {
  try {
    const body: any = {
      chat_id: chatId,
      photo: photoUrl,
      parse_mode: "HTML",
    };

    if (caption) {
      body.caption = caption;
    }

    if (keyboard) {
      body.reply_markup = keyboard;
    }

    const response = await fetch(
      `https://api.telegram.org/bot${botToken}/sendPhoto`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      }
    );

    if (!response.ok) {
      const errorText = await response.text();
      logError('Telegram sendPhoto error', errorText);
      return false;
    }

    return true;
  } catch (error) {
    logError('sendTelegramPhoto error', error);
    return false;
  }
}

/**
 * Answer callback query
 */
export async function answerCallbackQuery(
  botToken: string,
  callbackQueryId: string,
  text?: string,
  showAlert: boolean = false
): Promise<boolean> {
  try {
    const body: any = {
      callback_query_id: callbackQueryId,
    };

    if (text) {
      body.text = text;
      body.show_alert = showAlert;
    }

    const response = await fetch(
      `https://api.telegram.org/bot${botToken}/answerCallbackQuery`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      }
    );

    if (!response.ok) {
      const errorText = await response.text();
      logError('Telegram answerCallbackQuery error', errorText);
      return false;
    }

    return true;
  } catch (error) {
    logError('answerCallbackQuery error', error);
    return false;
  }
}

/**
 * Set webhook
 */
export async function setWebhook(
  botToken: string,
  webhookUrl: string
): Promise<boolean> {
  try {
    const response = await fetch(
      `https://api.telegram.org/bot${botToken}/setWebhook`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          url: webhookUrl,
          allowed_updates: ["message", "callback_query"],
        }),
      }
    );

    if (!response.ok) {
      const errorText = await response.text();
      logError('Telegram setWebhook error', errorText);
      return false;
    }

    const result = await response.json();
    console.log('Webhook set result:', result);
    return true;
  } catch (error) {
    logError('setWebhook error', error);
    return false;
  }
}

/**
 * Get webhook info
 */
export async function getWebhookInfo(botToken: string): Promise<any> {
  try {
    const response = await fetch(
      `https://api.telegram.org/bot${botToken}/getWebhookInfo`
    );

    if (!response.ok) {
      return null;
    }

    return await response.json();
  } catch (error) {
    logError('getWebhookInfo error', error);
    return null;
  }
}
