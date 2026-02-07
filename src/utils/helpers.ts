/**
 * Helper utilities
 */

import type { Language, Bindings } from '../types';

/**
 * Get list of available domains
 */
export function getDomains(env: Bindings): string[] {
  return env.TEMP_EMAIL_DOMAIN.split(",")
    .map(d => d.trim())
    .filter(d => d.length > 0);
}

/**
 * Validate email local part
 */
export function validateEmailLocalPart(localPart: string): {
  valid: boolean;
  error?: string;
} {
  if (!localPart || localPart.length < 3) {
    return {
      valid: false,
      error: 'Email name must be at least 3 characters'
    };
  }
  
  if (localPart.length > 30) {
    return {
      valid: false,
      error: 'Email name must be less than 30 characters'
    };
  }
  
  if (!/^[a-z0-9]+$/.test(localPart)) {
    return {
      valid: false,
      error: 'Email name can only contain lowercase letters and numbers'
    };
  }
  
  return { valid: true };
}

/**
 * Sanitize email local part
 */
export function sanitizeLocalPart(input: string): string {
  return input.toLowerCase().replace(/[^a-z0-9]/g, '');
}

/**
 * Format date for display
 */
export function formatDate(dateString: string, locale: Language = 'id'): string {
  try {
    const date = new Date(dateString);
    return date.toLocaleDateString(locale === 'id' ? 'id-ID' : 'en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  } catch {
    return dateString;
  }
}

/**
 * Truncate text with ellipsis
 */
export function truncate(text: string, maxLength: number): string {
  if (text.length <= maxLength) return text;
  return text.substring(0, maxLength) + '...';
}

/**
 * Escape HTML for Telegram
 */
export function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

/**
 * Generate progress bar
 */
export function generateProgressBar(current: number, total: number): string {
  const percentage = Math.round((current / total) * 100);
  const filled = Math.round(percentage / 10);
  const empty = 10 - filled;
  return "▓".repeat(filled) + "░".repeat(empty) + ` ${percentage}%`;
}

/**
 * Sleep utility
 */
export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Retry with exponential backoff
 */
export async function retryWithBackoff<T>(
  fn: () => Promise<T>,
  maxRetries: number = 3,
  baseDelay: number = 1000
): Promise<T> {
  let lastError: Error;
  
  for (let i = 0; i < maxRetries; i++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error as Error;
      
      if (i < maxRetries - 1) {
        const delay = baseDelay * Math.pow(2, i);
        await sleep(delay);
      }
    }
  }
  
  throw lastError!;
}

/**
 * Check if user is admin
 */
export function isAdmin(telegramUserId: string, env: Bindings): boolean {
  return telegramUserId === env.ADMIN_USER_ID;
}

/**
 * Validate environment variables
 */
export function validateEnv(env: Bindings): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  
  if (!env.TELEGRAM_BOT_TOKEN) {
    errors.push('TELEGRAM_BOT_TOKEN is required');
  }
  
  if (!env.TEMP_EMAIL_DOMAIN) {
    errors.push('TEMP_EMAIL_DOMAIN is required');
  }
  
  if (!env.ADMIN_USER_ID) {
    errors.push('ADMIN_USER_ID is required');
  }
  
  if (!env.DB) {
    errors.push('D1 Database binding is required');
  }
  
  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Log with timestamp
 */
export function log(message: string, ...args: any[]): void {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${message}`, ...args);
}

/**
 * Error logger
 */
export function logError(message: string, error: any): void {
  const timestamp = new Date().toISOString();
  console.error(`[${timestamp}] ERROR: ${message}`, {
    error: error?.message || error,
    stack: error?.stack
  });
}
