/**
 * Domain utilities for custom domain feature
 */

import type { Bindings } from '../types';
import { logError } from './helpers';

/**
 * Validate domain format
 */
export function validateDomainFormat(domain: string): { valid: boolean; error?: string } {
  // Convert to lowercase and trim
  domain = domain.toLowerCase().trim();
  
  // Check length
  if (domain.length < 4 || domain.length > 253) {
    return { valid: false, error: 'Domain must be between 4-253 characters' };
  }
  
  // Basic format validation
  const domainRegex = /^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,}$/;
  if (!domainRegex.test(domain)) {
    return { valid: false, error: 'Invalid domain format. Example: mybusiness.com' };
  }
  
  // Check for consecutive dots or hyphens
  if (/\.\./.test(domain) || /--/.test(domain)) {
    return { valid: false, error: 'Domain cannot have consecutive dots or hyphens' };
  }
  
  // Check if starts or ends with hyphen
  if (domain.startsWith('-') || domain.endsWith('-')) {
    return { valid: false, error: 'Domain cannot start or end with hyphen' };
  }
  
  return { valid: true };
}

/**
 * Check if domain is a bot domain or subdomain
 */
export function isBotDomain(domain: string, env: Bindings): boolean {
  const botDomains = env.TEMP_EMAIL_DOMAIN.split(',').map(d => d.trim().toLowerCase());
  const domainLower = domain.toLowerCase();
  
  // Check exact match or subdomain
  return botDomains.some(bd => 
    domainLower === bd || domainLower.endsWith('.' + bd)
  );
}

/**
 * Check if domain is in blacklist (common disposable/spam domains)
 */
export function isBlacklistedDomain(domain: string): boolean {
  const blacklist = [
    'tempmail.com',
    'guerrillamail.com',
    'mailinator.com',
    '10minutemail.com',
    'throwaway.email',
    'maildrop.cc',
    'temp-mail.org',
    // Add more as needed
  ];
  
  const domainLower = domain.toLowerCase();
  return blacklist.some(bd => 
    domainLower === bd || domainLower.endsWith('.' + bd)
  );
}

/**
 * Generate verification code for DNS TXT record
 */
export function generateVerificationCode(): string {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let code = 'tempbot-verify-';
  
  for (let i = 0; i < 16; i++) {
    code += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  
  return code;
}

/**
 * Format domain for display
 */
export function formatDomain(domain: string): string {
  return domain.toLowerCase().trim();
}

/**
 * Get domain status emoji
 */
export function getStatusEmoji(status: string): string {
  switch (status) {
    case 'pending': return '⏳';
    case 'approved': return '✅';
    case 'rejected': return '❌';
    case 'active': return '🟢';
    case 'suspended': return '⛔';
    default: return '❓';
  }
}

/**
 * Get domain status text
 */
export function getStatusText(status: string, lang: 'id' | 'en' = 'id'): string {
  const translations = {
    id: {
      pending: 'Menunggu Persetujuan',
      approved: 'Disetujui - Setup DNS',
      rejected: 'Ditolak',
      active: 'Aktif',
      suspended: 'Ditangguhkan'
    },
    en: {
      pending: 'Pending Approval',
      approved: 'Approved - Setup DNS',
      rejected: 'Rejected',
      active: 'Active',
      suspended: 'Suspended'
    }
  };
  
  return translations[lang][status as keyof typeof translations.id] || status;
}

/**
 * Check if user can request more domains (based on limits)
 */
export async function canRequestDomain(
  db: D1Database,
  userId: number,
  isPremium: boolean
): Promise<{ allowed: boolean; current: number; max: number }> {
  const result = await db
    .prepare('SELECT COUNT(*) as count FROM custom_domains WHERE user_id = ? AND status IN (?, ?, ?)')
    .bind(userId, 'pending', 'approved', 'active')
    .first<{ count: number }>();
  
  const current = result?.count || 0;
  
  // Free users: 0 custom domains
  // Premium users: 1 custom domain
  // Can be adjusted based on pricing tier
  const max = isPremium ? 1 : 0;
  
  return {
    allowed: current < max,
    current,
    max
  };
}

/**
 * Generate DNS setup instructions
 */
export function generateDNSInstructions(domain: string, verificationCode: string, lang: 'id' | 'en' = 'id'): string {
  if (lang === 'id') {
    return `🔧 <b>Panduan Setup DNS untuk: ${domain}</b>

Tambahkan record berikut di DNS domain Anda (GoDaddy, Namecheap, Cloudflare, dll):

<b>1️⃣ MX Record (Mail Exchange)</b>
━━━━━━━━━━━━━━━
Type: <code>MX</code>
Name: <code>@</code> atau kosongkan
Value: <code>route.cloudflare.net</code>
Priority: <code>10</code>
TTL: <code>Auto</code> atau <code>3600</code>

<b>2️⃣ TXT Record (Verifikasi)</b>
━━━━━━━━━━━━━━━
Type: <code>TXT</code>
Name: <code>_emailverify</code>
Value: <code>${verificationCode}</code>
TTL: <code>Auto</code> atau <code>3600</code>

⏱️ <b>Catatan Penting:</b>
• Perubahan DNS bisa memakan waktu 10-30 menit (kadang sampai 24 jam)
• Pastikan semua record sudah benar sebelum verifikasi
• Jika ragu, screenshot dan kirim ke admin: @kakatiri

Setelah setup selesai dan menunggu propagasi DNS, ketik:
<code>/verifydomain ${domain}</code>`;
  } else {
    return `🔧 <b>DNS Setup Instructions for: ${domain}</b>

Add these records to your domain DNS (GoDaddy, Namecheap, Cloudflare, etc):

<b>1️⃣ MX Record (Mail Exchange)</b>
━━━━━━━━━━━━━━━
Type: <code>MX</code>
Name: <code>@</code> or leave empty
Value: <code>route.cloudflare.net</code>
Priority: <code>10</code>
TTL: <code>Auto</code> or <code>3600</code>

<b>2️⃣ TXT Record (Verification)</b>
━━━━━━━━━━━━━━━
Type: <code>TXT</code>
Name: <code>_emailverify</code>
Value: <code>${verificationCode}</code>
TTL: <code>Auto</code> or <code>3600</code>

⏱️ <b>Important Notes:</b>
• DNS changes can take 10-30 minutes (sometimes up to 24 hours)
• Make sure all records are correct before verification
• If unsure, screenshot and send to admin: @kakatiri

After setup and waiting for DNS propagation, type:
<code>/verifydomain ${domain}</code>`;
  }
}
