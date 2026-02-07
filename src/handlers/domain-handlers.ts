/**
 * Custom Domain Command Handlers
 */

import type { Bindings, CommandResponse, Language } from '../types';
import { getUserId, checkPremiumStatus, getUserLanguage } from '../services/database';
import {
  createDomainRequest,
  getUserDomains,
  getDomainByName,
  getDomainById,
  deleteDomainRequest,
  getDomainStats
} from '../services/custom-domains';
import {
  validateDomainFormat,
  isBotDomain,
  isBlacklistedDomain,
  canRequestDomain,
  generateDNSInstructions,
  getStatusEmoji,
  getStatusText,
  formatDomain
} from '../utils/domain-utils';
import { t, getLang } from '../utils/translations';
import { buildBackButton } from '../utils/keyboards';
import { isAdmin, logError } from '../utils/helpers';

/**
 * Handle /requestdomain command
 */
export async function handleRequestDomain(
  env: Bindings,
  telegramUserId: string,
  arg: string
): Promise<CommandResponse> {
  const lang = getLang(await getUserLanguage(env.DB, telegramUserId));
  const userId = await getUserId(env.DB, telegramUserId);
  
  if (!userId) {
    return {
      text: `❌ Error: User tidak ditemukan.\n\nKetik /start untuk register.`,
      keyboard: buildBackButton("menu:main", lang)
    };
  }

  // Check if premium
  const { isPremium } = await checkPremiumStatus(env.DB, telegramUserId);
  if (!isPremium) {
    return {
      text: `⭐ <b>Custom Domain - Premium Feature</b>

Custom domain hanya tersedia untuk user Premium.

💎 <b>Premium Benefits:</b>
• 1 Custom Domain
• Unlimited Emails
• Unlimited 2FA Secrets
• Priority Support

💬 <b>Upgrade ke Premium:</b>
Contact admin @kakatiri`,
      keyboard: {
        inline_keyboard: [
          [{ text: "💬 Contact Admin", url: "https://t.me/kakatiri" }],
          [{ text: t(lang, "back_to_menu"), callback_data: "menu:main" }]
        ]
      }
    };
  }

  if (!arg) {
    return {
      text: `📧 <b>Request Custom Domain</b>

Format: <code>/requestdomain domain.com [note]</code>

Contoh:
<code>/requestdomain mybusiness.com</code>
<code>/requestdomain myshop.com For my online store</code>

⚠️ <b>Requirements:</b>
• You must own the domain
• Domain must be active
• You'll need to setup DNS records
• Admin will review and approve

💡 <b>Process:</b>
1. Submit request
2. Wait for admin approval (1-24 hours)
3. Setup DNS records
4. Request verification
5. Admin activates domain
6. You can create emails!`,
      keyboard: buildBackButton("menu:account", lang)
    };
  }

  // Parse arguments
  const parts = arg.split(/\s+/);
  const domain = formatDomain(parts[0]);
  const note = parts.slice(1).join(' ') || null;

  // Validate domain format
  const validation = validateDomainFormat(domain);
  if (!validation.valid) {
    return {
      text: `❌ <b>Invalid Domain</b>

${validation.error}

Contoh domain yang valid:
• mybusiness.com
• shop.co.id
• mystore.net`,
      keyboard: buildBackButton("menu:account", lang)
    };
  }

  // Check if bot domain
  if (isBotDomain(domain, env)) {
    return {
      text: `⚠️ <b>Cannot Use Bot Domain</b>

Domain <code>${domain}</code> adalah domain bot.

Gunakan domain Anda sendiri yang berbeda.`,
      keyboard: buildBackButton("menu:account", lang)
    };
  }

  // Check blacklist
  if (isBlacklistedDomain(domain)) {
    return {
      text: `❌ <b>Domain Not Allowed</b>

Domain <code>${domain}</code> tidak diizinkan.

Gunakan domain bisnis profesional.`,
      keyboard: buildBackButton("menu:account", lang)
    };
  }

  // Check user limits
  const limits = await canRequestDomain(env.DB, userId, isPremium);
  if (!limits.allowed) {
    return {
      text: `⚠️ <b>Domain Limit Reached</b>

Kamu sudah memiliki <b>${limits.current}/${limits.max}</b> custom domain.

Premium users: Max 1 domain
Upgrade to Enterprise untuk lebih banyak domain.`,
      keyboard: {
        inline_keyboard: [
          [{ text: "📋 My Domains", callback_data: "action:mydomains" }],
          [{ text: t(lang, "back_to_menu"), callback_data: "menu:main" }]
        ]
      }
    };
  }

  // Create request
  const result = await createDomainRequest(env.DB, userId, domain, note);
  if (!result.success) {
    return {
      text: `❌ <b>Request Failed</b>

${result.error}

Domain <code>${domain}</code> mungkin sudah terdaftar.`,
      keyboard: buildBackButton("menu:account", lang)
    };
  }

  // Notify admin
  try {
    const { sendTelegramMessage } = await import('../services/telegram');
    const username = telegramUserId; // Get from DB if needed
    
    const adminNotification = `📬 <b>New Custom Domain Request</b>

📧 <b>Domain:</b> <code>${domain}</code>
👤 <b>User:</b> @${username} (ID: ${telegramUserId})
⭐ <b>Premium:</b> Yes
📝 <b>Note:</b> ${note || '(No note)'}
📅 <b>Time:</b> ${new Date().toLocaleString('id-ID')}

━━━━━━━━━━━━━━━
Review this request:`;

    await sendTelegramMessage(
      env.TELEGRAM_BOT_TOKEN,
      parseInt(env.ADMIN_USER_ID),
      adminNotification,
      {
        inline_keyboard: [
          [
            { text: "✅ Approve", callback_data: `domain_approve:${result.domainId}` },
            { text: "❌ Reject", callback_data: `domain_reject:${result.domainId}` }
          ],
          [
            { text: "ℹ️ Domain Info", callback_data: `domain_info:${result.domainId}` }
          ]
        ]
      }
    );
  } catch (error) {
    logError('Failed to notify admin', error);
  }

  return {
    text: `✅ <b>Domain Request Submitted!</b>

📧 <b>Domain:</b> <code>${domain}</code>
📝 <b>Note:</b> ${note || '(No note)'}
📅 <b>Submitted:</b> ${new Date().toLocaleString('id-ID')}

⏳ <b>Next Steps:</b>
1. Admin will review your request (1-24 hours)
2. You'll be notified when approved
3. Setup DNS records (instructions will be provided)
4. Request verification
5. Admin activates domain
6. Start using your custom domain!

💬 Questions? Contact @kakatiri

Check status: <code>/mydomains</code>`,
    keyboard: {
      inline_keyboard: [
        [{ text: "📋 My Domains", callback_data: "action:mydomains" }],
        [{ text: t(lang, "back_to_menu"), callback_data: "menu:main" }]
      ]
    }
  };
}

/**
 * Handle /mydomains command
 */
export async function handleMyDomains(
  env: Bindings,
  telegramUserId: string
): Promise<CommandResponse> {
  const lang = getLang(await getUserLanguage(env.DB, telegramUserId));
  const userId = await getUserId(env.DB, telegramUserId);
  
  if (!userId) {
    return {
      text: `❌ Error: User tidak ditemukan.`,
      keyboard: buildBackButton("menu:main", lang)
    };
  }

  const domains = await getUserDomains(env.DB, userId);

  if (domains.length === 0) {
    return {
      text: `📭 <b>Belum Ada Custom Domain</b>

Kamu belum punya custom domain.

⭐ Request custom domain:
<code>/requestdomain yourdomain.com</code>

💡 Note: Custom domain adalah Premium feature.`,
      keyboard: {
        inline_keyboard: [
          [{ text: "➕ Request Domain", callback_data: "action:request_domain_prompt" }],
          [{ text: t(lang, "back_to_menu"), callback_data: "menu:main" }]
        ]
      }
    };
  }

  let response = `📋 <b>Custom Domains Kamu</b>\n\n`;

  const keyboard: any[][] = [];

  for (const domain of domains) {
    const emoji = getStatusEmoji(domain.status);
    const statusText = getStatusText(domain.status, lang);
    
    response += `${emoji} <b>${domain.domain}</b>
   Status: ${statusText}
   Requested: ${domain.requested_at.split('T')[0]}
`;

    if (domain.status === 'approved') {
      response += `   ⚠️ Action needed: Setup DNS\n`;
    } else if (domain.status === 'active') {
      response += `   ✅ Active since: ${domain.activated_at?.split('T')[0]}\n`;
    } else if (domain.status === 'rejected') {
      response += `   📝 Reason: ${domain.admin_note || 'No reason provided'}\n`;
    }
    
    response += `\n`;

    // Add action buttons based on status
    const buttons: any[] = [];
    if (domain.status === 'pending') {
      buttons.push({ text: `❌ Cancel ${domain.domain}`, callback_data: `domain_cancel:${domain.id}` });
    } else if (domain.status === 'approved') {
      buttons.push({ text: `🔧 Setup ${domain.domain}`, callback_data: `domain_setup:${domain.id}` });
      buttons.push({ text: `✅ Verify ${domain.domain}`, callback_data: `domain_verify_req:${domain.id}` });
    } else if (domain.status === 'active') {
      buttons.push({ text: `📊 Stats ${domain.domain}`, callback_data: `domain_stats:${domain.id}` });
    }
    
    if (buttons.length > 0) {
      keyboard.push(buttons);
    }
  }

  response += `━━━━━━━━━━━━━━━
Total: ${domains.length} domain(s)`;

  keyboard.push([{ text: "➕ Request New Domain", callback_data: "action:request_domain_prompt" }]);
  keyboard.push([{ text: t(lang, "back_to_menu"), callback_data: "menu:main" }]);

  return {
    text: response,
    keyboard: { inline_keyboard: keyboard }
  };
}

/**
 * Handle /setupdomain command - Show DNS instructions
 */
export async function handleSetupDomain(
  env: Bindings,
  telegramUserId: string,
  domainName: string
): Promise<CommandResponse> {
  const lang = getLang(await getUserLanguage(env.DB, telegramUserId));
  const userId = await getUserId(env.DB, telegramUserId);
  
  if (!userId) {
    return {
      text: `❌ Error: User tidak ditemukan.`,
      keyboard: buildBackButton("menu:main", lang)
    };
  }

  if (!domainName) {
    return {
      text: `⚠️ Format: <code>/setupdomain yourdomain.com</code>`,
      keyboard: buildBackButton("menu:account", lang)
    };
  }

  const domain = await getDomainByName(env.DB, formatDomain(domainName));

  if (!domain) {
    return {
      text: `❌ Domain <code>${domainName}</code> tidak ditemukan.`,
      keyboard: buildBackButton("menu:account", lang)
    };
  }

  if (domain.user_id !== userId && !isAdmin(telegramUserId, env)) {
    return {
      text: `⚠️ Domain bukan milik Anda.`,
      keyboard: buildBackButton("menu:account", lang)
    };
  }

  if (domain.status !== 'approved' && domain.status !== 'active') {
    return {
      text: `⚠️ Domain belum disetujui admin.

Status: ${getStatusText(domain.status, lang)}

Tunggu approval dari admin atau cek:
<code>/mydomains</code>`,
      keyboard: buildBackButton("menu:account", lang)
    };
  }

  const instructions = generateDNSInstructions(
    domain.domain,
    domain.verification_code || 'loading...',
    lang
  );

  return {
    text: instructions,
    keyboard: {
      inline_keyboard: [
        [{ text: "✅ I've Setup DNS", callback_data: `domain_verify_req:${domain.id}` }],
        [{ text: "💬 Need Help?", url: "https://t.me/kakatiri" }],
        [{ text: t(lang, "back_to_menu"), callback_data: "menu:main" }]
      ]
    }
  };
}

/**
 * Handle /verifydomain command
 */
export async function handleVerifyDomain(
  env: Bindings,
  telegramUserId: string,
  domainName: string
): Promise<CommandResponse> {
  const lang = getLang(await getUserLanguage(env.DB, telegramUserId));
  const userId = await getUserId(env.DB, telegramUserId);
  
  if (!userId) {
    return {
      text: `❌ Error: User tidak ditemukan.`,
      keyboard: buildBackButton("menu:main", lang)
    };
  }

  if (!domainName) {
    return {
      text: `⚠️ Format: <code>/verifydomain yourdomain.com</code>`,
      keyboard: buildBackButton("menu:account", lang)
    };
  }

  const domain = await getDomainByName(env.DB, formatDomain(domainName));

  if (!domain) {
    return {
      text: `❌ Domain <code>${domainName}</code> tidak ditemukan.`,
      keyboard: buildBackButton("menu:account", lang)
    };
  }

  if (domain.user_id !== userId && !isAdmin(telegramUserId, env)) {
    return {
      text: `⚠️ Domain bukan milik Anda.`,
      keyboard: buildBackButton("menu:account", lang)
    };
  }

  if (domain.status !== 'approved') {
    return {
      text: `⚠️ Domain belum dalam status 'approved'.

Current status: ${getStatusText(domain.status, lang)}`,
      keyboard: buildBackButton("menu:account", lang)
    };
  }

  // Send verification request to admin
  try {
    const { sendTelegramMessage } = await import('../services/telegram');
    
    const adminNotification = `🔍 <b>DNS Verification Request</b>

📧 <b>Domain:</b> <code>${domain.domain}</code>
👤 <b>User:</b> @${telegramUserId}
📅 <b>Time:</b> ${new Date().toLocaleString('id-ID')}

User claims DNS is setup and ready for verification.

<b>Verification Code:</b>
<code>${domain.verification_code}</code>

Check DNS and activate if ready.`;

    await sendTelegramMessage(
      env.TELEGRAM_BOT_TOKEN,
      parseInt(env.ADMIN_USER_ID),
      adminNotification,
      {
        inline_keyboard: [
          [
            { text: "🔍 Check DNS", callback_data: `domain_check:${domain.id}` },
            { text: "✅ Activate", callback_data: `domain_activate:${domain.id}` }
          ],
          [
            { text: "💬 Contact User", url: `https://t.me/${telegramUserId}` }
          ]
        ]
      }
    );
  } catch (error) {
    logError('Failed to notify admin', error);
  }

  return {
    text: `✅ <b>Verification Request Sent!</b>

📧 Domain: <code>${domain.domain}</code>

Admin akan mengecek DNS setup Anda.
Anda akan diberitahu saat domain diaktifkan.

⏱️ <b>Processing Time:</b>
Usually 10 minutes - 24 hours

💡 <b>Tips:</b>
• Pastikan DNS sudah propagate (10-30 menit)
• Check DNS status: https://dnschecker.org
• Jika urgent, contact @kakatiri`,
    keyboard: {
      inline_keyboard: [
        [{ text: "📋 My Domains", callback_data: "action:mydomains" }],
        [{ text: "💬 Contact Admin", url: "https://t.me/kakatiri" }],
        [{ text: t(lang, "back_to_menu"), callback_data: "menu:main" }]
      ]
    }
  };
}

/**
 * Handle /canceldomain command
 */
export async function handleCancelDomain(
  env: Bindings,
  telegramUserId: string,
  domainName: string
): Promise<CommandResponse> {
  const lang = getLang(await getUserLanguage(env.DB, telegramUserId));
  const userId = await getUserId(env.DB, telegramUserId);
  
  if (!userId) {
    return {
      text: `❌ Error: User tidak ditemukan.`,
      keyboard: buildBackButton("menu:main", lang)
    };
  }

  if (!domainName) {
    return {
      text: `⚠️ Format: <code>/canceldomain yourdomain.com</code>`,
      keyboard: buildBackButton("menu:account", lang)
    };
  }

  const domain = await getDomainByName(env.DB, formatDomain(domainName));

  if (!domain) {
    return {
      text: `❌ Domain <code>${domainName}</code> tidak ditemukan.`,
      keyboard: buildBackButton("menu:account", lang)
    };
  }

  if (domain.user_id !== userId) {
    return {
      text: `⚠️ Domain bukan milik Anda.`,
      keyboard: buildBackButton("menu:account", lang)
    };
  }

  if (domain.status !== 'pending') {
    return {
      text: `⚠️ Hanya request 'pending' yang bisa dibatalkan.

Current status: ${getStatusText(domain.status, lang)}`,
      keyboard: buildBackButton("menu:account", lang)
    };
  }

  await deleteDomainRequest(env.DB, domain.id);

  return {
    text: `✅ <b>Request Dibatalkan</b>

Domain <code>${domain.domain}</code> telah dibatalkan.

Kamu bisa request lagi kapan saja:
<code>/requestdomain ${domain.domain}</code>`,
    keyboard: {
      inline_keyboard: [
        [{ text: "📋 My Domains", callback_data: "action:mydomains" }],
        [{ text: t(lang, "back_to_menu"), callback_data: "menu:main" }]
      ]
    }
  };
}

/**
 * Handle domain stats view
 */
export async function handleDomainStats(
  env: Bindings,
  telegramUserId: string,
  domainId: number
): Promise<CommandResponse> {
  const lang = getLang(await getUserLanguage(env.DB, telegramUserId));
  const userId = await getUserId(env.DB, telegramUserId);
  
  if (!userId) {
    return {
      text: `❌ Error: User tidak ditemukan.`,
      keyboard: buildBackButton("menu:main", lang)
    };
  }

  const domain = await getDomainById(env.DB, domainId);
  if (!domain) {
    return {
      text: `❌ Domain tidak ditemukan.`,
      keyboard: buildBackButton("menu:account", lang)
    };
  }

  if (domain.user_id !== userId && !isAdmin(telegramUserId, env)) {
    return {
      text: `⚠️ Domain bukan milik Anda.`,
      keyboard: buildBackButton("menu:account", lang)
    };
  }

  const stats = await getDomainStats(env.DB, domainId);

  if (!stats) {
    return {
      text: `❌ Gagal mengambil statistik domain.`,
      keyboard: buildBackButton("menu:account", lang)
    };
  }

  let response = `📊 <b>Domain Statistics</b>

📧 <b>Domain:</b> <code>${domain.domain}</code>
${getStatusEmoji(domain.status)} <b>Status:</b> ${getStatusText(domain.status, lang)}

━━━ 📈 <b>STATISTICS</b> ━━━
📬 Email Addresses: <b>${stats.emailCount}</b>
📨 Total Messages: <b>${stats.messageCount}</b>
📩 Unread: <b>${stats.unreadCount}</b>

📅 <b>Created:</b> ${domain.requested_at.split('T')[0]}
${domain.activated_at ? `✅ <b>Activated:</b> ${domain.activated_at.split('T')[0]}` : ''}
`;

  if (stats.emails.length > 0) {
    response += `\n━━━ 📧 <b>EMAIL ADDRESSES</b> ━━━\n`;
    for (const email of stats.emails) {
      response += `• <code>${email.email_address}</code> (${email.message_count} msgs)\n`;
    }
  }

  return {
    text: response,
    keyboard: {
      inline_keyboard: [
        [{ text: "📋 My Domains", callback_data: "action:mydomains" }],
        [{ text: t(lang, "back_to_menu"), callback_data: "menu:main" }]
      ]
    }
  };
}
