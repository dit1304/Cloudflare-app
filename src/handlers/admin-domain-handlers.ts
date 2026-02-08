/**
 * Admin Custom Domain Handlers
 */

import type { Bindings, CommandResponse } from '../types';
import { getUserId, getUserLanguage } from '../services/database';
import {
  getPendingDomains,
  getAllDomains,
  getDomainById,
  getDomainByName,
  approveDomain,
  rejectDomain,
  activateDomain,
  suspendDomain
} from '../services/custom-domains';
import { getStatusEmoji, getStatusText } from '../utils/domain-utils';
import { getLang } from '../utils/translations';
import { buildBackButton } from '../utils/keyboards';
import { logError } from '../utils/helpers';
import { sendTelegramMessage } from '../services/telegram';

/**
 * Handle /domainrequests - View pending domain requests
 */
export async function handleDomainRequests(
  env: Bindings,
  telegramUserId: string
): Promise<CommandResponse> {
  const lang = getLang(await getUserLanguage(env.DB, telegramUserId));
  
  const pending = await getPendingDomains(env.DB);

  if (pending.length === 0) {
    return {
      text: `📭 <b>No Pending Domain Requests</b>

All domain requests have been reviewed.

View all domains: <code>/listdomains all</code>`,
      keyboard: buildBackButton("menu:admin", lang)
    };
  }

  let response = `📬 <b>Pending Domain Requests</b>\n\n`;

  const keyboard: any[][] = [];

  for (let i = 0; i < pending.length; i++) {
    const req = pending[i];
    const num = i + 1;
    const premiumBadge = req.is_premium ? ' ⭐' : '';
    const username = req.telegram_username ? `@${req.telegram_username}` : `ID: ${req.telegram_user_id}`;
    
    response += `${num}️⃣ <b>${req.domain}</b>
   👤 ${username}${premiumBadge}
   📅 ${req.requested_at.split('T')[0]}
   📝 ${req.request_note || '(No note)'}

`;

    // Add buttons for this request
    keyboard.push([
      { text: `✅ Approve #${num}`, callback_data: `domain_approve:${req.id}` },
      { text: `❌ Reject #${num}`, callback_data: `domain_reject:${req.id}` }
    ]);
  }

  response += `━━━━━━━━━━━━━━━
Total: ${pending.length} pending request(s)`;

  keyboard.push([{ text: "🔙 Admin Menu", callback_data: "menu:admin" }]);

  return {
    text: response,
    keyboard: { inline_keyboard: keyboard }
  };
}

/**
 * Handle /approvedomain - Approve domain request
 */
export async function handleApproveDomain(
  env: Bindings,
  telegramUserId: string,
  arg: string
): Promise<CommandResponse> {
  const lang = getLang(await getUserLanguage(env.DB, telegramUserId));
  const adminUserId = await getUserId(env.DB, telegramUserId);
  
  if (!adminUserId) {
    return {
      text: `❌ Error: Admin not found.`,
      keyboard: buildBackButton("menu:admin", lang)
    };
  }

  if (!arg) {
    return {
      text: `⚠️ Format: <code>/approvedomain domain.com [note]</code>

Example:
<code>/approvedomain mybusiness.com Approved for business use</code>`,
      keyboard: buildBackButton("menu:admin", lang)
    };
  }

  const parts = arg.split(/\s+/);
  const domainName = parts[0].toLowerCase();
  const note = parts.slice(1).join(' ') || 'Approved by admin';

  const domain = await getDomainByName(env.DB, domainName);

  if (!domain) {
    return {
      text: `❌ Domain <code>${domainName}</code> tidak ditemukan.`,
      keyboard: buildBackButton("menu:admin", lang)
    };
  }

  if (domain.status !== 'pending') {
    return {
      text: `⚠️ Domain status bukan 'pending'.

Current status: ${getStatusText(domain.status, lang)}`,
      keyboard: buildBackButton("menu:admin", lang)
    };
  }

  const success = await approveDomain(env.DB, domain.id, adminUserId, note);

  if (!success) {
    return {
      text: `❌ Gagal approve domain.`,
      keyboard: buildBackButton("menu:admin", lang)
    };
  }

  // Notify user
  try {
    const userResult = await env.DB.prepare(
      'SELECT telegram_user_id FROM users WHERE id = ?'
    ).bind(domain.user_id).first<{ telegram_user_id: string }>();

    if (userResult) {
      const userNotification = `🎉 <b>Domain Request APPROVED!</b>

📧 <b>Domain:</b> <code>${domain.domain}</code>
✅ <b>Approved by:</b> @kakatiri
📝 <b>Note:</b> ${note}

━━━━━━━━━━━━━━━
<b>Next Steps:</b>

1️⃣ Setup DNS records:
   <code>/setupdomain ${domain.domain}</code>

2️⃣ Wait 10-30 minutes for DNS propagation

3️⃣ Request verification:
   <code>/verifydomain ${domain.domain}</code>

4️⃣ Wait for admin to activate

5️⃣ Create emails using your domain!

💬 Need help? Contact @kakatiri`;

      await sendTelegramMessage(
        env.TELEGRAM_BOT_TOKEN,
        parseInt(userResult.telegram_user_id),
        userNotification,
        {
          inline_keyboard: [
            [{ text: "🔧 Setup DNS", callback_data: `domain_setup:${domain.id}` }],
            [{ text: "💬 Contact Admin", url: "https://t.me/kakatiri" }]
          ]
        }
      );
    }
  } catch (error) {
    logError('Failed to notify user', error);
  }

  return {
    text: `✅ <b>Domain Approved</b>

📧 Domain: <code>${domain.domain}</code>
👤 User notified
📝 Note: ${note}

User will setup DNS and request verification.`,
    keyboard: {
      inline_keyboard: [
        [{ text: "📬 Pending Requests", callback_data: "admin:domain_requests" }],
        [{ text: "🔙 Admin Menu", callback_data: "menu:admin" }]
      ]
    }
  };
}

/**
 * Handle /rejectdomain - Reject domain request
 */
export async function handleRejectDomain(
  env: Bindings,
  telegramUserId: string,
  arg: string
): Promise<CommandResponse> {
  const lang = getLang(await getUserLanguage(env.DB, telegramUserId));
  const adminUserId = await getUserId(env.DB, telegramUserId);
  
  if (!adminUserId) {
    return {
      text: `❌ Error: Admin not found.`,
      keyboard: buildBackButton("menu:admin", lang)
    };
  }

  if (!arg) {
    return {
      text: `⚠️ Format: <code>/rejectdomain domain.com reason</code>

Example:
<code>/rejectdomain spam.com Domain already in use</code>`,
      keyboard: buildBackButton("menu:admin", lang)
    };
  }

  const parts = arg.split(/\s+/);
  const domainName = parts[0].toLowerCase();
  const reason = parts.slice(1).join(' ');

  if (!reason) {
    return {
      text: `⚠️ Please provide rejection reason.

Format: <code>/rejectdomain ${domainName} [reason]</code>`,
      keyboard: buildBackButton("menu:admin", lang)
    };
  }

  const domain = await getDomainByName(env.DB, domainName);

  if (!domain) {
    return {
      text: `❌ Domain <code>${domainName}</code> tidak ditemukan.`,
      keyboard: buildBackButton("menu:admin", lang)
    };
  }

  const success = await rejectDomain(env.DB, domain.id, adminUserId, reason);

  if (!success) {
    return {
      text: `❌ Gagal reject domain.`,
      keyboard: buildBackButton("menu:admin", lang)
    };
  }

  // Notify user
  try {
    const userResult = await env.DB.prepare(
      'SELECT telegram_user_id FROM users WHERE id = ?'
    ).bind(domain.user_id).first<{ telegram_user_id: string }>();

    if (userResult) {
      const userNotification = `❌ <b>Domain Request REJECTED</b>

📧 <b>Domain:</b> <code>${domain.domain}</code>
📝 <b>Reason:</b> ${reason}

Sorry, your domain request has been rejected by admin.

💬 Questions? Contact @kakatiri`;

      await sendTelegramMessage(
        env.TELEGRAM_BOT_TOKEN,
        parseInt(userResult.telegram_user_id),
        userNotification,
        {
          inline_keyboard: [
            [{ text: "💬 Contact Admin", url: "https://t.me/kakatiri" }]
          ]
        }
      );
    }
  } catch (error) {
    logError('Failed to notify user', error);
  }

  return {
    text: `✅ <b>Domain Rejected</b>

📧 Domain: <code>${domain.domain}</code>
👤 User notified
📝 Reason: ${reason}`,
    keyboard: {
      inline_keyboard: [
        [{ text: "📬 Pending Requests", callback_data: "admin:domain_requests" }],
        [{ text: "🔙 Admin Menu", callback_data: "menu:admin" }]
      ]
    }
  };
}

/**
 * Handle /activatedomain - Activate domain after DNS verification
 */
export async function handleActivateDomain(
  env: Bindings,
  telegramUserId: string,
  arg: string
): Promise<CommandResponse> {
  const lang = getLang(await getUserLanguage(env.DB, telegramUserId));

  if (!arg) {
    return {
      text: `⚠️ Format: <code>/activatedomain domain.com</code>

Example:
<code>/activatedomain mybusiness.com</code>`,
      keyboard: buildBackButton("menu:admin", lang)
    };
  }

  const domainName = arg.trim().toLowerCase();
  const domain = await getDomainByName(env.DB, domainName);

  if (!domain) {
    return {
      text: `❌ Domain <code>${domainName}</code> tidak ditemukan.`,
      keyboard: buildBackButton("menu:admin", lang)
    };
  }

  if (domain.status !== 'approved') {
    return {
      text: `⚠️ Domain must be in 'approved' status.

Current status: ${getStatusText(domain.status, lang)}`,
      keyboard: buildBackButton("menu:admin", lang)
    };
  }

  const success = await activateDomain(env.DB, domain.id);

  if (!success) {
    return {
      text: `❌ Gagal activate domain.`,
      keyboard: buildBackButton("menu:admin", lang)
    };
  }

  // Notify user
  try {
    const userResult = await env.DB.prepare(
      'SELECT telegram_user_id FROM users WHERE id = ?'
    ).bind(domain.user_id).first<{ telegram_user_id: string }>();

    if (userResult) {
      const userNotification = `🎉 <b>DOMAIN ACTIVATED!</b>

📧 <b>Domain:</b> <code>${domain.domain}</code>
✅ <b>Status:</b> Active

━━━━━━━━━━━━━━━
Your custom domain is now ready!

You can create emails:
<code>/create sales@${domain.domain}</code>
<code>/create support@${domain.domain}</code>
<code>/create info@${domain.domain}</code>

✨ Enjoy your custom domain!

Check stats: <code>/mydomains</code>`;

      await sendTelegramMessage(
        env.TELEGRAM_BOT_TOKEN,
        parseInt(userResult.telegram_user_id),
        userNotification,
        {
          inline_keyboard: [
            [{ text: "➕ Create Email", callback_data: "action:create_prompt" }],
            [{ text: "📋 My Domains", callback_data: "action:mydomains" }]
          ]
        }
      );
    }
  } catch (error) {
    logError('Failed to notify user', error);
  }

  return {
    text: `✅ <b>Domain Activated!</b>

📧 Domain: <code>${domain.domain}</code>
👤 User notified
🟢 Status: Active

User can now create emails with this domain.`,
    keyboard: {
      inline_keyboard: [
        [{ text: "📊 Domain Stats", callback_data: `domain_stats:${domain.id}` }],
        [{ text: "📋 All Domains", callback_data: "admin:list_domains" }],
        [{ text: "🔙 Admin Menu", callback_data: "menu:admin" }]
      ]
    }
  };
}

/**
 * Handle /listdomains - List all custom domains
 */
export async function handleListDomains(
  env: Bindings,
  telegramUserId: string,
  status: string = 'all'
): Promise<CommandResponse> {
  const lang = getLang(await getUserLanguage(env.DB, telegramUserId));
  
  const domains = await getAllDomains(env.DB, status);

  if (domains.length === 0) {
    return {
      text: `📭 <b>No Custom Domains</b>

No domains found with status: ${status}

View all: <code>/listdomains all</code>`,
      keyboard: buildBackButton("menu:admin", lang)
    };
  }

  let response = `📋 <b>Custom Domains</b>
Status: ${status === 'all' ? 'All' : status}

`;

  for (const domain of domains) {
    const emoji = getStatusEmoji(domain.status);
    const username = domain.telegram_username ? `@${domain.telegram_username}` : `ID: ${domain.telegram_user_id}`;
    const premiumBadge = domain.is_premium ? ' ⭐' : '';
    
    response += `${emoji} <b>${domain.domain}</b>
   👤 ${username}${premiumBadge}
   📧 ${domain.email_count || 0} emails
   📅 ${domain.requested_at.split('T')[0]}
   Status: ${getStatusText(domain.status, lang)}

`;
  }

  response += `━━━━━━━━━━━━━━━
Total: ${domains.length} domain(s)

Filter:
<code>/listdomains pending</code>
<code>/listdomains active</code>
<code>/listdomains all</code>`;

  const keyboard: any[][] = [
    [
      { text: "⏳ Pending", callback_data: "admin:list_domains:pending" },
      { text: "🟢 Active", callback_data: "admin:list_domains:active" }
    ],
    [
      { text: "📋 All", callback_data: "admin:list_domains:all" }
    ],
    [
      { text: "🔙 Admin Menu", callback_data: "menu:admin" }
    ]
  ];

  return {
    text: response,
    keyboard: { inline_keyboard: keyboard }
  };
}

/**
 * Handle /suspenddomain - Suspend domain
 */
export async function handleSuspendDomain(
  env: Bindings,
  telegramUserId: string,
  arg: string
): Promise<CommandResponse> {
  const lang = getLang(await getUserLanguage(env.DB, telegramUserId));
  const adminUserId = await getUserId(env.DB, telegramUserId);
  
  if (!adminUserId) {
    return {
      text: `❌ Error: Admin not found.`,
      keyboard: buildBackButton("menu:admin", lang)
    };
  }

  if (!arg) {
    return {
      text: `⚠️ Format: <code>/suspenddomain domain.com reason</code>

Example:
<code>/suspenddomain spam.com Abuse detected</code>`,
      keyboard: buildBackButton("menu:admin", lang)
    };
  }

  const parts = arg.split(/\s+/);
  const domainName = parts[0].toLowerCase();
  const reason = parts.slice(1).join(' ') || 'Suspended by admin';

  const domain = await getDomainByName(env.DB, domainName);

  if (!domain) {
    return {
      text: `❌ Domain <code>${domainName}</code> tidak ditemukan.`,
      keyboard: buildBackButton("menu:admin", lang)
    };
  }

  const success = await suspendDomain(env.DB, domain.id, adminUserId, reason);

  if (!success) {
    return {
      text: `❌ Gagal suspend domain.`,
      keyboard: buildBackButton("menu:admin", lang)
    };
  }

  // Notify user
  try {
    const userResult = await env.DB.prepare(
      'SELECT telegram_user_id FROM users WHERE id = ?'
    ).bind(domain.user_id).first<{ telegram_user_id: string }>();

    if (userResult) {
      const userNotification = `⛔ <b>Domain SUSPENDED</b>

📧 <b>Domain:</b> <code>${domain.domain}</code>
📝 <b>Reason:</b> ${reason}

Your domain has been suspended.
All emails using this domain are temporarily disabled.

💬 Contact @kakatiri if you have questions.`;

      await sendTelegramMessage(
        env.TELEGRAM_BOT_TOKEN,
        parseInt(userResult.telegram_user_id),
        userNotification,
        {
          inline_keyboard: [
            [{ text: "💬 Contact Admin", url: "https://t.me/kakatiri" }]
          ]
        }
      );
    }
  } catch (error) {
    logError('Failed to notify user', error);
  }

  return {
    text: `✅ <b>Domain Suspended</b>

📧 Domain: <code>${domain.domain}</code>
👤 User notified
📝 Reason: ${reason}
⛔ All emails using this domain are disabled.`,
    keyboard: {
      inline_keyboard: [
        [{ text: "📋 All Domains", callback_data: "admin:list_domains" }],
        [{ text: "🔙 Admin Menu", callback_data: "menu:admin" }]
      ]
    }
  };
}

/**
 * Handle domain info view (for admin)
 */
export async function handleDomainInfo(
  env: Bindings,
  telegramUserId: string,
  domainId: number
): Promise<CommandResponse> {
  const lang = getLang(await getUserLanguage(env.DB, telegramUserId));
  
  const domain = await getDomainById(env.DB, domainId);
  if (!domain) {
    return {
      text: `❌ Domain tidak ditemukan.`,
      keyboard: buildBackButton("menu:admin", lang)
    };
  }

  const userResult = await env.DB.prepare(
    'SELECT telegram_user_id, telegram_username, is_premium FROM users WHERE id = ?'
  ).bind(domain.user_id).first<any>();

  const username = userResult?.telegram_username 
    ? `@${userResult.telegram_username}` 
    : `ID: ${userResult?.telegram_user_id}`;
  const premiumBadge = userResult?.is_premium ? ' ⭐ Premium' : '';

  let response = `ℹ️ <b>Domain Information</b>

📧 <b>Domain:</b> <code>${domain.domain}</code>
${getStatusEmoji(domain.status)} <b>Status:</b> ${getStatusText(domain.status, lang)}

━━━ 👤 <b>OWNER</b> ━━━
User: ${username}${premiumBadge}

━━━ 📅 <b>TIMELINE</b> ━━━
Requested: ${domain.requested_at.split('T')[0]}
${domain.reviewed_at ? `Reviewed: ${domain.reviewed_at.split('T')[0]}` : ''}
${domain.verified_at ? `DNS Verified: ${domain.verified_at.split('T')[0]}` : ''}
${domain.activated_at ? `Activated: ${domain.activated_at.split('T')[0]}` : ''}

━━━ 📝 <b>NOTES</b> ━━━
Request Note: ${domain.request_note || '(No note)'}
${domain.admin_note ? `Admin Note: ${domain.admin_note}` : ''}

━━━ 🔐 <b>VERIFICATION</b> ━━━
Code: <code>${domain.verification_code || 'N/A'}</code>
DNS Verified: ${domain.dns_verified ? '✅ Yes' : '❌ No'}`;

  const keyboard: any[][] = [];

  // Action buttons based on status
  if (domain.status === 'pending') {
    keyboard.push([
      { text: "✅ Approve", callback_data: `domain_approve:${domain.id}` },
      { text: "❌ Reject", callback_data: `domain_reject:${domain.id}` }
    ]);
  } else if (domain.status === 'approved') {
    keyboard.push([
      { text: "🔍 Check DNS", callback_data: `domain_check:${domain.id}` },
      { text: "✅ Activate", callback_data: `domain_activate:${domain.id}` }
    ]);
  } else if (domain.status === 'active') {
    keyboard.push([
      { text: "📊 Statistics", callback_data: `domain_stats:${domain.id}` },
      { text: "⛔ Suspend", callback_data: `domain_suspend_prompt:${domain.id}` }
    ]);
  }

  keyboard.push([
    { text: "💬 Contact User", url: `https://t.me/${userResult?.telegram_user_id}` }
  ]);
  keyboard.push([
    { text: "🔙 Admin Menu", callback_data: "menu:admin" }
  ]);

  return {
    text: response,
    keyboard: { inline_keyboard: keyboard }
  };
}
