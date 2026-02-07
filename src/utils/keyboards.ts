/**
 * Inline keyboard builders
 */

import type { Language, InlineKeyboard } from '../types';
import { t } from './translations';

/**
 * Build main menu keyboard
 */
export function buildMainMenuKeyboard(lang: Language, isAdmin: boolean): InlineKeyboard {
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
      { text: "🔧 Admin", callback_data: "menu:admin" }
    ]);
  }

  return { inline_keyboard: keyboard };
}

/**
 * Build email menu keyboard
 */
export function buildEmailMenuKeyboard(lang: Language): InlineKeyboard {
  const keyboard = [
    [
      { text: "➕ Buat Email", callback_data: "action:create_prompt" },
      { text: "📋 Daftar Email", callback_data: "action:list" }
    ],
    [
      { text: "🔍 Cari Email", callback_data: "action:search_prompt" },
      { text: "🌐 Domain", callback_data: "action:domains" }
    ],
    [
      { text: t(lang, "back_to_menu"), callback_data: "menu:main" }
    ]
  ];
  return { inline_keyboard: keyboard };
}

/**
 * Build 2FA menu keyboard
 */
export function build2FAMenuKeyboard(lang: Language): InlineKeyboard {
  const keyboard = [
    [
      { text: "🔢 Generate Kode", callback_data: "action:2fa_generate_prompt" },
      { text: "📋 Daftar Secret", callback_data: "action:2fa_list" }
    ],
    [
      { text: "➕ Tambah Secret", callback_data: "action:2fa_add_prompt" },
      { text: "🔳 QR Code", callback_data: "action:qr_prompt" }
    ],
    [
      { text: "💾 Backup", callback_data: "action:backup" }
    ],
    [
      { text: t(lang, "back_to_menu"), callback_data: "menu:main" }
    ]
  ];
  return { inline_keyboard: keyboard };
}

/**
 * Build account menu keyboard
 */
export function buildAccountMenuKeyboard(lang: Language): InlineKeyboard {
  const keyboard = [
    [
      { text: "📊 Statistik", callback_data: "action:mystats" },
      { text: "⚙️ Pengaturan", callback_data: "action:settings" }
    ],
    [
      { text: "🌐 Bahasa", callback_data: "action:lang" }
    ],
    [
      { text: t(lang, "back_to_menu"), callback_data: "menu:main" }
    ]
  ];
  return { inline_keyboard: keyboard };
}

/**
 * Build admin menu keyboard
 */
export function buildAdminMenuKeyboard(lang: Language): InlineKeyboard {
  const keyboard = [
    [
      { text: "📊 Statistik Bot", callback_data: "admin:stats" },
      { text: "👥 Daftar Users", callback_data: "admin:users" }
    ],
    [
      { text: "⭐ Premium", callback_data: "admin:premium" },
      { text: "🚫 Blacklist", callback_data: "admin:blacklist" }
    ],
    [
      { text: "🧹 Cleanup", callback_data: "admin:cleanup" },
      { text: "📢 Broadcast", callback_data: "admin:broadcast_prompt" }
    ],
    [
      { text: t(lang, "back_to_menu"), callback_data: "menu:main" }
    ]
  ];
  return { inline_keyboard: keyboard };
}

/**
 * Build back button only
 */
export function buildBackButton(target: string, lang: Language): InlineKeyboard {
  return {
    inline_keyboard: [[
      { text: t(lang, "back_to_menu"), callback_data: target }
    ]]
  };
}

/**
 * Build language selection keyboard
 */
export function buildLanguageKeyboard(): InlineKeyboard {
  return {
    inline_keyboard: [
      [
        { text: "🇮🇩 Bahasa Indonesia", callback_data: "lang:id" },
        { text: "🇬🇧 English", callback_data: "lang:en" }
      ]
    ]
  };
}
