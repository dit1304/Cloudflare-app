/**
 * Translations and i18n
 */

import type { Language } from '../types';

export const TRANSLATIONS = {
  id: {
    welcome_choose_lang: `🌍 <b>Pilih Bahasa / Choose Language</b>

Silakan pilih bahasa yang ingin kamu gunakan:
Please select your preferred language:`,
    lang_set: "✅ Bahasa berhasil diubah ke Bahasa Indonesia!",
    welcome_title: "🎉 <b>Selamat datang di Temp Email Bot!</b>",
    welcome_desc: "Bot ini membantu kamu membuat email temporary dan mengelola kode 2FA.",
    menu_title: "📱 <b>Menu Utama</b>",
    menu_desc: "Pilih menu di bawah:",
    menu_email: "📧 Email",
    menu_2fa: "🔐 2FA/OTP",
    menu_account: "👤 Akun",
    menu_help: "❓ Bantuan",
    back_to_menu: "🔙 Menu Utama",
    email_menu_title: "📧 <b>Menu Email</b>",
    twofa_menu_title: "🔐 <b>Menu 2FA/OTP</b>",
    account_menu_title: "👤 <b>Menu Akun</b>",
    admin_menu_title: "🔧 <b>Menu Admin</b>",
    choose_action: "Pilih aksi:",
    admin_only: "⛔ Perintah ini hanya untuk admin.",
    cmd_not_found: "❓ Perintah tidak dikenali.\n\nKetik /start untuk melihat panduan.",
  },
  en: {
    welcome_choose_lang: `🌍 <b>Choose Language / Pilih Bahasa</b>

Please select your preferred language:
Silakan pilih bahasa yang ingin kamu gunakan:`,
    lang_set: "✅ Language successfully changed to English!",
    welcome_title: "🎉 <b>Welcome to Temp Email Bot!</b>",
    welcome_desc: "This bot helps you create temporary emails and manage 2FA codes.",
    menu_title: "📱 <b>Main Menu</b>",
    menu_desc: "Choose menu below:",
    menu_email: "📧 Email",
    menu_2fa: "🔐 2FA/OTP",
    menu_account: "👤 Account",
    menu_help: "❓ Help",
    back_to_menu: "🔙 Main Menu",
    email_menu_title: "📧 <b>Email Menu</b>",
    twofa_menu_title: "🔐 <b>2FA/OTP Menu</b>",
    account_menu_title: "👤 <b>Account Menu</b>",
    admin_menu_title: "🔧 <b>Admin Menu</b>",
    choose_action: "Choose action:",
    admin_only: "⛔ This command is for admin only.",
    cmd_not_found: "❓ Command not recognized.\n\nType /start to see the guide.",
  }
};

export function t(lang: Language, key: keyof typeof TRANSLATIONS.id): string {
  return TRANSLATIONS[lang][key] || TRANSLATIONS.id[key];
}

export function getLang(lang: Language | null): Language {
  return lang || "id";
}
