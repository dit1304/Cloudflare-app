# Changelog

All notable changes to this project will be documented in this file.

## [2.1.0] - 2024-02-07

### ✨ New Features

#### Pagination System
- **List Pagination**: Added pagination to `/list` command (15 emails per page)
- **Navigation Buttons**: Previous/Next buttons for easy navigation
- **Page Indicator**: Shows current page and total pages
- **Performance**: Optimized database queries with LIMIT/OFFSET

#### Credit & About
- **Author Info**: Added `/credit` and `/about` commands
- **Menu Button**: Added "ℹ️ About / Credit" button in main menu
- **Contact Link**: Direct link to contact admin (@kakatiri)
- **Version Info**: Display bot version and tech stack

### 🐛 Bug Fixes
- Fixed admin `/list` rate limit issues
- Fixed `/read` command return type consistency
- Improved error messages with proper keyboard buttons

### 🔧 Improvements
- Limited admin email list to prevent Telegram rate limit
- Simplified email body decoding logic
- Better error handling throughout the app

## [2.0.0] - 2024-02-07

### 🎉 Major Improvements

#### Enhanced Email Parsing
- **Better Decoding**: Improved email body extraction with support for multiple encodings
  - RFC 2047 encoded headers (=?charset?encoding?text?=)
  - Base64 encoding with better error handling
  - Quoted-Printable encoding
  - Multiple charset support (UTF-8, ISO-8859-1, Windows-1252)
- **Better Charset Detection**: Automatic detection and conversion of various charsets
- **Malformed Email Handling**: Gracefully handle malformed or incorrectly encoded emails
- **Improved MIME Parsing**: Better extraction of text/plain and text/html parts

#### Code Architecture
- **Modular Structure**: Split monolithic code into organized modules
  - `services/`: Database, Telegram API, OTP generation
  - `handlers/`: Command handlers (email, 2FA, admin)
  - `utils/`: Helper functions, email parser, translations, keyboards
  - `types/`: TypeScript type definitions
- **Better Error Handling**: Comprehensive error logging and graceful degradation
- **Type Safety**: Full TypeScript support with strict mode

#### Documentation
- **Comprehensive README**: Complete setup guide, API documentation, troubleshooting
- **Code Comments**: Better inline documentation
- **Examples**: Usage examples for all features

### 🐛 Bug Fixes
- Fixed email decoding issues for non-ASCII characters
- Fixed Base64 detection false positives
- Fixed HTML entity decoding
- Fixed quoted-printable soft line breaks

### 🔧 Technical Improvements
- Separated concerns with service layer
- Added retry logic with exponential backoff for Telegram API
- Better logging with timestamps
- Improved database query performance
- Added environment validation

## [1.0.0] - 2024-01-01

### Initial Release
- Email temporary creation and management
- 2FA/OTP code generation
- Multi-language support (ID/EN)
- Admin dashboard
- Premium system
- Telegram bot integration
- Cloudflare Workers deployment
