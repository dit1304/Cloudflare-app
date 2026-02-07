# Changelog

All notable changes to this project will be documented in this file.

## [2.2.0] - 2024-02-07

### 🌐 Major Feature: Custom Domain System

#### Full Custom Domain Support with Admin Approval
- **User Request Flow**: Users can request custom domains (Premium only)
- **Admin Approval**: Manual review and approval by admin
- **DNS Verification**: Complete DNS setup guide with verification
- **Domain Activation**: Admin activates after DNS verification
- **Email Integration**: Create emails with custom domains seamlessly

#### User Commands
- `/requestdomain <domain> [note]` - Submit domain request
- `/mydomains` - View all custom domains with status
- `/setupdomain <domain>` - Get DNS setup instructions
- `/verifydomain <domain>` - Request DNS verification
- `/canceldomain <domain>` - Cancel pending request

#### Admin Commands
- `/domainrequests` - View pending domain requests
- `/approvedomain <domain> [note]` - Approve domain request
- `/rejectdomain <domain> <reason>` - Reject domain request
- `/activatedomain <domain>` - Activate domain after DNS check
- `/listdomains [status]` - List all domains (pending/active/all)
- `/suspenddomain <domain> <reason>` - Suspend domain

#### Features
- **Premium Feature**: Only Premium users can request custom domains
- **Approval Workflow**: Admin must approve every request
- **DNS Validation**: TXT record verification system
- **Domain Statistics**: Track emails and messages per domain
- **Status Tracking**: pending → approved → active lifecycle
- **Notifications**: Real-time notifications to both user and admin
- **Inline Buttons**: Interactive UI for domain management
- **Security**: Domain validation, blacklist checking, ownership verification

#### Documentation
- **CUSTOM_DOMAIN_GUIDE.md**: Complete 400+ line setup guide
- **DNS Instructions**: Step-by-step for Cloudflare, GoDaddy, Namecheap
- **Troubleshooting**: Common issues and solutions
- **Examples**: Real-world use cases

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
