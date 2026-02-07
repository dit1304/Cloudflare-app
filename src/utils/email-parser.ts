/**
 * Enhanced Email Parser
 * Handles various encodings and malformed emails
 */

/**
 * Decode Quoted-Printable encoding
 */
export function decodeQuotedPrintable(str: string): string {
  return str
    .replace(/=\r?\n/g, '') // Soft line breaks
    .replace(/=([0-9A-Fa-f]{2})/g, (_, hex) => {
      try {
        return String.fromCharCode(parseInt(hex, 16));
      } catch {
        return `=${hex}`;
      }
    });
}

/**
 * Decode Base64 with error handling
 */
export function decodeBase64(str: string): string {
  try {
    const clean = str.replace(/[\r\n\s]/g, '');
    
    // Validate base64
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(clean)) {
      return str;
    }
    
    const decoded = atob(clean);
    
    // Check if decoded content is valid text
    if (decoded.length === 0) {
      return str;
    }
    
    return decoded;
  } catch (error) {
    console.error('Base64 decode error:', error);
    return str;
  }
}

/**
 * Check if string is valid Base64
 */
export function isBase64(str: string): boolean {
  const clean = str.replace(/[\r\n\s]/g, '');
  
  if (clean.length < 20 || clean.length % 4 > 2) {
    return false;
  }
  
  if (!/^[A-Za-z0-9+/]+=*$/.test(clean)) {
    return false;
  }
  
  try {
    const decoded = atob(clean);
    // Check if decoded content looks like text
    return /[a-zA-Z<>\s]/.test(decoded);
  } catch {
    return false;
  }
}

/**
 * Decode RFC 2047 encoded words (=?charset?encoding?text?=)
 */
export function decodeRFC2047(str: string): string {
  return str.replace(
    /=\?([^?]+)\?([BbQq])\?([^?]+)\?=/g,
    (match, charset, encoding, text) => {
      try {
        let decoded = text;
        
        if (encoding.toUpperCase() === 'B') {
          // Base64
          decoded = decodeBase64(text);
        } else if (encoding.toUpperCase() === 'Q') {
          // Quoted-Printable (with underscore as space)
          decoded = decodeQuotedPrintable(text.replace(/_/g, ' '));
        }
        
        // Try to decode charset if needed
        return decodeCharset(decoded, charset);
      } catch (error) {
        console.error('RFC2047 decode error:', error);
        return match;
      }
    }
  );
}

/**
 * Decode various charsets to UTF-8
 */
export function decodeCharset(text: string, charset: string): string {
  const charsetLower = charset.toLowerCase();
  
  // Common charset aliases
  const charsetMap: Record<string, string> = {
    'utf8': 'utf-8',
    'utf-8': 'utf-8',
    'iso-8859-1': 'iso-8859-1',
    'latin1': 'iso-8859-1',
    'windows-1252': 'windows-1252',
    'us-ascii': 'us-ascii',
    'ascii': 'us-ascii',
  };
  
  const normalizedCharset = charsetMap[charsetLower] || 'utf-8';
  
  // For UTF-8 and ASCII, return as-is
  if (normalizedCharset === 'utf-8' || normalizedCharset === 'us-ascii') {
    return text;
  }
  
  // For other charsets, try to convert
  // Since we're in Workers environment, we have limited charset support
  // We'll do best-effort conversion
  try {
    // Convert Windows-1252 and ISO-8859-1 special characters
    if (normalizedCharset === 'windows-1252' || normalizedCharset === 'iso-8859-1') {
      return convertLatin1ToUTF8(text);
    }
  } catch (error) {
    console.error('Charset conversion error:', error);
  }
  
  return text;
}

/**
 * Convert Latin-1/Windows-1252 to UTF-8
 */
function convertLatin1ToUTF8(text: string): string {
  // Common Windows-1252 characters
  const windows1252Map: Record<number, string> = {
    0x80: '€', 0x82: '‚', 0x83: 'ƒ', 0x84: '„', 0x85: '…',
    0x86: '†', 0x87: '‡', 0x88: 'ˆ', 0x89: '‰', 0x8A: 'Š',
    0x8B: '‹', 0x8C: 'Œ', 0x8E: 'Ž', 0x91: ''', 0x92: ''',
    0x93: '"', 0x94: '"', 0x95: '•', 0x96: '–', 0x97: '—',
    0x98: '˜', 0x99: '™', 0x9A: 'š', 0x9B: '›', 0x9C: 'œ',
    0x9E: 'ž', 0x9F: 'Ÿ'
  };
  
  let result = '';
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    
    if (windows1252Map[code]) {
      result += windows1252Map[code];
    } else if (code >= 0xA0 && code <= 0xFF) {
      // ISO-8859-1 range, convert to proper UTF-8
      result += String.fromCharCode(code);
    } else {
      result += text[i];
    }
  }
  
  return result;
}

/**
 * Extract MIME part by content type
 */
export function extractMimePart(rawEmail: string, contentType: string): string | null {
  const regex = new RegExp(
    `Content-Type:\\s*${contentType.replace('/', '\\/')}[^\\r\\n]*` +
    `(?:;[^\\r\\n]*)*[\\r\\n]+` +
    `(?:Content-Transfer-Encoding:\\s*([^\\r\\n]+)[\\r\\n]+)?` +
    `(?:Content-Disposition:[^\\r\\n]*[\\r\\n]+)?` +
    `(?:[A-Za-z-]+:[^\\r\\n]*[\\r\\n]+)*` +
    `[\\r\\n]+` +
    `([\\s\\S]*?)` +
    `(?=\\r?\\n--[\\w-]+|$)`,
    'i'
  );
  
  const match = rawEmail.match(regex);
  if (!match) return null;
  
  const encoding = (match[1] || '').toLowerCase().trim();
  let content = match[2] || '';
  
  // Remove MIME boundaries
  content = content.replace(/--[\w-]+--?\s*$/gm, '').trim();
  
  // Decode based on encoding
  if (encoding === 'base64') {
    content = decodeBase64(content);
  } else if (encoding === 'quoted-printable') {
    content = decodeQuotedPrintable(content);
  } else if (encoding === '8bit' || encoding === '7bit') {
    // Already decoded
  }
  
  return content;
}

/**
 * Extract charset from Content-Type header
 */
export function extractCharset(rawEmail: string): string {
  const charsetMatch = rawEmail.match(/charset=["']?([^"'\s;]+)["']?/i);
  return charsetMatch ? charsetMatch[1] : 'utf-8';
}

/**
 * Enhanced email body extraction
 */
export function extractEmailBody(rawEmail: string): string {
  // Decode RFC 2047 encoded headers first
  rawEmail = decodeRFC2047(rawEmail);
  
  // Get charset
  const charset = extractCharset(rawEmail);
  
  // Try to extract plain text first
  let plainText = extractMimePart(rawEmail, 'text/plain');
  if (plainText && plainText.trim().length > 20) {
    plainText = decodeCharset(plainText, charset);
    
    // Check if it's base64 encoded again
    if (isBase64(plainText)) {
      plainText = decodeBase64(plainText);
    }
    
    const cleaned = stripHtml(plainText).trim();
    if (cleaned.length > 20) {
      return cleaned.substring(0, 4000);
    }
  }
  
  // Try HTML content
  let htmlContent = extractMimePart(rawEmail, 'text/html');
  if (htmlContent && htmlContent.trim().length > 0) {
    htmlContent = decodeCharset(htmlContent, charset);
    
    // Check if it's base64 encoded
    if (isBase64(htmlContent)) {
      htmlContent = decodeBase64(htmlContent);
    }
    
    const stripped = stripHtml(htmlContent).trim();
    if (stripped.length > 20) {
      return stripped.substring(0, 4000);
    }
  }
  
  // Fallback: extract body from raw email
  let body = rawEmail.replace(/^[\s\S]*?\r?\n\r?\n/, '');
  
  // Clean up MIME headers
  body = body
    .replace(/--[\w-]+[^\n]*/g, '')
    .replace(/Content-Type:[^\n]*/gi, '')
    .replace(/Content-Transfer-Encoding:[^\n]*/gi, '')
    .replace(/Content-Disposition:[^\n]*/gi, '')
    .replace(/Content-ID:[^\n]*/gi, '')
    .trim();
  
  // Try to detect and decode base64 chunks
  const base64Chunks = body.match(/[A-Za-z0-9+/]{100,}={0,2}/g);
  if (base64Chunks) {
    for (const chunk of base64Chunks) {
      if (isBase64(chunk)) {
        try {
          const decoded = decodeBase64(chunk);
          if (decoded.length > body.length / 2) {
            body = decoded;
            break;
          }
        } catch {}
      }
    }
  }
  
  // Try quoted-printable
  if (body.includes('=\n') || /=[0-9A-F]{2}/.test(body)) {
    body = decodeQuotedPrintable(body);
  }
  
  // Decode charset
  body = decodeCharset(body, charset);
  
  return stripHtml(body).substring(0, 4000);
}

/**
 * Enhanced HTML stripping with better handling
 */
export function stripHtml(html: string): string {
  return html
    // Remove doctype, comments, style, script
    .replace(/<!DOCTYPE[^>]*>/gi, '')
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
    .replace(/<head[^>]*>[\s\S]*?<\/head>/gi, '')
    
    // Convert block elements to newlines
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/p>/gi, '\n\n')
    .replace(/<\/div>/gi, '\n')
    .replace(/<\/tr>/gi, '\n')
    .replace(/<\/li>/gi, '\n')
    .replace(/<\/h[1-6]>/gi, '\n\n')
    
    // Remove all other HTML tags
    .replace(/<[^>]+>/g, '')
    
    // Decode HTML entities
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&apos;/g, "'")
    .replace(/&#(\d+);/g, (_, num) => {
      try {
        return String.fromCharCode(parseInt(num));
      } catch {
        return _;
      }
    })
    .replace(/&#x([0-9a-f]+);/gi, (_, hex) => {
      try {
        return String.fromCharCode(parseInt(hex, 16));
      } catch {
        return _;
      }
    })
    
    // Remove zero-width characters
    .replace(/[\u200B-\u200D\uFEFF]/g, '')
    .replace(/[\u2028\u2029]/g, '\n')
    
    // Remove soft hyphens
    .replace(/\u00AD/g, '')
    .replace(/&shy;/g, '')
    
    // Clean up quoted-printable remnants
    .replace(/=\r?\n/g, '')
    .replace(/=20/g, ' ')
    .replace(/=3D/g, '=')
    
    // Normalize whitespace
    .replace(/\r\n/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .replace(/[ \t]+/g, ' ')
    .replace(/^ +| +$/gm, '')
    .trim();
}

/**
 * Extract links from email with better parsing
 */
export function extractLinks(rawEmail: string): string[] {
  const links: string[] = [];
  const seen = new Set<string>();
  
  // Decode RFC 2047 first
  rawEmail = decodeRFC2047(rawEmail);
  
  let content = rawEmail;
  
  // Try to get HTML content
  const htmlContent = extractMimePart(rawEmail, 'text/html');
  if (htmlContent) {
    if (isBase64(htmlContent)) {
      content = decodeBase64(htmlContent);
    } else {
      content = htmlContent;
    }
  }
  
  // Important keywords for verification/action links
  const importantKeywords = [
    'verify', 'confirm', 'activate', 'validation', 'reset',
    'verifikasi', 'konfirmasi', 'aktifasi', 'aktivasi',
    'token', 'code', 'otp', 'password', 'login', 'auth',
    'click', 'klik', 'button', 'action', 'continue', 'lanjut'
  ];
  
  // Extract from href attributes
  const hrefRegex = /href=["']([^"']+)["']/gi;
  let match;
  while ((match = hrefRegex.exec(content)) !== null) {
    const url = match[1];
    if (url && url.startsWith('http') && !seen.has(url)) {
      const urlLower = url.toLowerCase();
      const isImportant = importantKeywords.some(kw => urlLower.includes(kw));
      
      // Skip common footer links
      const skipPatterns = [
        'unsubscribe', 'mailto:', 'facebook.com/sharer', 'twitter.com/share',
        'linkedin.com/share', 'instagram.com', 'youtube.com',
        'privacy', 'terms', 'help', 'support',
        'logo', 'image', '.png', '.jpg', '.gif', '.jpeg',
        'cdn.', 'static.', 'assets.'
      ];
      const shouldSkip = skipPatterns.some(p => urlLower.includes(p));
      
      if (isImportant && !shouldSkip) {
        seen.add(url);
        links.push(url);
      }
    }
  }
  
  // If no important links found, get any HTTP links
  if (links.length === 0) {
    const urlRegex = /https?:\/\/[^\s"'<>]+/gi;
    while ((match = urlRegex.exec(content)) !== null) {
      const url = match[0].replace(/[.,;:!?)>\]]+$/, '');
      if (url.length > 20 && !seen.has(url)) {
        const urlLower = url.toLowerCase();
        const skipPatterns = [
          'unsubscribe', 'facebook.com', 'twitter.com', 'linkedin.com',
          '.png', '.jpg', '.gif', 'cdn.', 'static.', 'logo', 'image'
        ];
        const shouldSkip = skipPatterns.some(p => urlLower.includes(p));
        
        if (!shouldSkip) {
          seen.add(url);
          links.push(url);
          if (links.length >= 5) break;
        }
      }
    }
  }
  
  return links.slice(0, 10); // Return max 10 links
}

/**
 * Parse "From" header with better handling
 */
export function parseFromHeader(fromHeader: string, rawFrom: string): string {
  // Decode RFC 2047 encoded display name
  fromHeader = decodeRFC2047(fromHeader);
  
  if (fromHeader) {
    // Try to extract display name from "Name" <email> format
    const match = fromHeader.match(/^["']?([^"'<]+)["']?\s*<([^>]+)>$/);
    if (match && match[1]) {
      return match[1].trim();
    }
    
    // Try without quotes
    const match2 = fromHeader.match(/^([^<]+)<([^>]+)>$/);
    if (match2 && match2[1]) {
      return match2[1].trim();
    }
  }
  
  // Handle bounces email format
  if (rawFrom.includes('=') && rawFrom.includes('bounces')) {
    const domain = rawFrom.split('@')[1];
    return domain || rawFrom;
  }
  
  return rawFrom;
}
