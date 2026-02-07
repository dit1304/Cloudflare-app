/**
 * OTP/2FA service
 */

import * as OTPAuth from "otpauth";
import type { OTPResult } from '../types';
import { logError } from '../utils/helpers';

/**
 * Generate OTP code from secret
 */
export function generateOTP(secret: string): OTPResult | null {
  try {
    const cleanSecret = secret.trim().replace(/ /g, '').toUpperCase();
    
    // Validate base32 format
    if (!/^[A-Z2-7]+=*$/.test(cleanSecret)) {
      return null;
    }
    
    const totp = new OTPAuth.TOTP({
      algorithm: "SHA1",
      digits: 6,
      period: 30,
      secret: OTPAuth.Secret.fromBase32(cleanSecret)
    });
    
    const code = totp.generate();
    const now = Math.floor(Date.now() / 1000);
    const remaining = 30 - (now % 30);
    
    return { code, remaining };
  } catch (error) {
    logError('generateOTP error', error);
    return null;
  }
}

/**
 * Validate OTP secret format
 */
export function validateSecret(secret: string): boolean {
  const cleanSecret = secret.trim().replace(/ /g, '').toUpperCase();
  
  // Check length (typically 16-32 characters)
  if (cleanSecret.length < 16 || cleanSecret.length > 128) {
    return false;
  }
  
  // Check base32 format (A-Z, 2-7, optional padding =)
  if (!/^[A-Z2-7]+=*$/.test(cleanSecret)) {
    return false;
  }
  
  // Try to generate OTP to validate
  try {
    const result = generateOTP(cleanSecret);
    return result !== null;
  } catch {
    return false;
  }
}

/**
 * Generate QR code URL for TOTP
 */
export function generateQRCodeUrl(name: string, secret: string, issuer: string = 'TempEmailBot'): string {
  const otpauthUri = `otpauth://totp/${encodeURIComponent(name)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}`;
  return `https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=${encodeURIComponent(otpauthUri)}`;
}

/**
 * Parse otpauth:// URI
 */
export function parseOTPAuthUri(uri: string): { name: string; secret: string; issuer?: string } | null {
  try {
    const match = uri.match(/otpauth:\/\/totp\/([^?]+)\?(.+)/);
    if (!match) return null;
    
    const name = decodeURIComponent(match[1]);
    const params = new URLSearchParams(match[2]);
    const secret = params.get('secret');
    const issuer = params.get('issuer');
    
    if (!secret) return null;
    
    return {
      name,
      secret,
      issuer: issuer || undefined
    };
  } catch (error) {
    logError('parseOTPAuthUri error', error);
    return null;
  }
}
