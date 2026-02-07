/**
 * Custom Domain Database Service
 */

import type { CustomDomain } from '../types';
import { logError } from '../utils/helpers';
import { generateVerificationCode } from '../utils/domain-utils';

/**
 * Create domain request
 */
export async function createDomainRequest(
  db: D1Database,
  userId: number,
  domain: string,
  requestNote?: string
): Promise<{ success: boolean; domainId?: number; error?: string }> {
  try {
    // Check if domain already exists
    const existing = await db
      .prepare('SELECT id, status FROM custom_domains WHERE domain = ?')
      .bind(domain)
      .first();

    if (existing) {
      return { success: false, error: 'Domain already registered' };
    }

    // Create request
    const result = await db
      .prepare(
        `INSERT INTO custom_domains (user_id, domain, status, request_note, verification_code) 
         VALUES (?, ?, 'pending', ?, ?) 
         RETURNING id`
      )
      .bind(userId, domain, requestNote || null, generateVerificationCode())
      .first<{ id: number }>();

    return { success: true, domainId: result?.id };
  } catch (error) {
    logError('createDomainRequest error', error);
    return { success: false, error: 'Database error' };
  }
}

/**
 * Get domain by ID
 */
export async function getDomainById(
  db: D1Database,
  domainId: number
): Promise<CustomDomain | null> {
  try {
    return await db
      .prepare('SELECT * FROM custom_domains WHERE id = ?')
      .bind(domainId)
      .first<CustomDomain>();
  } catch (error) {
    logError('getDomainById error', error);
    return null;
  }
}

/**
 * Get domain by domain name
 */
export async function getDomainByName(
  db: D1Database,
  domain: string
): Promise<CustomDomain | null> {
  try {
    return await db
      .prepare('SELECT * FROM custom_domains WHERE domain = ?')
      .bind(domain)
      .first<CustomDomain>();
  } catch (error) {
    logError('getDomainByName error', error);
    return null;
  }
}

/**
 * Get user's domains
 */
export async function getUserDomains(
  db: D1Database,
  userId: number
): Promise<CustomDomain[]> {
  try {
    const result = await db
      .prepare('SELECT * FROM custom_domains WHERE user_id = ? ORDER BY requested_at DESC')
      .bind(userId)
      .all();
    return (result.results as CustomDomain[]) || [];
  } catch (error) {
    logError('getUserDomains error', error);
    return [];
  }
}

/**
 * Get pending domain requests (for admin)
 */
export async function getPendingDomains(db: D1Database): Promise<any[]> {
  try {
    const result = await db
      .prepare(
        `SELECT cd.*, u.telegram_user_id, u.telegram_username, u.is_premium
         FROM custom_domains cd
         JOIN users u ON cd.user_id = u.id
         WHERE cd.status = 'pending'
         ORDER BY cd.requested_at ASC`
      )
      .all();
    return result.results || [];
  } catch (error) {
    logError('getPendingDomains error', error);
    return [];
  }
}

/**
 * Get all domains with filters (for admin) - backward compatible
 */
export async function getAllDomains(
  db: D1Database,
  status?: string
): Promise<any[]> {
  try {
    let query = `
      SELECT cd.*, u.telegram_user_id, u.telegram_username, u.is_premium
      FROM custom_domains cd
      JOIN users u ON cd.user_id = u.id
    `;
    
    const params: any[] = [];
    if (status && status !== 'all') {
      query += ' WHERE cd.status = ?';
      params.push(status);
    }
    
    query += ' ORDER BY cd.requested_at DESC';
    
    const result = params.length > 0
      ? await db.prepare(query).bind(...params).all()
      : await db.prepare(query).all();
    
    // Calculate email_count for each domain (backward compatible)
    const domains = result.results || [];
    for (const domain of domains as any[]) {
      const emailCount = await db
        .prepare('SELECT COUNT(*) as count FROM emails WHERE email_address LIKE ?')
        .bind(`%@${domain.domain}`)
        .first<{ count: number }>();
      domain.email_count = emailCount?.count || 0;
    }
      
    return domains;
  } catch (error) {
    logError('getAllDomains error', error);
    return [];
  }
}

/**
 * Approve domain request
 */
export async function approveDomain(
  db: D1Database,
  domainId: number,
  adminUserId: number,
  adminNote?: string
): Promise<boolean> {
  try {
    await db
      .prepare(
        `UPDATE custom_domains 
         SET status = 'approved', 
             reviewed_by = ?,
             reviewed_at = datetime('now'),
             admin_note = ?
         WHERE id = ?`
      )
      .bind(adminUserId, adminNote || null, domainId)
      .run();
    return true;
  } catch (error) {
    logError('approveDomain error', error);
    return false;
  }
}

/**
 * Reject domain request
 */
export async function rejectDomain(
  db: D1Database,
  domainId: number,
  adminUserId: number,
  adminNote: string
): Promise<boolean> {
  try {
    await db
      .prepare(
        `UPDATE custom_domains 
         SET status = 'rejected',
             reviewed_by = ?,
             reviewed_at = datetime('now'),
             admin_note = ?
         WHERE id = ?`
      )
      .bind(adminUserId, adminNote, domainId)
      .run();
    return true;
  } catch (error) {
    logError('rejectDomain error', error);
    return false;
  }
}

/**
 * Mark domain as DNS verified
 */
export async function markDomainVerified(
  db: D1Database,
  domainId: number
): Promise<boolean> {
  try {
    await db
      .prepare(
        `UPDATE custom_domains 
         SET dns_verified = 1,
             verified_at = datetime('now')
         WHERE id = ?`
      )
      .bind(domainId)
      .run();
    return true;
  } catch (error) {
    logError('markDomainVerified error', error);
    return false;
  }
}

/**
 * Activate domain
 */
export async function activateDomain(
  db: D1Database,
  domainId: number
): Promise<boolean> {
  try {
    await db
      .prepare(
        `UPDATE custom_domains 
         SET status = 'active',
             activated_at = datetime('now')
         WHERE id = ?`
      )
      .bind(domainId)
      .run();
    return true;
  } catch (error) {
    logError('activateDomain error', error);
    return false;
  }
}

/**
 * Suspend domain
 */
export async function suspendDomain(
  db: D1Database,
  domainId: number,
  adminUserId: number,
  reason: string
): Promise<boolean> {
  try {
    await db
      .prepare(
        `UPDATE custom_domains 
         SET status = 'suspended',
             reviewed_by = ?,
             reviewed_at = datetime('now'),
             admin_note = ?
         WHERE id = ?`
      )
      .bind(adminUserId, reason, domainId)
      .run();
    return true;
  } catch (error) {
    logError('suspendDomain error', error);
    return false;
  }
}

/**
 * Delete domain request
 */
export async function deleteDomainRequest(
  db: D1Database,
  domainId: number
): Promise<boolean> {
  try {
    await db
      .prepare('DELETE FROM custom_domains WHERE id = ?')
      .bind(domainId)
      .run();
    return true;
  } catch (error) {
    logError('deleteDomainRequest error', error);
    return false;
  }
}

/**
 * Get domain statistics (backward compatible - uses domain string match)
 */
export async function getDomainStats(
  db: D1Database,
  domainId: number
): Promise<any> {
  try {
    // Get domain first
    const domain = await getDomainById(db, domainId);
    if (!domain) return null;
    
    const domainPattern = `%@${domain.domain}`;
    
    const emailCount = await db
      .prepare('SELECT COUNT(*) as count FROM emails WHERE email_address LIKE ?')
      .bind(domainPattern)
      .first<{ count: number }>();

    const messageCount = await db
      .prepare(
        `SELECT COUNT(*) as count 
         FROM inbox i 
         JOIN emails e ON i.email_id = e.id 
         WHERE e.email_address LIKE ?`
      )
      .bind(domainPattern)
      .first<{ count: number }>();

    const unreadCount = await db
      .prepare(
        `SELECT COUNT(*) as count 
         FROM inbox i 
         JOIN emails e ON i.email_id = e.id 
         WHERE e.email_address LIKE ? AND i.is_read = 0`
      )
      .bind(domainPattern)
      .first<{ count: number }>();

    const emails = await db
      .prepare(
        `SELECT e.email_address, e.created_at,
         (SELECT COUNT(*) FROM inbox WHERE email_id = e.id) as message_count
         FROM emails e
         WHERE e.email_address LIKE ?
         ORDER BY e.created_at DESC
         LIMIT 10`
      )
      .bind(domainPattern)
      .all();

    return {
      emailCount: emailCount?.count || 0,
      messageCount: messageCount?.count || 0,
      unreadCount: unreadCount?.count || 0,
      emails: emails.results || []
    };
  } catch (error) {
    logError('getDomainStats error', error);
    return null;
  }
}
