/**
 * REST API (/api/v1) — akses programmatis ke Temp Email Bot.
 *
 * Auth: header `X-API-Key: tmail_...` atau `Authorization: Bearer tmail_...`.
 * Key dibuat lewat perintah Telegram /apikey (ditampilkan sekali saat dibuat).
 */
import { Hono } from 'hono';
import type { Context } from 'hono';
import type { Bindings, ApiKey, Email, InboxMessage } from '../types';
import { verifyApiKey, extractApiKey, checkApiRateLimit } from '../services/api-keys';
import { createEmail, markAsRead, checkUserLimits } from '../services/database';
import { getDomains } from '../utils/helpers';

type ApiEnv = { Bindings: Bindings; Variables: { apiKey: ApiKey } };

const api = new Hono<ApiEnv>();

type ErrStatus = 400 | 401 | 403 | 404 | 409 | 429 | 500 | 503;

function err(c: Context<ApiEnv>, status: ErrStatus, code: string, message: string) {
  return c.json({ error: { code, message } }, status);
}

function randomLocalPart(len = 10): string {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  const buf = crypto.getRandomValues(new Uint8Array(len));
  return [...buf].map((b) => chars[b % chars.length]).join('');
}

async function getTelegramUserId(db: D1Database, userId: number): Promise<string | null> {
  const row = await db.prepare('SELECT telegram_user_id FROM users WHERE id = ?').bind(userId).first<{ telegram_user_id: string }>();
  return row?.telegram_user_id || null;
}

// ---------- Public ----------
api.get('/health', (c) => c.json({ ok: true, service: 'temp-email-bot', version: '1.0.0' }));

// ---------- Auth + rate limit untuk semua route di bawah ----------
api.use('*', async (c, next) => {
  const rawKey = extractApiKey(c.req.raw.headers);
  if (!rawKey) return err(c, 401, 'missing_api_key', 'Header X-API-Key atau Authorization: Bearer wajib diisi.');
  const apiKey = await verifyApiKey(c.env.DB, rawKey);
  if (!apiKey) return err(c, 401, 'invalid_api_key', 'API key tidak valid atau sudah direvoke.');

  const rl = await checkApiRateLimit(c.env.DB, apiKey);
  if (rl.limited) {
    c.header('Retry-After', String(rl.retryAfter || 60));
    return err(c, 429, 'rate_limited', 'Terlalu banyak request. Coba lagi beberapa saat.');
  }

  c.set('apiKey', apiKey);
  await next();
});

// ---------- Domains ----------
api.get('/domains', (c) => {
  return c.json({ domains: getDomains(c.env) });
});

// ---------- Addresses ----------
api.post('/addresses', async (c) => {
  const env = c.env;
  const apiKey = c.get('apiKey');
  let body: { local_part?: string; domain?: string } = {};
  try {
    body = await c.req.json();
  } catch {
    /* body kosong -> pakai default */
  }

  const domains = getDomains(env);
  if (domains.length === 0) return err(c, 503, 'no_domains', 'Tidak ada domain yang dikonfigurasi.');

  let local = (body.local_part || '').toLowerCase().trim();
  if (!local) {
    local = randomLocalPart();
  } else {
    local = local.replace(/[^a-z0-9]/g, '');
    if (local.length < 3 || local.length > 30) {
      return err(c, 400, 'invalid_local_part', 'local_part harus 3-30 karakter alfanumerik.');
    }
  }

  const requestedDomain = (body.domain || domains[0]).toLowerCase().trim();
  if (!domains.map((d) => d.toLowerCase()).includes(requestedDomain)) {
    return err(c, 400, 'invalid_domain', `Domain tidak tersedia. Pilih: ${domains.join(', ')}`);
  }

  const address = `${local}@${requestedDomain}`;

  const telegramUserId = await getTelegramUserId(env.DB, apiKey.user_id);
  if (telegramUserId) {
    const limits = await checkUserLimits(env.DB, telegramUserId, 'email');
    if (!limits.allowed) {
      return err(c, 403, 'limit_reached', `Batas alamat tercapai (${limits.current}/${limits.max}).`);
    }
  }

  const created = await createEmail(env.DB, apiKey.user_id, address, local);
  if (!created.success) {
    const code = created.error === 'Email already exists' ? 409 : 500;
    return err(c, code, code === 409 ? 'address_exists' : 'db_error', created.error || 'Gagal membuat alamat.');
  }

  const row = await env.DB.prepare('SELECT id, email_address, local_part, is_active, created_at FROM emails WHERE id = ?')
    .bind(created.emailId)
    .first<Email>();
  return c.json({ id: row?.id, address: row?.email_address, local_part: row?.local_part, is_active: !!row?.is_active, created_at: row?.created_at }, 201);
});

api.get('/addresses', async (c) => {
  const apiKey = c.get('apiKey');
  const res = await c.env.DB.prepare(
    `SELECT e.id, e.email_address, e.local_part, e.is_active, e.created_at,
      (SELECT COUNT(*) FROM inbox i WHERE i.email_id = e.id AND i.is_read = 0) AS unread_count
     FROM emails e WHERE e.user_id = ? AND e.is_active = 1 ORDER BY e.created_at DESC`
  )
    .bind(apiKey.user_id)
    .all();
  const items = ((res.results as unknown as (Email & { unread_count: number })[]) || []).map((e) => ({
    id: e.id,
    address: e.email_address,
    local_part: e.local_part,
    is_active: !!e.is_active,
    unread_count: e.unread_count,
    created_at: e.created_at,
  }));
  return c.json({ addresses: items });
});

api.get('/addresses/:id', async (c) => {
  const apiKey = c.get('apiKey');
  const id = Number(c.req.param('id'));
  if (!Number.isInteger(id)) return err(c, 400, 'invalid_id', 'ID alamat tidak valid.');
  const row = await c.env.DB.prepare('SELECT id, email_address, local_part, is_active, created_at FROM emails WHERE id = ? AND user_id = ?')
    .bind(id, apiKey.user_id)
    .first<Email>();
  if (!row) return err(c, 404, 'not_found', 'Alamat tidak ditemukan.');
  return c.json({ id: row.id, address: row.email_address, local_part: row.local_part, is_active: !!row.is_active, created_at: row.created_at });
});

api.delete('/addresses/:id', async (c) => {
  const apiKey = c.get('apiKey');
  const id = Number(c.req.param('id'));
  if (!Number.isInteger(id)) return err(c, 400, 'invalid_id', 'ID alamat tidak valid.');
  const res = await c.env.DB.prepare('UPDATE emails SET is_active = 0 WHERE id = ? AND user_id = ? AND is_active = 1')
    .bind(id, apiKey.user_id)
    .run();
  if ((res.meta.changes || 0) === 0) return err(c, 404, 'not_found', 'Alamat tidak ditemukan.');
  return c.json({ ok: true, id });
});

// ---------- Messages ----------
api.get('/addresses/:id/messages', async (c) => {
  const apiKey = c.get('apiKey');
  const id = Number(c.req.param('id'));
  if (!Number.isInteger(id)) return err(c, 400, 'invalid_id', 'ID alamat tidak valid.');
  const limit = Math.min(Math.max(Number(c.req.query('limit')) || 20, 1), 100);
  const unreadOnly = c.req.query('unread_only') === 'true';

  const owner = await c.env.DB.prepare('SELECT id FROM emails WHERE id = ? AND user_id = ?')
    .bind(id, apiKey.user_id)
    .first();
  if (!owner) return err(c, 404, 'not_found', 'Alamat tidak ditemukan.');

  const res = await c.env.DB.prepare(
    `SELECT id, email_id, sender, subject, is_read, received_at FROM inbox
     WHERE email_id = ? ${unreadOnly ? 'AND is_read = 0' : ''} ORDER BY received_at DESC LIMIT ?`
  )
    .bind(id, limit)
    .all();
  const items = ((res.results as unknown as InboxMessage[]) || []).map((m) => ({
    id: m.id,
    email_id: m.email_id,
    sender: m.sender,
    subject: m.subject,
    is_read: !!m.is_read,
    received_at: m.received_at,
  }));
  return c.json({ messages: items });
});

api.post('/addresses/:id/read-all', async (c) => {
  const apiKey = c.get('apiKey');
  const id = Number(c.req.param('id'));
  if (!Number.isInteger(id)) return err(c, 400, 'invalid_id', 'ID alamat tidak valid.');
  const owner = await c.env.DB.prepare('SELECT id FROM emails WHERE id = ? AND user_id = ?')
    .bind(id, apiKey.user_id)
    .first();
  if (!owner) return err(c, 404, 'not_found', 'Alamat tidak ditemukan.');
  const res = await c.env.DB.prepare(
    `UPDATE inbox SET is_read = 1 WHERE email_id = ? AND is_read = 0`
  ).bind(id).run();
  return c.json({ ok: true, marked: res.meta.changes ?? 0 });
});

api.get('/messages/:id', async (c) => {
  const apiKey = c.get('apiKey');
  const id = Number(c.req.param('id'));
  if (!Number.isInteger(id)) return err(c, 400, 'invalid_id', 'ID pesan tidak valid.');
  const row = await c.env.DB.prepare(
    `SELECT i.id, i.email_id, i.sender, i.subject, i.body, i.is_read, i.received_at, e.email_address AS address
     FROM inbox i JOIN emails e ON i.email_id = e.id
     WHERE i.id = ? AND e.user_id = ?`
  )
    .bind(id, apiKey.user_id)
    .first<InboxMessage & { address: string }>();
  if (!row) return err(c, 404, 'not_found', 'Pesan tidak ditemukan.');
  if (!row.is_read) await markAsRead(c.env.DB, row.id);
  return c.json({
    id: row.id,
    email_id: row.email_id,
    address: row.address,
    sender: row.sender,
    subject: row.subject,
    body: row.body,
    is_read: true,
    received_at: row.received_at,
  });
});

export function createApiApp() {
  return api;
}
