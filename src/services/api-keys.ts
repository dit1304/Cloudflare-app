/**
 * API key service — penerbitan, verifikasi, dan rate limit untuk REST API.
 *
 * Key asli TIDAK PERNAH disimpan: yang disimpan hanya SHA-256 hash.
 * Format key: `tmail_` + 48 hex chars (192 bit entropy).
 */
import type { ApiKey } from '../types';

const KEY_PREFIX = 'tmail_';
const KEY_BYTES = 24; // 24 bytes -> 48 hex chars

function toHex(buf: ArrayBuffer): string {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export async function hashApiKey(key: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(key));
  return toHex(digest);
}

export async function generateApiKey(): Promise<{ key: string; keyHash: string; keyPrefix: string }> {
  const rand = crypto.getRandomValues(new Uint8Array(KEY_BYTES));
  const key = KEY_PREFIX + toHex(rand.buffer as ArrayBuffer);
  return { key, keyHash: await hashApiKey(key), keyPrefix: key.slice(0, KEY_PREFIX.length + 8) };
}

export async function createApiKey(
  db: D1Database,
  userId: number,
  name: string,
  rateLimitPerMin = 60
): Promise<{ key: string; id: number }> {
  const { key, keyHash, keyPrefix } = await generateApiKey();
  const cleanName = (name || 'default').slice(0, 64);
  const row = await db
    .prepare(
      'INSERT INTO api_keys (user_id, name, key_hash, key_prefix, rate_limit_per_min) VALUES (?, ?, ?, ?, ?) RETURNING id'
    )
    .bind(userId, cleanName, keyHash, keyPrefix, rateLimitPerMin)
    .first<{ id: number }>();
  if (!row) throw new Error('Gagal membuat API key');
  return { key, id: row.id };
}

export async function verifyApiKey(db: D1Database, key: string): Promise<ApiKey | null> {
  if (!key || !key.startsWith(KEY_PREFIX)) return null;
  const keyHash = await hashApiKey(key);
  const row = await db
    .prepare('SELECT * FROM api_keys WHERE key_hash = ? AND is_active = 1')
    .bind(keyHash)
    .first<ApiKey>();
  if (!row) return null;
  // Update last_used_at tanpa menghambat request (fire-and-forget aman di Workers)
  try {
    await db.prepare("UPDATE api_keys SET last_used_at = datetime('now') WHERE id = ?").bind(row.id).run();
  } catch {
    /* abaikan */
  }
  return row;
}

export async function listApiKeys(db: D1Database, userId: number): Promise<ApiKey[]> {
  const res = await db
    .prepare(
      'SELECT id, user_id, name, key_prefix, is_active, rate_limit_per_min, created_at, last_used_at FROM api_keys WHERE user_id = ? ORDER BY created_at DESC'
    )
    .bind(userId)
    .all();
  return (res.results as unknown as ApiKey[]) || [];
}

export async function revokeApiKey(db: D1Database, userId: number, keyId: number): Promise<boolean> {
  const res = await db
    .prepare('UPDATE api_keys SET is_active = 0 WHERE id = ? AND user_id = ? AND is_active = 1')
    .bind(keyId, userId)
    .run();
  return (res.meta.changes || 0) > 0;
}

/**
 * Sliding-window rate limit per API key (per menit, fail-open saat DB error).
 */
export async function checkApiRateLimit(db: D1Database, key: ApiKey): Promise<{ limited: boolean; retryAfter?: number }> {
  const limit = key.rate_limit_per_min || 60;
  const windowStart = Math.floor(Date.now() / 60000); // menit berjalan
  try {
    const row = await db
      .prepare('SELECT window_start, count FROM api_rate_limits WHERE key_id = ?')
      .bind(key.id)
      .first<{ window_start: number; count: number }>();

    if (!row || row.window_start !== windowStart) {
      await db
        .prepare(
          "INSERT INTO api_rate_limits (key_id, window_start, count) VALUES (?, ?, 1) ON CONFLICT(key_id) DO UPDATE SET window_start = excluded.window_start, count = 1"
        )
        .bind(key.id, windowStart)
        .run();
      return { limited: false };
    }

    if (row.count >= limit) {
      const retryAfter = 60 - Math.floor((Date.now() % 60000) / 1000);
      return { limited: true, retryAfter };
    }

    await db.prepare('UPDATE api_rate_limits SET count = count + 1 WHERE key_id = ?').bind(key.id).run();
    return { limited: false };
  } catch {
    return { limited: false }; // fail-open: jangan matikan API gara-gara rate limiter error
  }
}

/** Ambil key dari header X-API-Key atau Authorization: Bearer */
export function extractApiKey(headers: Headers): string | null {
  const direct = headers.get('X-API-Key');
  if (direct) return direct.trim();
  const auth = headers.get('Authorization');
  if (auth && auth.toLowerCase().startsWith('bearer ')) return auth.slice(7).trim();
  return null;
}
