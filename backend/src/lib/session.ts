/**
 * Server-side sessions (design Section 3).
 *
 * Sessions live in Redis, never in Postgres and never in a token: revocation has
 * to be a delete, not a blocklist. The id the browser holds is a bearer token —
 * whoever has it is the user — so the only copy the server keeps is a hash of
 * it. A Redis dump then yields no usable session, exactly as a Postgres dump
 * yields no usable password.
 */

import { createHash, randomBytes } from 'node:crypto';
import type { Redis } from 'ioredis';

/** 256-bit, per Section 3. Unguessable is the entire security property here. */
const SESSION_ID_BYTES = 32;

/**
 * Two clocks, both enforced server-side:
 *
 * - idle: Redis TTL, pushed forward on each authenticated request (2.6). An
 *   abandoned tab stops being a way in.
 * - absolute: stored on the record and checked on lookup, so a session that is
 *   kept warm by an attacker still dies on schedule.
 */
export const IDLE_TIMEOUT_SECONDS = 30 * 60;
export const ABSOLUTE_TTL_SECONDS = 12 * 60 * 60;

/** `siot_` prefix so it is obvious which app owns it in a shared localhost jar. */
export const SESSION_COOKIE = 'siot_session';

const sessionKey = (idHash: string) => `sess:${idHash}`;
/** Index of a user's live sessions, so logout-everywhere is one lookup (2.6). */
const userSessionsKey = (userId: string) => `sess:user:${userId}`;

/**
 * SHA-256, not Argon2 — and that is not the same call as `login_key`. A session
 * id is 256 bits of CSPRNG output, so there is no dictionary to run against it
 * and a slow hash buys nothing; meanwhile this runs on every authenticated
 * request, where a slow hash would be a DoS surface.
 */
function hashSessionId(id: string): string {
  return createHash('sha256').update(id, 'utf8').digest('base64url');
}

/**
 * Creates a session and returns the raw id — the only moment it exists in
 * plaintext anywhere on the server. Hand it straight to the cookie and drop it.
 */
export async function createSession(redis: Redis, userId: string): Promise<string> {
  const id = randomBytes(SESSION_ID_BYTES).toString('base64url');
  const idHash = hashSessionId(id);
  const absoluteExpiry = Date.now() + ABSOLUTE_TTL_SECONDS * 1000;

  await redis
    .multi()
    .hset(sessionKey(idHash), { uid: userId, abs: String(absoluteExpiry) })
    .expire(sessionKey(idHash), IDLE_TIMEOUT_SECONDS)
    // The index outlives any single session's idle window, so it needs its own
    // ceiling or it accumulates hashes of dead sessions forever.
    .sadd(userSessionsKey(userId), idHash)
    .expire(userSessionsKey(userId), ABSOLUTE_TTL_SECONDS)
    .exec();

  return id;
}

export interface ActiveSession {
  userId: string;
  /** What identifies the session in Redis. The raw id is never kept past login. */
  idHash: string;
}

/**
 * Resolves a cookie value to a live session, sliding the idle window forward as
 * a side effect. Returns null for anything not currently valid — absent, forged,
 * idled out, or past its absolute deadline — with no distinction between them,
 * because a caller has nothing useful to do with the difference.
 */
export async function lookupSession(redis: Redis, id: string): Promise<ActiveSession | null> {
  const idHash = hashSessionId(id);
  const record = await redis.hgetall(sessionKey(idHash));
  // An idled-out session is already gone: Redis expired the key, and hgetall on
  // a missing key is an empty object rather than an error.
  if (!record.uid) return null;

  const remainingMs = Number(record.abs) - Date.now();
  if (!Number.isFinite(remainingMs) || remainingMs <= 0) {
    await revokeSession(redis, { userId: record.uid, idHash });
    return null;
  }

  // Sliding the idle window must never push the key past the absolute deadline,
  // or a session kept warm by an attacker would outlive the cap it exists for.
  const ttl = Math.min(IDLE_TIMEOUT_SECONDS, Math.ceil(remainingMs / 1000));
  await redis.expire(sessionKey(idHash), ttl);

  return { userId: record.uid, idHash };
}

/** Logout. The index entry goes too, so it does not accumulate dead hashes. */
export async function revokeSession(redis: Redis, session: ActiveSession): Promise<void> {
  await redis
    .multi()
    .del(sessionKey(session.idHash))
    .srem(userSessionsKey(session.userId), session.idHash)
    .exec();
}

/**
 * Logout everywhere — the reason sessions are server-side at all. A stateless
 * token would need a revocation list here; this is one SMEMBERS and a DEL.
 *
 * @returns how many sessions were live, so the caller can say so.
 */
export async function revokeAllSessions(redis: Redis, userId: string): Promise<number> {
  const idHashes = await redis.smembers(userSessionsKey(userId));

  const pipeline = redis.multi();
  for (const idHash of idHashes) pipeline.del(sessionKey(idHash));
  pipeline.del(userSessionsKey(userId));
  await pipeline.exec();

  // The index can name sessions Redis already idled out, so this is an upper
  // bound on what was actually still usable.
  return idHashes.length;
}
