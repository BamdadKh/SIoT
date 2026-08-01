/**
 * Login throttling with exponential backoff (design Section 3).
 *
 * Zero-knowledge does nothing to slow down online guessing: the client derives
 * `login_key` from the password and posts it, so an attacker can too. The only
 * thing between a weak password and an attacker is this file.
 *
 * Two independent scopes, because they stop different attacks:
 *
 * - **account**: one name, many passwords. This is the guessing attack.
 * - **address**: one source, many names. This is the credential-stuffing sweep
 *   that never trips a per-account limit because it only tries each name once.
 *
 * Either scope being locked rejects the request. Account locking is a denial of
 * service against that account by design; the backoff is therefore *time*, not a
 * latch, and it caps out — a victim waits minutes, never needs an unlock.
 *
 * Written against Redis directly rather than `@fastify/rate-limit`: what is
 * needed here is a stateful failure counter with backoff that survives restarts
 * and is only incremented on a *wrong* answer, not a fixed request budget.
 */

import type { Redis } from 'ioredis';

interface ScopePolicy {
  /** Wrong answers allowed before any delay at all. */
  freeAttempts: number;
  /** Delay after the first attempt past the free ones; doubles from there. */
  baseDelaySeconds: number;
  maxDelaySeconds: number;
  /** How long a quiet period has to be before the counter is forgotten. */
  windowSeconds: number;
}

/**
 * Tight, because the attacker only needs the account name to start. Five wrong
 * tries is a fat-fingered human; the sixth starts costing seconds.
 */
const ACCOUNT_POLICY: ScopePolicy = {
  freeAttempts: 5,
  baseDelaySeconds: 2,
  maxDelaySeconds: 15 * 60,
  windowSeconds: 60 * 60,
};

/**
 * Looser: one address can legitimately be a household behind NAT, or the whole
 * office. It is a backstop against a sweep, not the primary control.
 */
const ADDRESS_POLICY: ScopePolicy = {
  freeAttempts: 30,
  baseDelaySeconds: 1,
  maxDelaySeconds: 15 * 60,
  windowSeconds: 60 * 60,
};

export interface Throttle {
  key: string;
  policy: ScopePolicy;
}

/**
 * Keyed on the username as *submitted* (already normalised), whether or not it
 * exists. An unknown name gets a counter too — otherwise the limiter itself
 * becomes the account-existence oracle that `GET /salt` exists to prevent.
 */
export const accountThrottle = (username: string): Throttle => ({
  key: `login:acct:${username}`,
  policy: ACCOUNT_POLICY,
});

export const addressThrottle = (address: string): Throttle => ({
  key: `login:addr:${address}`,
  policy: ADDRESS_POLICY,
});

const lockKey = (key: string) => `${key}:until`;

/** Doubling from the first attempt past the free allowance, then flat at the cap. */
function delayFor(failures: number, policy: ScopePolicy): number {
  const over = failures - policy.freeAttempts;
  if (over <= 0) return 0;
  const delay = policy.baseDelaySeconds * 2 ** (over - 1);
  return Math.min(delay, policy.maxDelaySeconds);
}

/**
 * Whether any scope is currently locked out, and for how much longer.
 *
 * Called *before* the Argon2 verify, so a locked-out attacker cannot use login
 * attempts as a CPU-exhaustion lever either.
 */
export async function checkThrottles(
  redis: Redis,
  throttles: Throttle[],
): Promise<{ allowed: true } | { allowed: false; retryAfterSeconds: number }> {
  const locks = await redis.mget(throttles.map((t) => lockKey(t.key)));

  const now = Date.now();
  let longest = 0;
  for (const lock of locks) {
    if (!lock) continue;
    const remaining = Number(lock) - now;
    if (remaining > 0) longest = Math.max(longest, remaining);
  }

  if (longest <= 0) return { allowed: true };
  return { allowed: false, retryAfterSeconds: Math.ceil(longest / 1000) };
}

/**
 * Records a wrong answer and arms the next lockout window.
 *
 * The counter and the lock are separate keys on purpose: the lock expires when
 * the wait is served, but the counter survives it, so attempt seven waits longer
 * than attempt six instead of resetting the ladder every time.
 */
export async function registerFailure(redis: Redis, throttles: Throttle[]): Promise<void> {
  const pipeline = redis.pipeline();
  for (const { key, policy } of throttles) {
    pipeline.incr(key);
    pipeline.expire(key, policy.windowSeconds);
  }
  const results = await pipeline.exec();
  if (!results) return;

  const lockPipeline = redis.pipeline();
  throttles.forEach(({ key, policy }, index) => {
    // Two commands queued per throttle; the INCR reply is the first of each pair.
    const failures = Number(results[index * 2]?.[1] ?? 0);
    const delay = delayFor(failures, policy);
    if (delay > 0) {
      lockPipeline.set(lockKey(key), String(Date.now() + delay * 1000), 'EX', delay);
    }
  });
  await lockPipeline.exec();
}

/**
 * Clears the account ladder after a correct password. The address counter is
 * deliberately *not* cleared: one working account of their own would otherwise
 * let a stuffer reset the sweep limit at will.
 */
export async function clearThrottle(redis: Redis, throttle: Throttle): Promise<void> {
  await redis.del(throttle.key, lockKey(throttle.key));
}
