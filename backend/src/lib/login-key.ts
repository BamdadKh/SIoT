/**
 * Server-side hashing of `login_key` (design Section 3).
 *
 * This is the *second* Argon2id in the chain and it protects a different thing
 * from the first. The client-side KDF protects the vault; this one protects
 * authentication. Without it a database dump is not a pile of sealed vaults, it
 * is a working login credential for every account — the vault stays sealed, but
 * the attacker is logged in and can read metadata, delete records, or register
 * devices.
 *
 * Note what is *not* here: nothing in this file, or anywhere in `backend/`, can
 * derive `kek`. `login_key` and `kek` come from HKDF with distinct `info`
 * labels, so holding one says nothing about the other.
 */

import { hash, verify, Algorithm } from '@node-rs/argon2';
import { randomBytes } from 'node:crypto';

/**
 * Deliberately lighter than the client's m=64 MiB, t=3 — and that is not a
 * weakening. The client hashes a low-entropy human password, where the KDF cost
 * *is* the security margin. Here the input is already a 256-bit HKDF output, so
 * brute-forcing the hash is infeasible regardless of cost; the work factor only
 * has to make a stolen-hash attack pointless, not survive a dictionary run.
 * Meanwhile this runs on every login attempt, so cost is a DoS surface the
 * client-side hash isn't. OWASP's minimum recommendation, m=19 MiB / t=2 / p=1.
 *
 * The salt is generated internally by @node-rs/argon2 (CSPRNG, per-hash) and
 * embedded in the returned PHC string, which is what `users.login_key_hash`
 * stores — it is independent of the client's salt by construction.
 */
const SERVER_ARGON2_PARAMS = {
  algorithm: Algorithm.Argon2id,
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
} as const;

/**
 * `@node-rs/argon2` 2.0.2 accepts a `Uint8Array` password on `hash` but decodes
 * it as UTF-8 on `verify`, so raw key bytes hash fine and then fail to verify
 * with `invalid utf-8 sequence`. Feeding both calls the same ASCII encoding
 * sidesteps it. base64 of a fixed 32-byte input is injective, so no entropy is
 * lost — 43 characters standing in for the same 256 bits.
 *
 * The cost is that the value briefly exists as a JS string, which cannot be
 * zeroed the way the caller zeroes its Buffer. That is the same immutable-string
 * limitation the browser has with the password itself; it is a platform floor,
 * not a choice. Both functions must use this — hashing one encoding and
 * verifying another silently rejects every correct password.
 */
function argon2Input(loginKey: Buffer): string {
  return loginKey.toString('base64');
}

/**
 * @param loginKey 32 raw bytes as received from the client.
 * @returns an encoded PHC string (`$argon2id$v=19$m=...`).
 */
export function hashLoginKey(loginKey: Buffer): Promise<string> {
  return hash(argon2Input(loginKey), SERVER_ARGON2_PARAMS);
}

/**
 * Constant-time by construction: Argon2's own verify compares the recomputed tag
 * without short-circuiting. Never reimplement this with `===`.
 */
export function verifyLoginKey(storedHash: string, loginKey: Buffer): Promise<boolean> {
  return verify(storedHash, argon2Input(loginKey), SERVER_ARGON2_PARAMS);
}

/**
 * A hash of 32 bytes nobody will ever submit. Logging in as a username with no
 * account verifies against this and fails, so the expensive path runs whether or
 * not the account exists — otherwise a login attempt answers in ~1 ms for
 * unknown names and ~40 ms for real ones, and the timing is a cleaner account
 * oracle than anything `GET /salt` was hardened against.
 *
 * Started at import so the cost lands at boot rather than on the first unknown
 * username. It cannot realistically reject, but an eagerly started promise with
 * no handler would take the process down if it did; the `catch` below silences
 * only the unhandled-rejection warning — anyone awaiting it still sees the error.
 */
const decoyLoginKeyHash = hashLoginKey(randomBytes(32));
decoyLoginKeyHash.catch(() => {});

/** Always false. The point is the work done on the way to returning it. */
export async function verifyAgainstDecoy(loginKey: Buffer): Promise<boolean> {
  return verifyLoginKey(await decoyLoginKeyHash, loginKey);
}
