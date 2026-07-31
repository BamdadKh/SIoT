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
 * @param loginKey 32 raw bytes as received from the client.
 * @returns an encoded PHC string (`$argon2id$v=19$m=...`).
 */
export function hashLoginKey(loginKey: Buffer): Promise<string> {
  return hash(loginKey, SERVER_ARGON2_PARAMS);
}

/**
 * Constant-time by construction: Argon2's own verify compares the recomputed tag
 * without short-circuiting. Never reimplement this with `===`.
 */
export function verifyLoginKey(storedHash: string, loginKey: Buffer): Promise<boolean> {
  return verify(storedHash, loginKey, SERVER_ARGON2_PARAMS);
}
