/**
 * Password stretching — the root of the whole key hierarchy (design Section 2.1).
 *
 * Library choice: `hash-wasm`. Rationale, since roadmap 1.1 asks for it:
 *   - MIT, actively maintained (4.12.0), ~2M weekly downloads, WASM compiled
 *     from the reference Argon2 C implementation.
 *   - The WASM is inlined as base64 in the dist bundle, so there is no separate
 *     `.wasm` fetch to get wrong and no build step required to use it.
 *   - It runs identically in Node and the browser, which means the unit tests
 *     below exercise the exact code the client will run — no mock, no shim.
 *   - `argon2-browser`, the obvious alternative, has had no release since 2022.
 */

import { argon2id } from 'hash-wasm';
import { SALT_BYTES } from './random.js';

/**
 * Design Section 2.1 / Section 14. These are load-bearing: changing any of them
 * changes every existing user's master_key and locks them out of their vault.
 * Treat this object as a wire format, not a tunable.
 */
export const ARGON2_PARAMS = Object.freeze({
  memorySizeKiB: 64 * 1024, // 64 MiB
  iterations: 3,
  parallelism: 1,
  hashLengthBytes: 32,
});

/**
 * Derives `master_key` from the user's password. Never leaves the device, and is
 * only ever used as HKDF input — nothing downstream should take the master_key
 * itself.
 *
 * @param {string} password
 * @param {Uint8Array} salt 16 bytes, from `generateSalt()` or `GET /salt`.
 * @returns {Promise<Uint8Array>} 32 bytes.
 */
export async function deriveMasterKey(password, salt) {
  if (typeof password !== 'string' || password.length === 0) {
    throw new TypeError('deriveMasterKey: password must be a non-empty string');
  }
  if (!(salt instanceof Uint8Array) || salt.length !== SALT_BYTES) {
    throw new TypeError(`deriveMasterKey: salt must be ${SALT_BYTES} bytes`);
  }

  return argon2id({
    password,
    salt,
    memorySize: ARGON2_PARAMS.memorySizeKiB,
    iterations: ARGON2_PARAMS.iterations,
    parallelism: ARGON2_PARAMS.parallelism,
    hashLength: ARGON2_PARAMS.hashLengthBytes,
    outputType: 'binary',
  });
}
