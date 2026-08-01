/**
 * CSPRNG helpers.
 *
 * Every random byte in the client comes from here so there is exactly one place
 * to audit. `Math.random` is not a CSPRNG and must never appear anywhere in this
 * codebase — a predictable salt or vault_key silently destroys the whole scheme.
 */

// Browsers expose this on `window.crypto`, Node >= 19 on `globalThis.crypto`.
// Same object, same API, so the module below is literally the same code in both.
const webcrypto = globalThis.crypto;

if (typeof webcrypto?.getRandomValues !== 'function') {
  // Failing at import time is deliberate. There is no fallback RNG to degrade to.
  throw new Error('Web Crypto getRandomValues unavailable; refusing to load SIoT crypto');
}

/** Per-user signup salt, 128-bit (design Section 2.1). */
export const SALT_BYTES = 16;

/**
 * @param {number} length
 * @returns {Uint8Array} `length` cryptographically random bytes.
 */
export function randomBytes(length) {
  if (!Number.isInteger(length) || length <= 0) {
    throw new RangeError(`randomBytes: length must be a positive integer, got ${length}`);
  }
  return webcrypto.getRandomValues(new Uint8Array(length));
}

/**
 * Generates the per-user salt handed to Argon2id at signup. Stored in plaintext
 * server-side, which is safe because the password itself never travels.
 *
 * @returns {Uint8Array} 16 random bytes.
 */
export function generateSalt() {
  return randomBytes(SALT_BYTES);
}
