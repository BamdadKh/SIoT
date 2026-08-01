/**
 * SIoT client crypto for the entire key hierarchy of design Section 2.1.
 *
 * This module lives under `frontend/` and not `backend/` on purpose: the server
 * must never be able to `import` the code that produces `kek` or `vault_key`.
 * Physical separation is a weaker guarantee than a cryptographic one, but it
 * makes an accidental "just call the derive function server-side" impossible to
 * write without an obviously wrong import path.
 */

export { randomBytes, generateSalt, SALT_BYTES } from './random.js';
export { toBase64Url, fromBase64Url, utf8Bytes, utf8String, bytesEqual } from './encoding.js';
export { deriveMasterKey, ARGON2_PARAMS } from './argon2.js';
export { hkdfSha256, deriveLoginKey, deriveKek, HKDF_INFO } from './hkdf.js';
export {
  generateVaultKey,
  wrapVaultKey,
  unwrapVaultKey,
  VAULT_KEY_BYTES,
} from './vault-key.js';
export { encryptVault, decryptVault, VAULT_BLOB_OVERHEAD_BYTES } from './vault.js';

import { deriveMasterKey } from './argon2.js';
import { deriveLoginKey, deriveKek } from './hkdf.js';

/**
 * The full password -> {login_key, kek} path, in one call, so no caller has to
 * remember the ordering or hold onto the master_key.
 *
 * The master_key is zeroed before returning. In a garbage-collected runtime with
 * copying allocators that is best-effort, not a guarantee — it costs one line and
 * shortens the window, and nothing here should be mistaken for real memory
 * hygiene, which JS cannot offer.
 *
 * @param {string} password
 * @param {Uint8Array} salt 16 bytes
 * @returns {Promise<{ loginKey: Uint8Array, kek: Uint8Array }>}
 */
export async function deriveAccountKeys(password, salt) {
  const masterKey = await deriveMasterKey(password, salt);
  try {
    const [loginKey, kek] = await Promise.all([
      deriveLoginKey(masterKey),
      deriveKek(masterKey),
    ]);
    return { loginKey, kek };
  } finally {
    masterKey.fill(0);
  }
}
