/**
 * `vault_key` generation and wrapping (design Section 2.2).
 *
 * The vault is encrypted under a random `vault_key`, not directly under the
 * password-derived `kek`. A password change then re-wraps 32 bytes instead of
 * re-encrypting and re-uploading the entire vault.
 */

import { randomBytes } from './random.js';
import { utf8Bytes } from './encoding.js';

export const VAULT_KEY_BYTES = 32;
const IV_BYTES = 12;
const GCM_TAG_BITS = 128;

/**
 * AAD binds the ciphertext to its purpose, so a wrapped vault_key cannot be
 * replayed into a slot expecting some other AES-GCM blob (design Section 2.3).
 * Deliberately not bound to the username: it must survive a username change.
 */
const WRAP_AAD = utf8Bytes('siot/vault-key-wrap/v1');

/**
 * Generated exactly once, at signup. Regenerating it orphans every vault record.
 *
 * @returns {Uint8Array} 32 random bytes.
 */
export function generateVaultKey() {
  return randomBytes(VAULT_KEY_BYTES);
}

/**
 * @param {Uint8Array} keyBytes
 * @param {KeyUsage[]} usages
 * @returns {Promise<CryptoKey>}
 */
function importAesKey(keyBytes, usages) {
  if (!(keyBytes instanceof Uint8Array) || keyBytes.length !== 32) {
    throw new TypeError('AES-256-GCM key must be 32 bytes');
  }
  return crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, usages);
}

/**
 * Wraps `vault_key` under `kek`. Output is `iv(12B) || ciphertext || tag(16B)`,
 * stored server-side as an opaque blob.
 *
 * A random IV is safe *here*, unlike on a device (Section 7.2): a given `kek`
 * wraps a vault_key a handful of times in an account's life (signup, password
 * changes), so the birthday bound on a 96-bit random nonce is not remotely in
 * play, and the browser has a real CSPRNG — neither of which is true of an
 * ESP32 emitting records forever from a cold boot.
 *
 * @param {Uint8Array} vaultKey 32 bytes
 * @param {Uint8Array} kek 32 bytes
 * @returns {Promise<Uint8Array>} 60 bytes.
 */
export async function wrapVaultKey(vaultKey, kek) {
  if (!(vaultKey instanceof Uint8Array) || vaultKey.length !== VAULT_KEY_BYTES) {
    throw new TypeError(`wrapVaultKey: vault_key must be ${VAULT_KEY_BYTES} bytes`);
  }

  const key = await importAesKey(kek, ['encrypt']);
  const iv = randomBytes(IV_BYTES);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: WRAP_AAD, tagLength: GCM_TAG_BITS },
    key,
    vaultKey,
  );

  const wrapped = new Uint8Array(IV_BYTES + ciphertext.byteLength);
  wrapped.set(iv, 0);
  wrapped.set(new Uint8Array(ciphertext), IV_BYTES);
  return wrapped;
}

/**
 * Reverses `wrapVaultKey`. Throws on a wrong `kek`, a tampered blob, or a
 * mismatched AAD — GCM authentication failure is indistinguishable between those
 * cases and that is fine; all three mean "do not use this key".
 *
 * @param {Uint8Array} wrapped
 * @param {Uint8Array} kek 32 bytes
 * @returns {Promise<Uint8Array>} 32 bytes.
 */
export async function unwrapVaultKey(wrapped, kek) {
  if (!(wrapped instanceof Uint8Array) || wrapped.length <= IV_BYTES) {
    throw new TypeError('unwrapVaultKey: wrapped blob is too short to contain an IV');
  }

  const key = await importAesKey(kek, ['decrypt']);
  const iv = wrapped.subarray(0, IV_BYTES);
  const ciphertext = wrapped.subarray(IV_BYTES);

  let plaintext;
  try {
    plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData: WRAP_AAD, tagLength: GCM_TAG_BITS },
      key,
      ciphertext,
    );
  } catch (cause) {
    // Web Crypto throws a bare OperationError with no message. Replace it with
    // something a caller can surface, but never swallow it — a failed unwrap is
    // always fatal to the session, never a "continue without the vault" case.
    throw new Error('vault_key unwrap failed: wrong password or corrupted blob', { cause });
  }

  const vaultKey = new Uint8Array(plaintext);
  if (vaultKey.length !== VAULT_KEY_BYTES) {
    throw new Error(`vault_key unwrap produced ${vaultKey.length} bytes, expected 32`);
  }
  return vaultKey;
}
