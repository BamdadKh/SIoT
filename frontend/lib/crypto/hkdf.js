/**
 * Domain-separated key derivation (design Section 2.1).
 *
 * `login_key` goes to the server; `kek` never does. Both come from the same
 * master_key, and the only thing stopping the server from computing `kek` out of
 * the `login_key` it holds is HKDF's guarantee that outputs under distinct `info`
 * labels are computationally independent. The labels are therefore part of the
 * security argument, not naming preference — never reuse one across purposes.
 */

import { utf8Bytes } from './encoding.js';

/** Every `info` label in the system. New consumers add a label, never reuse one. */
export const HKDF_INFO = Object.freeze({
  LOGIN_KEY: 'siot/auth/v1',
  KEK: 'siot/kek/v1',
  // Phase 4 will add: 'siot/device/data/v1', 'siot/device/sign/v1'.
});

/**
 * HKDF-SHA256 with an empty salt.
 *
 * The empty salt is intentional and RFC 5869-sanctioned: HKDF's salt exists to
 * extract entropy from a non-uniform IKM, and our IKM is either an Argon2id
 * output or a CSPRNG secret — already uniform. The per-user randomness lives in
 * the Argon2id salt one step up, where it actually does work.
 *
 * @param {Uint8Array} ikm input keying material (32B secret)
 * @param {string} info domain-separation label, from `HKDF_INFO`
 * @param {number} [lengthBytes]
 * @returns {Promise<Uint8Array>}
 */
export async function hkdfSha256(ikm, info, lengthBytes = 32) {
  if (!(ikm instanceof Uint8Array) || ikm.length === 0) {
    throw new TypeError('hkdfSha256: ikm must be a non-empty Uint8Array');
  }
  if (typeof info !== 'string' || info.length === 0) {
    throw new TypeError('hkdfSha256: info label is required (domain separation)');
  }

  const baseKey = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: utf8Bytes(info) },
    baseKey,
    lengthBytes * 8,
  );
  return new Uint8Array(bits);
}

/**
 * Password-equivalent authenticator sent to the server, which stores only
 * Argon2id(login_key) (design Section 3).
 *
 * @param {Uint8Array} masterKey
 * @returns {Promise<Uint8Array>} 32 bytes.
 */
export function deriveLoginKey(masterKey) {
  return hkdfSha256(masterKey, HKDF_INFO.LOGIN_KEY);
}

/**
 * Key-encryption key. Wraps `vault_key` and never touches the network.
 *
 * @param {Uint8Array} masterKey
 * @returns {Promise<Uint8Array>} 32 bytes.
 */
export function deriveKek(masterKey) {
  return hkdfSha256(masterKey, HKDF_INFO.KEK);
}
