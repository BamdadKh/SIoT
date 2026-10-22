/**
 * Read-only key grants (design Section 9; roadmap 8.1).
 *
 * A grant is `device_B_data_key` wrapped under `device_A_data_key`, so Device A
 * can read B's records (past and future) without any always-on relay. Only the
 * data key is ever wrapped. `device_sign_priv` stays on B, which is the entire
 * reason 5.1 splits the keys: a grant can read, never forge.
 *
 * Blob layout is `iv(12) || ct(32) || tag(16)` = 60 bytes, the size the server
 * enforces as `GRANT_BLOB_BYTES`. AAD is `"grant/v1" || DEVICE_ID_A ||
 * DEVICE_ID_B`, which pins a blob to the ordered pair: a grant lifted from one
 * pair of devices will not open under another, and swapping the roles fails too.
 *
 * A random IV is safe here for the reason it is in `vault-key.js`: a given
 * `device_A_data_key` wraps a grant a handful of times in its life, and this runs
 * in a browser with a real CSPRNG. Device A only ever *opens* grants.
 */

import { randomBytes } from './random.js';
import { utf8Bytes } from './encoding.js';
import { DEVICE_ID_BYTES } from './device.js';

export const GRANT_BLOB_BYTES = 60;
const KEY_BYTES = 32;
const IV_BYTES = 12;
const GCM_TAG_BITS = 128;
const GRANT_AAD_PREFIX = utf8Bytes('grant/v1');

function assertBytes(value, length, label) {
  if (!(value instanceof Uint8Array) || value.length !== length) {
    throw new TypeError(`${label} must be ${length} bytes`);
  }
}

/** `"grant/v1" || DEVICE_ID_A || DEVICE_ID_B`. Order matters and is the point. */
export function grantAad(deviceIdA, deviceIdB) {
  assertBytes(deviceIdA, DEVICE_ID_BYTES, 'DEVICE_ID_A');
  assertBytes(deviceIdB, DEVICE_ID_BYTES, 'DEVICE_ID_B');
  const aad = new Uint8Array(GRANT_AAD_PREFIX.length + 2 * DEVICE_ID_BYTES);
  aad.set(GRANT_AAD_PREFIX, 0);
  aad.set(deviceIdA, GRANT_AAD_PREFIX.length);
  aad.set(deviceIdB, GRANT_AAD_PREFIX.length + DEVICE_ID_BYTES);
  return aad;
}

function importKey(keyBytes, usage) {
  return crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, [usage]);
}

/**
 * @param {{ deviceIdA: Uint8Array, deviceIdB: Uint8Array,
 *           dataKeyA: Uint8Array, dataKeyB: Uint8Array }} grant
 * @returns {Promise<Uint8Array>} 60 bytes, the `ciphertext` of `POST /grants`.
 */
export async function createGrant({ deviceIdA, deviceIdB, dataKeyA, dataKeyB }) {
  assertBytes(dataKeyA, KEY_BYTES, 'device_A_data_key');
  assertBytes(dataKeyB, KEY_BYTES, 'device_B_data_key');
  const aad = grantAad(deviceIdA, deviceIdB);

  const iv = randomBytes(IV_BYTES);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: aad, tagLength: GCM_TAG_BITS },
      await importKey(dataKeyA, 'encrypt'),
      dataKeyB,
    ),
  );
  const blob = new Uint8Array(IV_BYTES + ct.length);
  blob.set(iv, 0);
  blob.set(ct, IV_BYTES);
  return blob;
}

/**
 * Opens a grant. Throws on a wrong key, a tampered blob, or a pair it was not
 * made for; GCM cannot say which, and all three mean "do not use this".
 *
 * @returns {Promise<Uint8Array>} `device_B_data_key`, 32 bytes.
 */
export async function openGrant({ blob, deviceIdA, deviceIdB, dataKeyA }) {
  assertBytes(blob, GRANT_BLOB_BYTES, 'grant blob');
  assertBytes(dataKeyA, KEY_BYTES, 'device_A_data_key');
  const aad = grantAad(deviceIdA, deviceIdB);

  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: blob.subarray(0, IV_BYTES), additionalData: aad, tagLength: GCM_TAG_BITS },
    await importKey(dataKeyA, 'decrypt'),
    blob.subarray(IV_BYTES),
  );
  return new Uint8Array(plain);
}
