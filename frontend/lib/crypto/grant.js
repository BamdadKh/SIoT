/**
 * Grants: letting one device read another's records (design Section 9).
 *
 * A grant is `device_B_data_key` sealed under `device_A_data_key`, so that Device
 * A (which holds its own key and nothing of B's) can fetch the blob from the
 * server and open it. The server stores the blob and can read none of it. What
 * is shared is the *read* key only: `device_data_key` and the signing seed are
 * separate HKDF outputs (device.js), so A can decrypt B's records and cannot
 * forge one.
 *
 * Wire layout, the same shape as the other 32-byte wraps:
 *
 *   nonce(12) || AES-256-GCM(device_B_data_key)(32) || tag(16)   = 60 bytes
 *
 * AAD = utf8("grant/v1") || DEVICE_ID_A(16) || DEVICE_ID_B(16)
 *
 * The ids are bound in order, so a blob made for (A, B) will not open as (B, A)
 * and cannot be replayed as a grant between any other pair. Without that, the
 * server could hand A a grant it wrote for some other device pair and A would
 * accept the key it contained.
 *
 * Keys here are raw bytes, matching `record.js`: `deriveDeviceDataKey` already
 * returns the 32 bytes (the HKDF output), so B's key needs no extractable
 * CryptoKey and nothing in the normal read path is made extractable to support
 * this. The raw copy made for sealing is zeroed on the way out, best effort in a
 * GC'd runtime.
 *
 * A random nonce is safe: a given `device_A_data_key` seals one grant per
 * (A, B) pairing, a count nowhere near the 96-bit birthday bound. Records use a
 * counter nonce because a device emits them forever; this does not.
 */

import { utf8Bytes } from './encoding.js';
import { randomBytes } from './random.js';
import { DEVICE_ID_BYTES } from './device.js';

export const GRANT_AAD_LABEL = 'grant/v1';

const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const GCM_TAG_BITS = 128;
const DATA_KEY_BYTES = 32;

/** Must equal `GRANT_BLOB_BYTES` in backend/src/lib/wire-format.ts. */
export const GRANT_BLOB_BYTES = NONCE_BYTES + DATA_KEY_BYTES + TAG_BYTES;

const LABEL_BYTES = utf8Bytes(GRANT_AAD_LABEL);

function assertBytes(value, length, name) {
  if (!(value instanceof Uint8Array) || value.length !== length) {
    throw new TypeError(`${name} must be ${length} bytes`);
  }
}

function grantAad(deviceAId, deviceBId) {
  assertBytes(deviceAId, DEVICE_ID_BYTES, 'DEVICE_ID_A');
  assertBytes(deviceBId, DEVICE_ID_BYTES, 'DEVICE_ID_B');
  const aad = new Uint8Array(LABEL_BYTES.length + 2 * DEVICE_ID_BYTES);
  aad.set(LABEL_BYTES, 0);
  aad.set(deviceAId, LABEL_BYTES.length);
  aad.set(deviceBId, LABEL_BYTES.length + DEVICE_ID_BYTES);
  return aad;
}

function importWrapKey(deviceADataKey, usages) {
  assertBytes(deviceADataKey, DATA_KEY_BYTES, 'device_A_data_key');
  return crypto.subtle.importKey('raw', deviceADataKey, 'AES-GCM', false, usages);
}

/**
 * Seals B's read key for A.
 *
 * @param {{ deviceAId: Uint8Array, deviceBId: Uint8Array,
 *          deviceADataKey: Uint8Array, deviceBDataKey: Uint8Array }} grant
 *        ids 16 bytes, keys 32 bytes (as returned by `deriveDeviceDataKey`).
 * @returns {Promise<Uint8Array>} 60 bytes: nonce || ciphertext || tag.
 */
export async function sealGrant({ deviceAId, deviceBId, deviceADataKey, deviceBDataKey }) {
  assertBytes(deviceBDataKey, DATA_KEY_BYTES, 'device_B_data_key');
  const aad = grantAad(deviceAId, deviceBId);
  const key = await importWrapKey(deviceADataKey, ['encrypt']);
  const nonce = randomBytes(NONCE_BYTES);

  const sealed = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: GCM_TAG_BITS },
    key,
    deviceBDataKey,
  );

  const blob = new Uint8Array(NONCE_BYTES + sealed.byteLength);
  blob.set(nonce, 0);
  blob.set(new Uint8Array(sealed), NONCE_BYTES);
  return blob;
}

/**
 * Opens a grant and returns B's read key. This direction runs on Device A's
 * firmware in the shipped product; it is here for the test suite, for 8.3, and
 * to stand in for firmware on ports that do not exist yet.
 *
 * Refuses a blob sealed for a different ordering or pair of ids, a different
 * `device_A_data_key`, or any altered byte, all as one error: to a caller they
 * mean one thing, that this is not a grant from B to A.
 *
 * @param {{ deviceAId: Uint8Array, deviceBId: Uint8Array,
 *          deviceADataKey: Uint8Array, blob: Uint8Array }} grant
 * @returns {Promise<Uint8Array>} 32 bytes, `device_B_data_key`. Caller zeroes it.
 */
export async function openGrant({ deviceAId, deviceBId, deviceADataKey, blob }) {
  assertBytes(blob, GRANT_BLOB_BYTES, 'grant blob');
  const aad = grantAad(deviceAId, deviceBId);
  const key = await importWrapKey(deviceADataKey, ['decrypt']);

  let plaintext;
  try {
    plaintext = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: blob.subarray(0, NONCE_BYTES),
        additionalData: aad,
        tagLength: GCM_TAG_BITS,
      },
      key,
      blob.subarray(NONCE_BYTES),
    );
  } catch (cause) {
    throw new Error(
      'grant would not open: wrong device_A_data_key, a different device pair, or a tampered blob',
      { cause },
    );
  }
  return new Uint8Array(plaintext);
}
