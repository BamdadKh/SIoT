/**
 * Device identity and key derivation (design Section 5.1).
 *
 * A device is two random values and everything else falls out of them:
 *
 *   DEVICE_ID      128 bits, plaintext. The server's lookup index, and the only
 *                  part of a device the server is ever told.
 *   DEVICE_SECRET  256 bits, encrypted in the vault and written to the board's
 *                  NVS. Two HKDF labels split it into a key that reads and a key
 *                  that writes.
 *
 * The split is the whole reason grants can be read-only (Section 9):
 * `device_data_key` decrypts records and is shareable; `ed25519_seed` produces
 * the signing key that authorises uploads and never leaves the device. One
 * symmetric key could not separate those, so handing a peer read access would
 * hand it forgery too.
 *
 * This runs in two places that must agree byte for byte: here, once, at
 * provisioning, and in the ESP32 library on every boot (Phase 5.1). The HKDF
 * labels below are therefore a wire format, not naming. Changing one orphans
 * every device already in the field, exactly like `ARGON2_PARAMS`.
 */

import { randomBytes } from './random.js';
import { hkdfSha256, HKDF_INFO } from './hkdf.js';
import { ed25519PublicKeyFromSeed, ED25519_SEED_BYTES } from './ed25519.js';

/** 256 bits, per design 5.1. Never leaves the vault except to reach the board. */
export const DEVICE_SECRET_BYTES = 32;

/**
 * 128 bits (design 5.2). Large enough that collision is negligible without
 * coordination, which matters because the browser mints it offline and only then
 * asks the server to accept it. The server enforces uniqueness as well, but as a
 * constraint rather than as the thing entropy is standing in for.
 */
export const DEVICE_ID_BYTES = 16;

/** @returns {Uint8Array} 32 random bytes. */
export function generateDeviceSecret() {
  return randomBytes(DEVICE_SECRET_BYTES);
}

/** @returns {Uint8Array} 16 random bytes. */
export function generateDeviceId() {
  return randomBytes(DEVICE_ID_BYTES);
}

/**
 * @param {Uint8Array} deviceSecret
 * @returns {Uint8Array}
 */
function assertDeviceSecret(deviceSecret) {
  if (!(deviceSecret instanceof Uint8Array) || deviceSecret.length !== DEVICE_SECRET_BYTES) {
    throw new TypeError(`DEVICE_SECRET must be ${DEVICE_SECRET_BYTES} bytes`);
  }
  return deviceSecret;
}

/**
 * The AES-256-GCM key every record from this device is encrypted under.
 *
 * Derived on its own rather than only as part of `deriveDeviceKeys` because the
 * read path (Phase 6.3, decrypting records out of the vault's stored secret) has
 * no use for the public key and no reason to compute one.
 *
 * @param {Uint8Array} deviceSecret 32 bytes
 * @returns {Promise<Uint8Array>} 32 bytes.
 */
export async function deriveDeviceDataKey(deviceSecret) {
  return hkdfSha256(assertDeviceSecret(deviceSecret), HKDF_INFO.DEVICE_DATA);
}

/**
 * The Ed25519 seed the device's signing keypair is built from.
 *
 * Returned as a seed rather than a keypair because that is what the firmware
 * persists conceptually and what `ed25519.js` takes. The browser only ever turns
 * it into a public key.
 *
 * @param {Uint8Array} deviceSecret 32 bytes
 * @returns {Promise<Uint8Array>} 32 bytes.
 */
export async function deriveDeviceSignSeed(deviceSecret) {
  return hkdfSha256(assertDeviceSecret(deviceSecret), HKDF_INFO.DEVICE_SIGN, ED25519_SEED_BYTES);
}

/**
 * Everything the browser needs from a `DEVICE_SECRET`: the data key it will use
 * to read records back, and the public key it registers with the server.
 *
 * The signing seed is zeroed before returning rather than handed out. The caller
 * (a provisioning screen) has no use for signing authority, and the seed is
 * reproducible from `DEVICE_SECRET` at any time by whoever legitimately holds it.
 * Best-effort in a GC'd runtime, the same caveat `deriveAccountKeys` carries.
 *
 * @param {Uint8Array} deviceSecret 32 bytes
 * @returns {Promise<{ dataKey: Uint8Array, signPub: Uint8Array }>}
 */
export async function deriveDeviceKeys(deviceSecret) {
  assertDeviceSecret(deviceSecret);

  const [dataKey, signSeed] = await Promise.all([
    deriveDeviceDataKey(deviceSecret),
    deriveDeviceSignSeed(deviceSecret),
  ]);

  try {
    const signPub = await ed25519PublicKeyFromSeed(signSeed);
    return { dataKey, signPub };
  } finally {
    signSeed.fill(0);
  }
}

/**
 * A whole new device, minted locally: the two random values plus what derives
 * from them. Nothing here has touched the network yet, which is the point of
 * doing it in this order. Registration (`device_id`, `sign_pub`) and the vault
 * write (`DEVICE_SECRET`, name) are two separate steps the caller sequences, and
 * both can fail without this needing to be repeated.
 *
 * @returns {Promise<{
 *   deviceId: Uint8Array,
 *   deviceSecret: Uint8Array,
 *   dataKey: Uint8Array,
 *   signPub: Uint8Array,
 * }>}
 */
export async function generateDevice() {
  const deviceId = generateDeviceId();
  const deviceSecret = generateDeviceSecret();
  const { dataKey, signPub } = await deriveDeviceKeys(deviceSecret);
  return { deviceId, deviceSecret, dataKey, signPub };
}
