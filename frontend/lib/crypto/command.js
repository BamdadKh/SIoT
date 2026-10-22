/**
 * Dashboard-to-device commands (roadmap Phase 11.2).
 *
 * The *browser* is the writer here, so the nonce is random: `crypto.getRandomValues`
 * is the CSPRNG a device cannot be trusted to have, and command volume is a person
 * pressing a button rather than a sensor looping. That reverses 7.2's rule for
 * records on purpose; see ROADMAP 11.0.
 *
 * Replay defence lives *inside* the plaintext as `command_seq`, not in the nonce
 * or the AAD, because a replayed command is a physical action repeating. The
 * counter that feeds it is kept in the vault (`reserveCommandSeq` in
 * `vault-document.js`), so two tabs racing for the same number collide on the
 * existing `vault_version` compare-and-swap rather than both sending it.
 *
 * AAD is `version(1B) || DEVICE_ID(16B) || command-class(1B)`: it pins a command
 * to one device and one protocol revision, and carries nothing the server needs.
 */

import { randomBytes } from './random.js';
import { encodeCbor, decodeCbor } from './cbor.js';
import { DEVICE_ID_BYTES } from './device.js';

export const COMMAND_PROTOCOL_VERSION = 1;
/** Only one class exists in v1. A byte rather than an implicit constant so a second can be added without reshaping the AAD. */
export const COMMAND_CLASS_V1 = 1;
export const COMMAND_NONCE_BYTES = 12;
export const COMMAND_CIPHERTEXT_MAX_BYTES = 1024; // the server's bound
const GCM_TAG_BYTES = 16;
export const COMMAND_PLAINTEXT_MAX_BYTES = COMMAND_CIPHERTEXT_MAX_BYTES - GCM_TAG_BYTES;

/** `version || DEVICE_ID || class` */
export function commandAad(deviceId) {
  if (!(deviceId instanceof Uint8Array) || deviceId.length !== DEVICE_ID_BYTES) {
    throw new TypeError(`DEVICE_ID must be ${DEVICE_ID_BYTES} bytes`);
  }
  const aad = new Uint8Array(1 + DEVICE_ID_BYTES + 1);
  aad[0] = COMMAND_PROTOCOL_VERSION;
  aad.set(deviceId, 1);
  aad[1 + DEVICE_ID_BYTES] = COMMAND_CLASS_V1;
  return aad;
}

function assertKey(key) {
  if (!(key instanceof Uint8Array) || key.length !== 32) {
    throw new TypeError('device_command_key must be 32 bytes');
  }
}

/**
 * @param {{ deviceId: Uint8Array, commandKey: Uint8Array, commandSeq: number|bigint,
 *           type: string, args?: Record<string, unknown> }} command
 * @returns {Promise<{ nonce: Uint8Array, ciphertext: Uint8Array }>} the
 *   `POST /devices/:id/commands` body fields, as bytes.
 */
export async function encryptCommand({ deviceId, commandKey, commandSeq, type, args = {} }) {
  assertKey(commandKey);
  if (typeof type !== 'string' || type.length === 0 || type.length > 32) {
    throw new TypeError('command type must be a short non-empty string');
  }
  if (BigInt(commandSeq) < 1n) {
    throw new RangeError('command_seq starts at 1; 0 is what a fresh device has already seen');
  }
  const plaintext = encodeCbor({ command_seq: BigInt(commandSeq), type, args });
  if (plaintext.length > COMMAND_PLAINTEXT_MAX_BYTES) {
    throw new RangeError('command is too large');
  }

  const nonce = randomBytes(COMMAND_NONCE_BYTES);
  const key = await crypto.subtle.importKey('raw', commandKey, 'AES-GCM', false, ['encrypt']);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: commandAad(deviceId), tagLength: 128 },
      key,
      plaintext,
    ),
  );
  return { nonce, ciphertext };
}

/**
 * The device does this in firmware; it exists here so the format has a second
 * implementation to be tested against. Throws on anything that does not open.
 *
 * @returns {Promise<{ command_seq: bigint, type: string, args: object }>}
 */
export async function decryptCommand({ deviceId, commandKey, nonce, ciphertext }) {
  assertKey(commandKey);
  const key = await crypto.subtle.importKey('raw', commandKey, 'AES-GCM', false, ['decrypt']);
  const plain = new Uint8Array(
    await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: commandAad(deviceId), tagLength: 128 },
      key,
      ciphertext,
    ),
  );
  const decoded = decodeCbor(plain);
  return { ...decoded, command_seq: BigInt(decoded.command_seq) };
}
