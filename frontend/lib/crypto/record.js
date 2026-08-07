/**
 * The device record wire format (design Section 7), on the browser side.
 *
 * This is the other end of what firmware produces: the same nonce, the same AAD,
 * the same AES-256-GCM, so a record encrypted by an ESP32 opens here and a
 * record built here is one the server accepts. `docs/protocol.md` is the
 * published form of everything in this file, and the two are checked against
 * each other by `test/protocol-vectors.test.js` rather than by proofreading.
 *
 * Nothing here signs. Signing authority is `ed25519_seed`, which design 5.1
 * keeps on the device and which `deriveDeviceKeys` deliberately zeroes before
 * returning; a browser building a record it could sign would be a browser that
 * can impersonate the device. `recordSigningInput` exists so the *verification*
 * side, and the firmware stand-ins in the test suite, can assemble exactly what
 * gets signed without either reimplementing the layout.
 *
 * ## Layout
 *
 *   seq (uint64)  = (boot_epoch << 32) | msg_counter        design 7.1
 *   nonce (12B)   = 0x00000000 || seq (8B big-endian)       design 7.2
 *   AAD (26B)     = version(1) || DEVICE_ID(16) || record_type(1) || seq(8)
 *   ciphertext    = AES-256-GCM(device_data_key, nonce, CBOR{t,r}, AAD)
 *   signature     = Ed25519(device_sign_priv, AAD || nonce || ciphertext)
 *
 * `version` and `record_type` are fixed v1 constants rather than wire fields,
 * because design 7.3's own `POST /records` example body does not carry them.
 * Both sides rebuild the AAD from these constants plus the `device_id` and `seq`
 * that are on the wire. `record_type` is reserved for Phase 7's per-schema types
 * and is 0 for every record until then. Phase 10 notifications do **not** get a
 * value of their own here: a distinguishable alert record is a labelled event
 * log, so the type marker for those lives inside the ciphertext (roadmap 10.0).
 */

import { encodeCbor, decodeCbor } from './cbor.js';

export const PROTOCOL_VERSION = 1;
export const RECORD_TYPE_V1 = 0;

export const NONCE_BYTES = 12;
export const SEQ_BYTES = 8;
export const RECORD_AAD_BYTES = 1 + 16 + 1 + SEQ_BYTES;
export const GCM_TAG_BYTES = 16;

const DEVICE_ID_BYTES = 16;
const DATA_KEY_BYTES = 32;
const GCM_TAG_BITS = 128;
const UINT32_MAX = 0xffffffffn;
const UINT64_MAX = (1n << 64n) - 1n;

/**
 * `(boot_epoch << 32) | msg_counter`, always through `BigInt`: the value leaves
 * the safe-integer range as soon as `boot_epoch` passes 2^21, and the failure
 * mode of doing it in `Number` is silent rounding rather than an error.
 *
 * @param {number|bigint} bootEpoch persisted across reboots (design 7.1)
 * @param {number|bigint} msgCounter reset to zero each boot
 * @returns {bigint}
 */
export function composeSeq(bootEpoch, msgCounter) {
  const epoch = BigInt(bootEpoch);
  const counter = BigInt(msgCounter);
  if (epoch < 0n || epoch > UINT32_MAX) throw new RangeError('boot_epoch must fit in a uint32');
  if (counter < 0n || counter > UINT32_MAX) throw new RangeError('msg_counter must fit in a uint32');
  return (epoch << 32n) | counter;
}

/**
 * @param {unknown} seq
 * @returns {bigint}
 */
function assertSeq(seq) {
  if (typeof seq !== 'bigint') throw new TypeError('seq must be a bigint');
  if (seq < 0n || seq > UINT64_MAX) throw new RangeError('seq must fit in a uint64');
  return seq;
}

function assertBytes(value, length, label) {
  if (!(value instanceof Uint8Array) || value.length !== length) {
    throw new TypeError(`${label} must be ${length} bytes`);
  }
  return value;
}

/** `seq` as 8 bytes big-endian: the tail of both the nonce and the AAD. */
export function seqToBytes(seq) {
  const bytes = new Uint8Array(SEQ_BYTES);
  new DataView(bytes.buffer).setBigUint64(0, assertSeq(seq), false);
  return bytes;
}

/**
 * `0x00000000 || seq`.
 *
 * The four leading zeroes are not padding for its own sake: they keep the nonce
 * at GCM's 96-bit width while leaving the whole of it a function of a counter
 * that only ever increases. There is no RNG in this construction and therefore
 * no RNG quality assumption, which is the entire reason design 7.2 chose it.
 *
 * @param {bigint} seq
 * @returns {Uint8Array} 12 bytes
 */
export function buildNonce(seq) {
  const nonce = new Uint8Array(NONCE_BYTES);
  nonce.set(seqToBytes(seq), NONCE_BYTES - SEQ_BYTES);
  return nonce;
}

/**
 * `version(1) || DEVICE_ID(16) || record_type(1) || seq(8)`.
 *
 * Authenticated but not encrypted, which is what lets the server verify a record
 * it cannot read. It is also why the record type stays out of it (see the module
 * comment): everything in the AAD is something the server gets to see.
 *
 * @param {Uint8Array} deviceId 16 bytes
 * @param {bigint} seq
 * @param {number} [recordType]
 * @returns {Uint8Array} 26 bytes
 */
export function buildRecordAad(deviceId, seq, recordType = RECORD_TYPE_V1) {
  assertBytes(deviceId, DEVICE_ID_BYTES, 'DEVICE_ID');
  if (!Number.isInteger(recordType) || recordType < 0 || recordType > 0xff) {
    throw new RangeError('record_type must be a single byte');
  }

  const aad = new Uint8Array(RECORD_AAD_BYTES);
  aad[0] = PROTOCOL_VERSION;
  aad.set(deviceId, 1);
  aad[1 + DEVICE_ID_BYTES] = recordType;
  aad.set(seqToBytes(seq), 2 + DEVICE_ID_BYTES);
  return aad;
}

/**
 * Exactly the bytes an Ed25519 signature covers: `AAD || nonce || ciphertext`.
 *
 * Sequence position, device identity and record type are all inside it, so a
 * server cannot move a valid record to a different device or a different point
 * in the sequence without the signature failing.
 *
 * @returns {Uint8Array}
 */
export function recordSigningInput(aad, nonce, ciphertext) {
  const message = new Uint8Array(aad.length + nonce.length + ciphertext.length);
  message.set(aad, 0);
  message.set(nonce, aad.length);
  message.set(ciphertext, aad.length + nonce.length);
  return message;
}

function importDataKey(dataKey, usages) {
  assertBytes(dataKey, DATA_KEY_BYTES, 'device_data_key');
  return crypto.subtle.importKey('raw', dataKey, 'AES-GCM', false, usages);
}

/**
 * Builds one record's `nonce` and `ciphertext` from a payload object.
 *
 * In the shipped product this direction runs on the device, not here. It is
 * exported because the test suite has to stand in for firmware that does not
 * exist on every port, and because the published vectors have to be produced by
 * the same code the client decrypts with rather than by a script beside it.
 *
 * @param {{ dataKey: Uint8Array, deviceId: Uint8Array, seq: bigint, payload: unknown,
 *          recordType?: number }} record
 * @returns {Promise<{ nonce: Uint8Array, ciphertext: Uint8Array, aad: Uint8Array }>}
 */
export async function encryptRecord({ dataKey, deviceId, seq, payload, recordType }) {
  const aad = buildRecordAad(deviceId, seq, recordType);
  const nonce = buildNonce(seq);
  const key = await importDataKey(dataKey, ['encrypt']);

  const sealed = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: GCM_TAG_BITS },
    key,
    encodeCbor(payload),
  );

  return { nonce, ciphertext: new Uint8Array(sealed), aad };
}

/**
 * Opens one record (roadmap 6.3).
 *
 * The nonce is checked against the `seq` before anything is decrypted, which is
 * the client's own copy of the server's check 3. The server having run it is not
 * a reason to skip it: this code has to hold when the server is the adversary,
 * and a nonce that disagrees with the sequence position it claims is the one
 * signal that a record has been moved.
 *
 * A wrong `device_data_key`, a tampered blob and a record relocated to another
 * device all surface here as the same refusal, because they mean the same thing
 * to a caller: this is not a record this device wrote at this position.
 *
 * @param {{ dataKey: Uint8Array, deviceId: Uint8Array, seq: bigint, nonce: Uint8Array,
 *          ciphertext: Uint8Array, recordType?: number }} record
 * @returns {Promise<unknown>} the decoded CBOR payload.
 */
export async function decryptRecord({ dataKey, deviceId, seq, nonce, ciphertext, recordType }) {
  assertBytes(nonce, NONCE_BYTES, 'nonce');
  if (!(ciphertext instanceof Uint8Array) || ciphertext.length <= GCM_TAG_BYTES) {
    throw new TypeError('ciphertext is too short to hold a GCM tag and a payload');
  }

  const expected = buildNonce(seq);
  if (!nonce.every((byte, index) => byte === expected[index])) {
    throw new Error(`record nonce does not match 0x00000000 || seq for seq ${seq}`);
  }

  const aad = buildRecordAad(deviceId, seq, recordType);
  const key = await importDataKey(dataKey, ['decrypt']);

  let plaintext;
  try {
    plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: GCM_TAG_BITS },
      key,
      ciphertext,
    );
  } catch (cause) {
    throw new Error(
      `record ${seq} would not open: wrong device_data_key, a different device, or a tampered blob`,
      { cause },
    );
  }

  return decodeCbor(new Uint8Array(plaintext));
}
