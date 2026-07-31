/**
 * Byte <-> text conversions.
 *
 * Binary values (keys, salts, ciphertext, DEVICE_ID) are `bytea` in Postgres and
 * base64url on the wire. Never hex, never standard base64 — one encoding means
 * one set of parsing bugs.
 */

const utf8Encoder = new TextEncoder();
const utf8Decoder = new TextDecoder();

/**
 * @param {string} text
 * @returns {Uint8Array}
 */
export function utf8Bytes(text) {
  return utf8Encoder.encode(text);
}

/**
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function utf8String(bytes) {
  return utf8Decoder.decode(bytes);
}

/**
 * base64url, unpadded (RFC 4648 §5).
 *
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function toBase64Url(bytes) {
  let binary = '';
  // Chunked so a large vault blob cannot blow the argument limit of fromCharCode.
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * @param {string} text base64url, with or without padding.
 * @returns {Uint8Array}
 */
export function fromBase64Url(text) {
  if (!/^[A-Za-z0-9_-]*={0,2}$/.test(text)) {
    throw new TypeError('fromBase64Url: input is not base64url');
  }
  const base64 = text.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/**
 * Constant-time-ish equality for byte arrays. Used in tests and anywhere a
 * comparison touches secret material; the branch-free loop keeps it from
 * short-circuiting on the first differing byte.
 *
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @returns {boolean}
 */
export function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
}
