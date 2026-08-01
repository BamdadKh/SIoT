/**
 * base64url on the wire, `bytea` in the database (never hex — one encoding means
 * one set of parsing bugs).
 *
 * The server treats every one of these values as an opaque blob. Decoding here is
 * about shape validation, not interpretation: a 60-byte wrapped_vault_key is
 * checked for being 60 bytes and then stored untouched.
 */

import { Type } from '@sinclair/typebox';

/** Unpadded base64url length for a fixed byte count (RFC 4648 §5). */
function encodedLength(byteLength: number): number {
  return Math.ceil((byteLength * 4) / 3);
}

/**
 * A JSON Schema string that can only be a base64url encoding of exactly
 * `byteLength` bytes. Fixing the character count in the pattern means an
 * over-long blob is rejected by Fastify's validator before it reaches a handler.
 */
export function Base64UrlBytes(byteLength: number, description: string) {
  const chars = encodedLength(byteLength);
  return Type.String({
    pattern: `^[A-Za-z0-9_-]{${chars}}$`,
    description: `${description}: ${byteLength} bytes base64url (unpadded)`,
  });
}

/**
 * The same, for a value whose length is genuinely variable — currently only the
 * vault blob. The character count cannot pin the byte count here, so the pattern
 * only constrains the alphabet and the real bound is asserted after decoding by
 * `decodeBase64UrlRange`. `maxLength` still matters: it stops a multi-megabyte
 * string from being decoded at all.
 */
export function Base64UrlVariableBytes(
  minBytes: number,
  maxBytes: number,
  description: string,
) {
  return Type.String({
    pattern: '^[A-Za-z0-9_-]+$',
    minLength: encodedLength(minBytes),
    maxLength: encodedLength(maxBytes),
    description: `${description}: ${minBytes}-${maxBytes} bytes base64url (unpadded)`,
  });
}

/**
 * `Buffer.from(s, 'base64url')` silently skips characters it does not
 * understand, so a malformed string decodes to something short rather than
 * throwing. The length assertion is what turns that into an error. Schema
 * validation should already have caught it; this is the belt to that's braces.
 */
export function decodeBase64Url(text: string, expectedBytes: number): Buffer {
  const bytes = Buffer.from(text, 'base64url');
  if (bytes.length !== expectedBytes) {
    throw new Error(`expected ${expectedBytes} bytes, decoded ${bytes.length}`);
  }
  return bytes;
}

/** As above, for a variable-length value. Returns the decoded bytes or throws. */
export function decodeBase64UrlRange(text: string, minBytes: number, maxBytes: number): Buffer {
  const bytes = Buffer.from(text, 'base64url');
  if (bytes.length < minBytes || bytes.length > maxBytes) {
    throw new Error(`expected ${minBytes}-${maxBytes} bytes, decoded ${bytes.length}`);
  }
  return bytes;
}

export function encodeBase64Url(bytes: Buffer | Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}
