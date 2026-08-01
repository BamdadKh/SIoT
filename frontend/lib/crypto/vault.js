/**
 * Vault *contents* encryption (design Sections 2.2 and 8).
 *
 * Not to be confused with `vault-key.js`, which seals the 32-byte `vault_key`
 * under the password-derived `kek`. This module is one level down: it seals the
 * vault document — device secrets, schemas, layout — under that `vault_key`.
 * The indirection is why a password change re-wraps 32 bytes instead of
 * re-encrypting and re-uploading everything.
 *
 * v1 granularity is one blob per user (design Section 15.6 keeps that open).
 * Every write replaces the whole document and bumps `vault_version`.
 *
 * The version is bound in two independent places, which is not redundancy for
 * its own sake:
 *
 *   in the AAD       so the server cannot serve version 3's blob while claiming
 *                    it is version 7 — the AAD no longer matches and GCM refuses
 *                    to open it at all.
 *   in the plaintext so the version survives independently of whatever the
 *                    caller passed in. A mismatch between the two is a named
 *                    error rather than a bare authentication failure, which is
 *                    the difference between "the server rolled you back" and
 *                    "something is broken somewhere".
 *
 * Neither catches a *consistent* rollback — old blob served with its own old
 * version. That is what the client's cached high-water mark is for, and it lives
 * with the caller because it needs storage this module has no business touching.
 */

import { utf8Bytes, utf8String } from './encoding.js';
import { randomBytes } from './random.js';

const IV_BYTES = 12;
const TAG_BYTES = 16;
const GCM_TAG_BITS = 128;
const VERSION_BYTES = 8;

/** Smallest possible blob: iv + tag + a one-byte plaintext that cannot exist. */
export const VAULT_BLOB_OVERHEAD_BYTES = IV_BYTES + TAG_BYTES;

const AAD_LABEL = utf8Bytes('siot/vault/v1');

/**
 * `"siot/vault/v1" || version` as a big-endian uint64.
 *
 * Deliberately not bound to the username or user id: a username must stay
 * changeable, and the user id is the server's own identifier — binding to it
 * would let a server rename a row and invalidate a vault it cannot read.
 *
 * @param {number} version
 * @returns {Uint8Array}
 */
function vaultAad(version) {
  const aad = new Uint8Array(AAD_LABEL.length + VERSION_BYTES);
  aad.set(AAD_LABEL, 0);
  new DataView(aad.buffer).setBigUint64(AAD_LABEL.length, BigInt(version), false);
  return aad;
}

/**
 * @param {unknown} version
 * @returns {number}
 */
function assertVersion(version) {
  if (!Number.isSafeInteger(version) || version < 0) {
    throw new TypeError('vault version must be a non-negative safe integer');
  }
  return version;
}

/**
 * @param {Uint8Array} keyBytes
 * @param {KeyUsage[]} usages
 * @returns {Promise<CryptoKey>}
 */
function importVaultKey(keyBytes, usages) {
  if (!(keyBytes instanceof Uint8Array) || keyBytes.length !== 32) {
    throw new TypeError('vault_key must be 32 bytes');
  }
  return crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, usages);
}

/**
 * Seals a vault document at a given version. Output is `iv(12) || ct || tag(16)`,
 * which the server stores as an opaque blob.
 *
 * A random IV is safe here for the same reason it is in `vault-key.js`: a given
 * `vault_key` encrypts once per vault write, a number that stays in the
 * thousands over an account's life, nowhere near the birthday bound on 96 bits.
 * A device emitting records forever is the case that needs a counter (Section 7.2).
 *
 * The ciphertext length still reveals roughly how large the vault is, and so how
 * many devices an account has. That is accepted metadata leakage, not an
 * oversight — padding it would be a Section 9.4-style opt-in, and there is
 * nothing to opt in to yet.
 *
 * @param {unknown} contents JSON-serialisable vault document.
 * @param {Uint8Array} vaultKey 32 bytes
 * @param {number} version the version this write will become, i.e. current + 1.
 * @returns {Promise<Uint8Array>}
 */
export async function encryptVault(contents, vaultKey, version) {
  assertVersion(version);

  const key = await importVaultKey(vaultKey, ['encrypt']);
  const plaintext = utf8Bytes(JSON.stringify({ version, contents }));
  const iv = randomBytes(IV_BYTES);

  const sealed = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: vaultAad(version), tagLength: GCM_TAG_BITS },
    key,
    plaintext,
  );

  const blob = new Uint8Array(IV_BYTES + sealed.byteLength);
  blob.set(iv, 0);
  blob.set(new Uint8Array(sealed), IV_BYTES);
  return blob;
}

/**
 * Opens a vault blob the server claims is at `version`, and returns the document.
 *
 * Throws if the blob was written at a different version, was tampered with, or
 * was produced under a different `vault_key`. All three mean the same thing to a
 * caller — do not trust this vault — so none of them is recoverable.
 *
 * @param {Uint8Array} blob
 * @param {Uint8Array} vaultKey 32 bytes
 * @param {number} version the version the server says this blob is.
 * @returns {Promise<unknown>} the vault document.
 */
export async function decryptVault(blob, vaultKey, version) {
  assertVersion(version);
  if (!(blob instanceof Uint8Array) || blob.length <= VAULT_BLOB_OVERHEAD_BYTES) {
    throw new TypeError('vault blob is too short to contain an IV, a tag and a document');
  }

  const key = await importVaultKey(vaultKey, ['decrypt']);

  let plaintext;
  try {
    plaintext = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: blob.subarray(0, IV_BYTES),
        additionalData: vaultAad(version),
        tagLength: GCM_TAG_BITS,
      },
      key,
      blob.subarray(IV_BYTES),
    );
  } catch (cause) {
    // Web Crypto throws a bare OperationError. The most likely cause by far is
    // the server handing back a blob from a different version than it claimed,
    // so say that — it is a far more useful starting point than "decrypt failed".
    throw new Error(
      `vault decrypt failed at version ${version}: wrong vault_key, wrong version or a tampered blob`,
      { cause },
    );
  }

  let envelope;
  try {
    envelope = JSON.parse(utf8String(new Uint8Array(plaintext)));
  } catch (cause) {
    throw new Error('vault decrypted but is not valid JSON', { cause });
  }

  // Unreachable short of a bug on the writing side: the AAD already pinned the
  // version, so anything that got this far was sealed under this exact number.
  // Checked anyway, because the inner copy is the one Section 8 calls
  // authoritative and a silent disagreement between them is not something to
  // discover later from a rollback that went unnoticed.
  if (envelope?.version !== version) {
    throw new Error(
      `vault version mismatch: server claimed ${version}, blob says ${envelope?.version}`,
    );
  }

  return envelope.contents;
}
