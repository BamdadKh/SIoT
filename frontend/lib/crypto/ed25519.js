/**
 * Ed25519 from a 32-byte seed (design Section 5.1).
 *
 * The device's signing keypair is *derived*, not generated: both the browser (at
 * provisioning, to learn `device_sign_pub`) and the firmware (at every boot, to
 * sign) have to arrive at the same key from the same `ed25519_seed`. Web Crypto's
 * `generateKey` cannot do that, having no seed input, so the seed is wrapped in
 * the fixed 16-byte PKCS#8 preamble every Ed25519 private key shares and imported.
 *
 * The public half then comes back out via a JWK export, which is the only route
 * Web Crypto offers from a private key to its public bytes. That is why the
 * imported key is `extractable: true`: not laxness, but the mechanism. The seed
 * it was built from is already in the caller's hands, so extractability gives
 * away nothing that was not already given.
 *
 * No `@noble/ed25519` or `tweetnacl` dependency, for the same reason
 * `backend/src/lib/ed25519.ts` has none: the platform ships an audited
 * implementation, and a signing primitive is the last place to want a supply
 * chain. Ed25519 has landed in Web Crypto across Chromium, Firefox and Safari; a
 * browser without it fails loudly here rather than silently taking some other path.
 */

import { fromBase64Url } from './encoding.js';

/**
 * `SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.112 }, OCTET STRING { OCTET
 * STRING (32) } }`. The whole PKCS#8 wrapper for an Ed25519 private key is
 * constant apart from the seed, since the seed is the only variable-length-free
 * field in it. Checked against RFC 8032's test vectors rather than trusted by
 * construction: `test/ed25519.test.js` pins seed 1 to its published public key
 * and signature, so a wrong byte here fails the suite instead of producing a
 * plausible key that no device will ever agree with.
 */
const PKCS8_ED25519_PREAMBLE = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
  0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

export const ED25519_SEED_BYTES = 32;
export const ED25519_PUBLIC_KEY_BYTES = 32;
export const ED25519_SIGNATURE_BYTES = 64;

/**
 * @param {Uint8Array} seed
 * @returns {Promise<CryptoKey>}
 */
async function importSeed(seed) {
  if (!(seed instanceof Uint8Array) || seed.length !== ED25519_SEED_BYTES) {
    throw new TypeError(`ed25519 seed must be ${ED25519_SEED_BYTES} bytes`);
  }

  const pkcs8 = new Uint8Array(PKCS8_ED25519_PREAMBLE.length + ED25519_SEED_BYTES);
  pkcs8.set(PKCS8_ED25519_PREAMBLE, 0);
  pkcs8.set(seed, PKCS8_ED25519_PREAMBLE.length);

  try {
    return await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, true, ['sign']);
  } catch (cause) {
    throw new Error(
      'Ed25519 is unavailable in this browser: device provisioning cannot continue',
      { cause },
    );
  } finally {
    pkcs8.fill(0);
  }
}

/**
 * The 32 public bytes registered with the server as `sign_pub`. This is the only
 * half of the keypair the app ever needs: the browser derives it to register the
 * device and has no further use for signing authority, which belongs to the board.
 *
 * @param {Uint8Array} seed 32 bytes
 * @returns {Promise<Uint8Array>} 32 bytes.
 */
export async function ed25519PublicKeyFromSeed(seed) {
  const privateKey = await importSeed(seed);
  // `x` is base64url by JWK definition (RFC 7517), and is the only route Web
  // Crypto gives from a private key to its public bytes.
  const jwk = await crypto.subtle.exportKey('jwk', privateKey);

  const publicKey = fromBase64Url(jwk.x);
  if (publicKey.length !== ED25519_PUBLIC_KEY_BYTES) {
    throw new Error(`derived sign_pub is ${publicKey.length} bytes, expected 32`);
  }
  return publicKey;
}

/**
 * Signs with a seed-derived key.
 *
 * Nothing in `frontend/app/` calls this and nothing should: signing is what
 * `device_sign_priv` confers, and it lives on the device (design 5.1, 9.1). It is
 * exported so `node --test` can prove the browser's derivation produces a key the
 * server's verifier accepts, and so a stand-in script can impersonate firmware
 * that does not exist yet. An app screen importing it would be the bug.
 *
 * @param {Uint8Array} seed 32 bytes
 * @param {Uint8Array} message
 * @returns {Promise<Uint8Array>} 64 bytes.
 */
export async function ed25519Sign(seed, message) {
  const privateKey = await importSeed(seed);
  const signature = await crypto.subtle.sign({ name: 'Ed25519' }, privateKey, message);
  return new Uint8Array(signature);
}
