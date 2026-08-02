/**
 * Ed25519 signature verification (design Section 7.4, check 1).
 *
 * Node's `crypto` module has verified Ed25519 natively since v12 but only takes
 * a `KeyObject`, not raw bytes, so a raw 32-byte `sign_pub` needs wrapping before
 * `crypto.verify` can use it. JWK is the shortest path to that: an Ed25519 public
 * key's JWK form is just `{ kty: 'OKP', crv: 'Ed25519', x: <the same 32 bytes> }`,
 * so no DER/ASN.1 construction and no extra dependency (`tweetnacl`, `@noble/ed25519`)
 * for something the platform already implements and has audited.
 */

import { createPublicKey, verify } from 'node:crypto';

export function verifyEd25519(signPub: Buffer, message: Buffer, signature: Buffer): boolean {
  const key = createPublicKey({
    key: { kty: 'OKP', crv: 'Ed25519', x: signPub.toString('base64url') },
    format: 'jwk',
  });
  // Ed25519 is a one-shot signature scheme (it hashes internally), so the
  // algorithm argument is null rather than e.g. 'sha256' — there is no
  // incremental `update()` the way there is for RSA/ECDSA.
  return verify(null, message, key, signature);
}
