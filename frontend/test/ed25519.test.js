// Roadmap 4.1: Ed25519 from a seed, the primitive device signing keys are built on.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createPublicKey, verify } from 'node:crypto';

import {
  ed25519PublicKeyFromSeed,
  ed25519Sign,
  ED25519_PUBLIC_KEY_BYTES,
  ED25519_SIGNATURE_BYTES,
} from '../lib/crypto/ed25519.js';
import { randomBytes } from '../lib/crypto/random.js';
import { bytesEqual, toBase64Url, fromBase64Url } from '../lib/crypto/encoding.js';

/**
 * RFC 8032 section 7.1, TEST 1. Pinned for the same reason argon2.test.js pins a
 * known-answer vector: the PKCS#8 preamble in `ed25519.js` is 16 hand-written
 * bytes, and a wrong one there would still import cleanly and produce a
 * confident, useless key that no firmware would ever agree with.
 */
const RFC8032_TEST_1 = {
  seed: 'nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A',
  publicKey: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
  emptyMessageSignature:
    '5VZDAMNgrHKQhuLMgG6CioSHfx645dl02HPgZSJJAVVfuIIVkKM7rMYeOXAc-bRr0lv18FlbviRlUUFDjnoQCw',
};

test('a known seed produces the RFC 8032 public key', async () => {
  const publicKey = await ed25519PublicKeyFromSeed(fromBase64Url(RFC8032_TEST_1.seed));

  assert.equal(publicKey.length, ED25519_PUBLIC_KEY_BYTES);
  assert.equal(toBase64Url(publicKey), RFC8032_TEST_1.publicKey);
});

test('signing matches the RFC 8032 vector, so this is pure Ed25519', async () => {
  // Pins the scheme itself, not just the preamble: Ed25519ph or a context-string
  // variant would derive the same public key and produce a different signature,
  // and the disagreement would surface as an unexplained 401 from `POST /records`.
  const signature = await ed25519Sign(fromBase64Url(RFC8032_TEST_1.seed), new Uint8Array(0));

  assert.equal(toBase64Url(signature), RFC8032_TEST_1.emptyMessageSignature);
});

test('the same seed always produces the same public key', async () => {
  const seed = randomBytes(32);
  const first = await ed25519PublicKeyFromSeed(seed);
  const second = await ed25519PublicKeyFromSeed(seed);

  assert.ok(bytesEqual(first, second));
});

test('different seeds produce different public keys', async () => {
  const a = await ed25519PublicKeyFromSeed(randomBytes(32));
  const b = await ed25519PublicKeyFromSeed(randomBytes(32));

  assert.ok(!bytesEqual(a, b));
});

test('a signature verifies against the derived public key', async () => {
  const seed = randomBytes(32);
  const publicKey = await ed25519PublicKeyFromSeed(seed);
  const message = randomBytes(64);

  const signature = await ed25519Sign(seed, message);
  assert.equal(signature.length, ED25519_SIGNATURE_BYTES);

  // Verified through Node's `crypto.verify` with a JWK-reconstructed key, which
  // is byte for byte what `backend/src/lib/ed25519.ts` does with a registered
  // `sign_pub`. So this asserts the real property: what the browser derives is
  // what the server will accept.
  const asServerSeesIt = createPublicKey({
    key: { kty: 'OKP', crv: 'Ed25519', x: toBase64Url(publicKey) },
    format: 'jwk',
  });
  assert.ok(verify(null, message, asServerSeesIt, signature));

  const tampered = Uint8Array.from(message);
  tampered[0] ^= 0x01;
  assert.ok(!verify(null, tampered, asServerSeesIt, signature));
});

test('rejects a seed that is not 32 bytes', async () => {
  await assert.rejects(() => ed25519PublicKeyFromSeed(randomBytes(31)), TypeError);
  await assert.rejects(() => ed25519PublicKeyFromSeed(randomBytes(33)), TypeError);
  await assert.rejects(() => ed25519Sign('not bytes', randomBytes(8)), TypeError);
});
