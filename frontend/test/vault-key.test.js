// Roadmap 1.3 — vault_key generation and wrapping.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  generateVaultKey,
  wrapVaultKey,
  unwrapVaultKey,
  VAULT_KEY_BYTES,
} from '../lib/crypto/vault-key.js';
import { randomBytes } from '../lib/crypto/random.js';
import { bytesEqual } from '../lib/crypto/encoding.js';

const KEK = randomBytes(32);
const OTHER_KEK = randomBytes(32);

test('vault_key is 32 random bytes and never repeats', () => {
  const a = generateVaultKey();
  const b = generateVaultKey();

  assert.equal(a.length, VAULT_KEY_BYTES);
  assert.ok(!bytesEqual(a, b));
});

test('wrap then unwrap round-trips', async () => {
  const vaultKey = generateVaultKey();
  const wrapped = await wrapVaultKey(vaultKey, KEK);
  const recovered = await unwrapVaultKey(wrapped, KEK);

  assert.ok(bytesEqual(recovered, vaultKey));
});

test('wrapped blob is iv(12) + ciphertext(32) + tag(16) and leaks nothing', async () => {
  const vaultKey = generateVaultKey();
  const wrapped = await wrapVaultKey(vaultKey, KEK);

  assert.equal(wrapped.length, 12 + 32 + 16);
  // The plaintext key must not appear anywhere in what the server receives.
  const asString = Array.from(wrapped).join(',');
  assert.ok(!asString.includes(Array.from(vaultKey).join(',')));
});

test('same key wrapped twice yields different blobs (fresh IV each time)', async () => {
  const vaultKey = generateVaultKey();
  const first = await wrapVaultKey(vaultKey, KEK);
  const second = await wrapVaultKey(vaultKey, KEK);

  assert.ok(!bytesEqual(first, second), 'IV reuse — catastrophic under AES-GCM');
  assert.ok(!bytesEqual(first.subarray(0, 12), second.subarray(0, 12)));
});

test('unwrap fails loudly with the wrong kek', async () => {
  const wrapped = await wrapVaultKey(generateVaultKey(), KEK);

  await assert.rejects(() => unwrapVaultKey(wrapped, OTHER_KEK), /unwrap failed/);
});

test('unwrap fails if the blob is tampered with', async () => {
  const wrapped = await wrapVaultKey(generateVaultKey(), KEK);

  for (const index of [0, 12, wrapped.length - 1]) {
    const tampered = Uint8Array.from(wrapped);
    tampered[index] ^= 0x01;
    await assert.rejects(() => unwrapVaultKey(tampered, KEK), /unwrap failed/);
  }
});

test('unwrap rejects a blob with a foreign AAD', async () => {
  // A blob encrypted under the same kek but for a different purpose must not be
  // accepted here — that is exactly the slot-swap AAD is there to prevent.
  const key = await crypto.subtle.importKey('raw', KEK, 'AES-GCM', false, ['encrypt']);
  const iv = randomBytes(12);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: new TextEncoder().encode('siot/some-other-blob/v1') },
    key,
    generateVaultKey(),
  );
  const foreign = new Uint8Array(12 + ciphertext.byteLength);
  foreign.set(iv, 0);
  foreign.set(new Uint8Array(ciphertext), 12);

  await assert.rejects(() => unwrapVaultKey(foreign, KEK), /unwrap failed/);
});

test('rejects malformed inputs', async () => {
  await assert.rejects(() => wrapVaultKey(randomBytes(16), KEK), TypeError);
  await assert.rejects(() => wrapVaultKey(generateVaultKey(), randomBytes(16)), TypeError);
  await assert.rejects(() => unwrapVaultKey(randomBytes(8), KEK), TypeError);
});
