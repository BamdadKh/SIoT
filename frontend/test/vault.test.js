// Roadmap 3.1 — vault contents sealed under vault_key, with the version bound in.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { encryptVault, decryptVault } from '../lib/crypto/vault.js';
import { generateVaultKey } from '../lib/crypto/vault-key.js';
import { randomBytes } from '../lib/crypto/random.js';
import { bytesEqual, utf8Bytes } from '../lib/crypto/encoding.js';

const VAULT_KEY = generateVaultKey();
const OTHER_VAULT_KEY = generateVaultKey();

const DOCUMENT = {
  devices: [
    { device_id: 'zVQ7v3Y5RGuWq0hK1nJv8w', label: 'greenhouse', secret: 'not really a secret' },
  ],
};

test('encrypt then decrypt round-trips the document', async () => {
  const blob = await encryptVault(DOCUMENT, VAULT_KEY, 1);
  const recovered = await decryptVault(blob, VAULT_KEY, 1);

  assert.deepEqual(recovered, DOCUMENT);
});

test('blob is iv(12) || ciphertext || tag(16) and carries no plaintext', async () => {
  const blob = await encryptVault(DOCUMENT, VAULT_KEY, 1);
  const plaintext = utf8Bytes(JSON.stringify({ version: 1, contents: DOCUMENT }));

  assert.equal(blob.length, 12 + plaintext.length + 16);
  // Anything recognisable from the document appearing in what the server
  // receives would mean the ciphertext is not actually covering it.
  const asString = Buffer.from(blob).toString('latin1');
  assert.ok(!asString.includes('greenhouse'));
  assert.ok(!asString.includes('device_id'));
});

test('the same document at the same version encrypts differently each time', async () => {
  const first = await encryptVault(DOCUMENT, VAULT_KEY, 4);
  const second = await encryptVault(DOCUMENT, VAULT_KEY, 4);

  assert.ok(!bytesEqual(first, second), 'IV reuse — catastrophic under AES-GCM');
  assert.ok(!bytesEqual(first.subarray(0, 12), second.subarray(0, 12)));
});

test('decrypt refuses another user’s vault_key', async () => {
  const blob = await encryptVault(DOCUMENT, VAULT_KEY, 1);

  await assert.rejects(() => decryptVault(blob, OTHER_VAULT_KEY, 1), /vault decrypt failed/);
});

test('a blob served under a different version will not open', async () => {
  // This is the rollback the AAD catches: the server keeps blob v3 but tells the
  // client it is v7, hoping the client cannot tell. It cannot even read it.
  const blob = await encryptVault(DOCUMENT, VAULT_KEY, 3);

  for (const claimed of [0, 2, 4, 7]) {
    await assert.rejects(() => decryptVault(blob, VAULT_KEY, claimed), /vault decrypt failed/);
  }
  assert.deepEqual(await decryptVault(blob, VAULT_KEY, 3), DOCUMENT);
});

test('decrypt fails on a tampered blob', async () => {
  const blob = await encryptVault(DOCUMENT, VAULT_KEY, 2);

  for (const index of [0, 12, blob.length - 1]) {
    const tampered = Uint8Array.from(blob);
    tampered[index] ^= 0x01;
    await assert.rejects(() => decryptVault(tampered, VAULT_KEY, 2), /vault decrypt failed/);
  }
});

test('an inner version disagreeing with the outer one is a named error', async () => {
  // Forged by hand: correct AAD for version 5, but an envelope claiming 5000.
  // Unreachable through encryptVault, which is the point — if the two copies
  // ever disagree in the field, the client says so rather than trusting one.
  const key = await crypto.subtle.importKey('raw', VAULT_KEY, 'AES-GCM', false, ['encrypt']);
  const aad = new Uint8Array(utf8Bytes('siot/vault/v1').length + 8);
  aad.set(utf8Bytes('siot/vault/v1'), 0);
  new DataView(aad.buffer).setBigUint64(utf8Bytes('siot/vault/v1').length, 5n, false);

  const iv = randomBytes(12);
  const sealed = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: aad },
    key,
    utf8Bytes(JSON.stringify({ version: 5000, contents: DOCUMENT })),
  );
  const forged = new Uint8Array(12 + sealed.byteLength);
  forged.set(iv, 0);
  forged.set(new Uint8Array(sealed), 12);

  await assert.rejects(
    () => decryptVault(forged, VAULT_KEY, 5),
    /version mismatch: server claimed 5, blob says 5000/,
  );
});

test('an empty document still round-trips', async () => {
  // The state a fresh account writes on its very first save.
  const blob = await encryptVault({ devices: [] }, VAULT_KEY, 1);

  assert.deepEqual(await decryptVault(blob, VAULT_KEY, 1), { devices: [] });
});

test('rejects malformed inputs', async () => {
  await assert.rejects(() => encryptVault(DOCUMENT, randomBytes(16), 1), TypeError);
  await assert.rejects(() => encryptVault(DOCUMENT, VAULT_KEY, -1), TypeError);
  await assert.rejects(() => encryptVault(DOCUMENT, VAULT_KEY, 1.5), TypeError);
  await assert.rejects(() => decryptVault(randomBytes(20), VAULT_KEY, 1), TypeError);
});
