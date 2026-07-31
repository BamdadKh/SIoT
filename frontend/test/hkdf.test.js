// Roadmap 1.2 — HKDF domain separation.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { hkdfSha256, deriveLoginKey, deriveKek, HKDF_INFO } from '../lib/crypto/hkdf.js';
import { deriveAccountKeys } from '../lib/crypto/index.js';
import { bytesEqual, fromBase64Url } from '../lib/crypto/encoding.js';

const MASTER_KEY = fromBase64Url('AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8');
const SALT = fromBase64Url('AAECAwQFBgcICQoLDA0ODw');

test('login_key and kek differ despite sharing a master_key', async () => {
  const loginKey = await deriveLoginKey(MASTER_KEY);
  const kek = await deriveKek(MASTER_KEY);

  assert.equal(loginKey.length, 32);
  assert.equal(kek.length, 32);
  assert.ok(!bytesEqual(loginKey, kek), 'domain separation failed — info labels collided');
});

test('derivation is deterministic', async () => {
  assert.ok(bytesEqual(await deriveLoginKey(MASTER_KEY), await deriveLoginKey(MASTER_KEY)));
  assert.ok(bytesEqual(await deriveKek(MASTER_KEY), await deriveKek(MASTER_KEY)));
});

test('the info labels are the ones the design specifies', async () => {
  assert.equal(HKDF_INFO.LOGIN_KEY, 'siot/auth/v1');
  assert.equal(HKDF_INFO.KEK, 'siot/kek/v1');

  assert.ok(bytesEqual(await deriveLoginKey(MASTER_KEY), await hkdfSha256(MASTER_KEY, 'siot/auth/v1')));
  assert.ok(bytesEqual(await deriveKek(MASTER_KEY), await hkdfSha256(MASTER_KEY, 'siot/kek/v1')));
});

test('a one-character change to the label changes the output completely', async () => {
  const real = await hkdfSha256(MASTER_KEY, 'siot/kek/v1');
  const typo = await hkdfSha256(MASTER_KEY, 'siot/kek/v2');

  assert.ok(!bytesEqual(real, typo));
});

test('requires an info label', async () => {
  await assert.rejects(() => hkdfSha256(MASTER_KEY, ''), TypeError);
  await assert.rejects(() => hkdfSha256(new Uint8Array(0), 'siot/kek/v1'), TypeError);
});

test('deriveAccountKeys matches the step-by-step path', async () => {
  const { deriveMasterKey } = await import('../lib/crypto/argon2.js');
  const masterKey = await deriveMasterKey('a plain enough password', SALT);
  const expectedLogin = await deriveLoginKey(masterKey);
  const expectedKek = await deriveKek(masterKey);

  const { loginKey, kek } = await deriveAccountKeys('a plain enough password', SALT);

  assert.ok(bytesEqual(loginKey, expectedLogin));
  assert.ok(bytesEqual(kek, expectedKek));
});
