import test from 'node:test';
import assert from 'node:assert/strict';
import { createPublicKey, verify as nodeVerify } from 'node:crypto';

import {
  buildNonce,
  buildRecordAad,
  composeSeq,
  decryptRecord,
  encryptRecord,
  recordSigningInput,
  seqToBytes,
  RECORD_AAD_BYTES,
} from '../lib/crypto/record.js';
import { deriveDeviceDataKey, deriveDeviceSignSeed } from '../lib/crypto/device.js';
import { ed25519PublicKeyFromSeed, ed25519Sign } from '../lib/crypto/ed25519.js';
import { randomBytes } from '../lib/crypto/random.js';

const hex = (bytes) => Buffer.from(bytes).toString('hex');

const DEVICE_ID = Uint8Array.from({ length: 16 }, (_, i) => 0xa0 + i);
const DATA_KEY = Uint8Array.from({ length: 32 }, (_, i) => i);

test('seq is composed as (boot_epoch << 32) | msg_counter, in BigInt throughout', () => {
  assert.equal(composeSeq(0, 0), 0n);
  assert.equal(composeSeq(1, 0), 4294967296n);
  assert.equal(composeSeq(1, 1), 4294967297n);
  // Past 2^21 the composed value is no longer exactly representable as a double,
  // which is the case a port that reached for a float gets silently wrong.
  assert.equal(composeSeq(4000000, 7), 17179869184000007n);
  assert.ok(composeSeq(4000000, 7) > BigInt(Number.MAX_SAFE_INTEGER));
  assert.equal(composeSeq(0xffffffff, 0xffffffff), (1n << 64n) - 1n);

  assert.throws(() => composeSeq(-1, 0), /boot_epoch/);
  assert.throws(() => composeSeq(0, 2 ** 32), /msg_counter/);
});

test('the nonce is four zero bytes then the seq, big-endian', () => {
  assert.equal(hex(buildNonce(0n)), '000000000000000000000000');
  assert.equal(hex(buildNonce(1n)), '000000000000000000000001');
  assert.equal(hex(buildNonce(composeSeq(1, 0))), '000000000000000100000000');
  assert.equal(hex(buildNonce((1n << 64n) - 1n)), '00000000ffffffffffffffff');
  assert.equal(hex(seqToBytes(composeSeq(2, 3))), '0000000200000003');
});

test('the AAD is version, DEVICE_ID, record_type and seq, in that order', () => {
  const aad = buildRecordAad(DEVICE_ID, composeSeq(1, 0));
  assert.equal(aad.length, RECORD_AAD_BYTES);
  assert.equal(aad.length, 26);
  assert.equal(hex(aad), '01' + hex(DEVICE_ID) + '00' + '0000000100000000');
});

test('a record round-trips through encrypt and decrypt', async () => {
  const payload = { t: 1786000000, r: { temp_c: 21.5, humidity: 48 } };
  const seq = composeSeq(3, 12);

  const { nonce, ciphertext } = await encryptRecord({
    dataKey: DATA_KEY,
    deviceId: DEVICE_ID,
    seq,
    payload,
  });

  const opened = await decryptRecord({
    dataKey: DATA_KEY,
    deviceId: DEVICE_ID,
    seq,
    nonce,
    ciphertext,
  });
  assert.deepEqual(opened, payload);
});

test('AES-GCM with a counter nonce is deterministic, so the same record is the same bytes', async () => {
  // Not a property to rely on, but the reason the published vectors can exist at
  // all: there is no IV to vary, because the nonce is a function of the seq.
  const payload = { t: 1, r: { a: 1 } };
  const first = await encryptRecord({ dataKey: DATA_KEY, deviceId: DEVICE_ID, seq: 5n, payload });
  const second = await encryptRecord({ dataKey: DATA_KEY, deviceId: DEVICE_ID, seq: 5n, payload });
  assert.equal(hex(first.ciphertext), hex(second.ciphertext));
});

test('a record will not open under the wrong key, device, seq or nonce', async () => {
  const seq = composeSeq(2, 1);
  const { nonce, ciphertext } = await encryptRecord({
    dataKey: DATA_KEY,
    deviceId: DEVICE_ID,
    seq,
    payload: { t: 1, r: { a: 1 } },
  });

  const otherKey = randomBytes(32);
  await assert.rejects(
    decryptRecord({ dataKey: otherKey, deviceId: DEVICE_ID, seq, nonce, ciphertext }),
    /would not open/,
  );

  // The AAD binds the device, so a record relocated to another device's id is
  // refused rather than decrypted into the wrong dashboard.
  const otherDevice = Uint8Array.from(DEVICE_ID, (byte) => byte ^ 0xff);
  await assert.rejects(
    decryptRecord({ dataKey: DATA_KEY, deviceId: otherDevice, seq, nonce, ciphertext }),
    /would not open/,
  );

  // And it binds the sequence position, so a record cannot be replayed into a
  // different slot even by a server that holds every blob.
  await assert.rejects(
    decryptRecord({ dataKey: DATA_KEY, deviceId: DEVICE_ID, seq: seq + 1n, nonce, ciphertext }),
    /nonce does not match/,
  );

  const tampered = Uint8Array.from(ciphertext);
  tampered[0] ^= 1;
  await assert.rejects(
    decryptRecord({ dataKey: DATA_KEY, deviceId: DEVICE_ID, seq, nonce, ciphertext: tampered }),
    /would not open/,
  );
});

test('a nonce that disagrees with the seq is caught before any decryption is attempted', async () => {
  const seq = composeSeq(1, 1);
  const { ciphertext } = await encryptRecord({
    dataKey: DATA_KEY,
    deviceId: DEVICE_ID,
    seq,
    payload: { t: 1, r: {} },
  });

  // The server runs this check too (design 7.4, check 3). The client runs its
  // own because the server is the party this is defending against.
  const wrong = buildNonce(seq + 100n);
  await assert.rejects(
    decryptRecord({ dataKey: DATA_KEY, deviceId: DEVICE_ID, seq, nonce: wrong, ciphertext }),
    /nonce does not match/,
  );
});

test('what the device signs verifies as the server verifies it', async () => {
  // The whole chain in one test, in the same order firmware runs it: derive both
  // keys from one DEVICE_SECRET, encrypt, sign AAD||nonce||ciphertext, and then
  // verify through Node's own Ed25519 exactly as `backend/src/lib/ed25519.ts`
  // does. If this passes, a record built by this code is one the server accepts.
  const deviceSecret = randomBytes(32);
  const dataKey = await deriveDeviceDataKey(deviceSecret);
  const signSeed = await deriveDeviceSignSeed(deviceSecret);
  const signPub = await ed25519PublicKeyFromSeed(signSeed);

  const seq = composeSeq(9, 4);
  const { nonce, ciphertext, aad } = await encryptRecord({
    dataKey,
    deviceId: DEVICE_ID,
    seq,
    payload: { t: 1786000000, r: { lux: 812 } },
  });

  const message = recordSigningInput(aad, nonce, ciphertext);
  assert.equal(message.length, aad.length + nonce.length + ciphertext.length);

  const signature = await ed25519Sign(signSeed, message);
  const publicKey = createPublicKey({
    key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(signPub).toString('base64url') },
    format: 'jwk',
  });

  assert.equal(nodeVerify(null, message, publicKey, signature), true);

  // And the same signature over a message with one byte moved does not verify,
  // so the check above is testing something.
  const moved = Uint8Array.from(message);
  moved[0] ^= 1;
  assert.equal(nodeVerify(null, moved, publicKey, signature), false);
});
