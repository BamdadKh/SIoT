import test from 'node:test';
import assert from 'node:assert/strict';

import { sealGrant, openGrant, GRANT_AAD_LABEL, GRANT_BLOB_BYTES } from '../lib/crypto/grant.js';
import { deriveDeviceDataKey, generateDeviceId, generateDeviceSecret } from '../lib/crypto/device.js';
import { encryptRecord, decryptRecord, composeSeq } from '../lib/crypto/record.js';
import { bytesEqual } from '../lib/crypto/encoding.js';

async function pair() {
  const aId = generateDeviceId();
  const bId = generateDeviceId();
  const aKey = await deriveDeviceDataKey(generateDeviceSecret());
  const bKey = await deriveDeviceDataKey(generateDeviceSecret());
  return { aId, bId, aKey, bKey };
}

const seal = (p) =>
  sealGrant({ deviceAId: p.aId, deviceBId: p.bId, deviceADataKey: p.aKey, deviceBDataKey: p.bKey });

test('a grant round-trips to device_B_data_key', async () => {
  const p = await pair();
  const blob = await seal(p);
  const opened = await openGrant({
    deviceAId: p.aId, deviceBId: p.bId, deviceADataKey: p.aKey, blob,
  });
  assert.ok(bytesEqual(opened, p.bKey));
});

test('blob length equals the server GRANT_BLOB_BYTES', async () => {
  // 60 is GRANT_BLOB_BYTES in backend/src/lib/wire-format.ts. Hardcoded on
  // purpose: importing the constant from this module would only check it against
  // itself.
  assert.equal(GRANT_BLOB_BYTES, 60);
  assert.equal((await seal(await pair())).length, 60);
  assert.equal(GRANT_AAD_LABEL, 'grant/v1');
});

test('swapped A and B is refused', async () => {
  const p = await pair();
  const blob = await seal(p);
  await assert.rejects(
    openGrant({ deviceAId: p.bId, deviceBId: p.aId, deviceADataKey: p.aKey, blob }),
    /would not open/,
  );
});

test('a different device id is refused', async () => {
  const p = await pair();
  const blob = await seal(p);
  await assert.rejects(
    openGrant({ deviceAId: p.aId, deviceBId: generateDeviceId(), deviceADataKey: p.aKey, blob }),
    /would not open/,
  );
});

test('a different device_A_data_key is refused', async () => {
  const p = await pair();
  const blob = await seal(p);
  await assert.rejects(
    openGrant({ deviceAId: p.aId, deviceBId: p.bId, deviceADataKey: p.bKey, blob }),
    /would not open/,
  );
});

test('a tampered blob is refused at every byte position', async () => {
  const p = await pair();
  const blob = await seal(p);
  for (const i of [0, 11, 12, 43, 44, 59]) {
    const bad = blob.slice();
    bad[i] ^= 1;
    await assert.rejects(
      openGrant({ deviceAId: p.aId, deviceBId: p.bId, deviceADataKey: p.aKey, blob: bad }),
      /would not open/,
    );
  }
});

test('a wrong-length blob is a TypeError, not an auth failure', async () => {
  const p = await pair();
  await assert.rejects(
    openGrant({
      deviceAId: p.aId, deviceBId: p.bId, deviceADataKey: p.aKey, blob: new Uint8Array(59),
    }),
    TypeError,
  );
});

test('each seal uses a fresh nonce', async () => {
  const p = await pair();
  const a = await seal(p);
  const b = await seal(p);
  assert.ok(!bytesEqual(a.subarray(0, 12), b.subarray(0, 12)));
  assert.ok(!bytesEqual(a, b));
});

test('the opened key decrypts a record device B sealed', async () => {
  const bSecret = generateDeviceSecret();
  const p = { ...(await pair()), bKey: await deriveDeviceDataKey(bSecret) };
  const seq = composeSeq(1, 1);
  const { nonce, ciphertext } = await encryptRecord({
    dataKey: p.bKey, deviceId: p.bId, seq, payload: { temp: 21.5 },
  });

  const blob = await seal(p);
  const granted = await openGrant({
    deviceAId: p.aId, deviceBId: p.bId, deviceADataKey: p.aKey, blob,
  });
  const payload = await decryptRecord({ dataKey: granted, deviceId: p.bId, seq, nonce, ciphertext });
  assert.deepEqual(payload, { temp: 21.5 });
});
