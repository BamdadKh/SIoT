// Roadmap 8.1: grant creation and opening.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createGrant, openGrant, grantAad, GRANT_BLOB_BYTES } from '../lib/crypto/grant.js';
import { generateDevice } from '../lib/crypto/device.js';
import { bytesEqual } from '../lib/crypto/encoding.js';

async function pair() {
  return [await generateDevice(), await generateDevice()];
}

test('a grant round-trips and is the size the server enforces', async () => {
  const [a, b] = await pair();
  const blob = await createGrant({
    deviceIdA: a.deviceId, deviceIdB: b.deviceId, dataKeyA: a.dataKey, dataKeyB: b.dataKey,
  });
  assert.equal(blob.length, GRANT_BLOB_BYTES);

  const opened = await openGrant({
    blob, deviceIdA: a.deviceId, deviceIdB: b.deviceId, dataKeyA: a.dataKey,
  });
  assert.ok(bytesEqual(opened, b.dataKey));
});

test('the same grant twice is two different blobs (fresh IV)', async () => {
  const [a, b] = await pair();
  const args = { deviceIdA: a.deviceId, deviceIdB: b.deviceId, dataKeyA: a.dataKey, dataKeyB: b.dataKey };
  assert.ok(!bytesEqual(await createGrant(args), await createGrant(args)));
});

test('a grant will not open under the wrong key, pair, or role order', async () => {
  const [a, b] = await pair();
  const c = await generateDevice();
  const blob = await createGrant({
    deviceIdA: a.deviceId, deviceIdB: b.deviceId, dataKeyA: a.dataKey, dataKeyB: b.dataKey,
  });

  const base = { blob, deviceIdA: a.deviceId, deviceIdB: b.deviceId, dataKeyA: a.dataKey };
  await assert.rejects(openGrant({ ...base, dataKeyA: c.dataKey }));
  await assert.rejects(openGrant({ ...base, deviceIdB: c.deviceId }));
  await assert.rejects(openGrant({ ...base, deviceIdA: b.deviceId, deviceIdB: a.deviceId }));
});

test('a tampered grant does not open', async () => {
  const [a, b] = await pair();
  const blob = await createGrant({
    deviceIdA: a.deviceId, deviceIdB: b.deviceId, dataKeyA: a.dataKey, dataKeyB: b.dataKey,
  });
  blob[20] ^= 1;
  await assert.rejects(
    openGrant({ blob, deviceIdA: a.deviceId, deviceIdB: b.deviceId, dataKeyA: a.dataKey }),
  );
});

test('the AAD is "grant/v1" || A || B', async () => {
  const [a, b] = await pair();
  const aad = grantAad(a.deviceId, b.deviceId);
  assert.equal(new TextDecoder().decode(aad.subarray(0, 8)), 'grant/v1');
  assert.ok(bytesEqual(aad.subarray(8, 24), a.deviceId));
  assert.ok(bytesEqual(aad.subarray(24), b.deviceId));
});

test('wrong-sized inputs are refused before any crypto', async () => {
  const [a, b] = await pair();
  await assert.rejects(
    createGrant({ deviceIdA: a.deviceId.subarray(1), deviceIdB: b.deviceId, dataKeyA: a.dataKey, dataKeyB: b.dataKey }),
    TypeError,
  );
  await assert.rejects(
    openGrant({ blob: new Uint8Array(59), deviceIdA: a.deviceId, deviceIdB: b.deviceId, dataKeyA: a.dataKey }),
    TypeError,
  );
});
