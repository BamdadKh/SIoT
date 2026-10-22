// Roadmap 4.1: device key derivation in the browser.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  generateDevice,
  generateDeviceId,
  generateDeviceSecret,
  deriveDeviceKeys,
  deriveDeviceDataKey,
  deriveDeviceSignSeed,
  DEVICE_ID_BYTES,
  DEVICE_SECRET_BYTES,
} from '../lib/crypto/device.js';
import { hkdfSha256 } from '../lib/crypto/hkdf.js';
import { randomBytes } from '../lib/crypto/random.js';
import { bytesEqual } from '../lib/crypto/encoding.js';

test('DEVICE_ID and DEVICE_SECRET are the sizes design 5.1 specifies', () => {
  assert.equal(generateDeviceId().length, DEVICE_ID_BYTES);
  assert.equal(generateDeviceSecret().length, DEVICE_SECRET_BYTES);
});

test('generated values never repeat', () => {
  assert.ok(!bytesEqual(generateDeviceId(), generateDeviceId()));
  assert.ok(!bytesEqual(generateDeviceSecret(), generateDeviceSecret()));
});

test('the same DEVICE_SECRET reproduces the same keys', async () => {
  // The property the whole provisioning model rests on: the browser derives
  // these once, the board derives them again on every boot from the same 32
  // bytes in NVS, and they have to be identical or nothing the device uploads
  // can ever be read or verified.
  const deviceSecret = generateDeviceSecret();

  const first = await deriveDeviceKeys(deviceSecret);
  const second = await deriveDeviceKeys(deviceSecret);

  assert.ok(bytesEqual(first.dataKey, second.dataKey));
  assert.ok(bytesEqual(first.signPub, second.signPub));
});

test('different DEVICE_SECRETs produce different keys', async () => {
  const a = await deriveDeviceKeys(generateDeviceSecret());
  const b = await deriveDeviceKeys(generateDeviceSecret());

  assert.ok(!bytesEqual(a.dataKey, b.dataKey));
  assert.ok(!bytesEqual(a.signPub, b.signPub));
});

test('the data key and the signing seed are independent', async () => {
  // If these collided, a grant conveying read access would convey forgery too,
  // which is the exact failure the two-label split exists to prevent (design 9.1).
  const deviceSecret = generateDeviceSecret();
  const dataKey = await deriveDeviceDataKey(deviceSecret);
  const signSeed = await deriveDeviceSignSeed(deviceSecret);

  assert.equal(dataKey.length, 32);
  assert.equal(signSeed.length, 32);
  assert.ok(!bytesEqual(dataKey, signSeed));
  assert.ok(!bytesEqual(dataKey, deviceSecret));
  assert.ok(!bytesEqual(signSeed, deviceSecret));
});

test('the HKDF labels are the exact strings firmware will use', async () => {
  // Spelled out literally rather than imported from HKDF_INFO. A test that reads
  // the same constant the code reads cannot catch a relabelling, and a
  // relabelling here silently orphans every device already provisioned.
  const deviceSecret = generateDeviceSecret();

  assert.ok(
    bytesEqual(
      await deriveDeviceDataKey(deviceSecret),
      await hkdfSha256(deviceSecret, 'siot/device/data/v1'),
    ),
  );
  assert.ok(
    bytesEqual(
      await deriveDeviceSignSeed(deviceSecret),
      await hkdfSha256(deviceSecret, 'siot/device/sign/v1'),
    ),
  );
});

test('generateDevice mints a complete, self-consistent device', async () => {
  const device = await generateDevice();

  assert.equal(device.deviceId.length, DEVICE_ID_BYTES);
  assert.equal(device.deviceSecret.length, DEVICE_SECRET_BYTES);
  assert.equal(device.dataKey.length, 32);
  assert.equal(device.signPub.length, 32);

  const rederived = await deriveDeviceKeys(device.deviceSecret);
  assert.ok(bytesEqual(rederived.dataKey, device.dataKey));
  assert.ok(bytesEqual(rederived.signPub, device.signPub));
});

test('rejects a DEVICE_SECRET that is not 32 bytes', async () => {
  await assert.rejects(() => deriveDeviceKeys(randomBytes(16)), TypeError);
  await assert.rejects(() => deriveDeviceDataKey(randomBytes(31)), TypeError);
  await assert.rejects(() => deriveDeviceSignSeed('not bytes'), TypeError);
});

// Roadmap 10.1 and 11.1: the third and fourth labels.
test('data, notify, command and signing keys are four distinct values from one secret', async () => {
  const { deriveDeviceNotifyKey, deriveDeviceCommandKey, deriveDeviceSignSeed } = await import(
    '../lib/crypto/device.js'
  );
  const secret = generateDeviceSecret();
  const keys = await Promise.all([
    deriveDeviceDataKey(secret),
    deriveDeviceNotifyKey(secret),
    deriveDeviceCommandKey(secret),
    deriveDeviceSignSeed(secret),
  ]);
  const hex = keys.map((k) => Buffer.from(k).toString('hex'));
  assert.equal(new Set(hex).size, 4);
  for (const k of keys) assert.equal(k.length, 32);
});

test('notify and command keys are reproducible from the secret alone, and per-device', async () => {
  const { deriveDeviceNotifyKey, deriveDeviceCommandKey } = await import('../lib/crypto/device.js');
  const secret = generateDeviceSecret();
  assert.deepEqual(await deriveDeviceNotifyKey(secret), await deriveDeviceNotifyKey(secret));
  assert.deepEqual(await deriveDeviceCommandKey(secret), await deriveDeviceCommandKey(secret));
  assert.notDeepEqual(
    await deriveDeviceNotifyKey(secret),
    await deriveDeviceNotifyKey(generateDeviceSecret()),
  );
});

test('deriveDeviceKeys hands back the notify and command keys too', async () => {
  const { deriveDeviceNotifyKey, deriveDeviceCommandKey } = await import('../lib/crypto/device.js');
  const secret = generateDeviceSecret();
  const keys = await deriveDeviceKeys(secret);
  assert.deepEqual(keys.notifyKey, await deriveDeviceNotifyKey(secret));
  assert.deepEqual(keys.commandKey, await deriveDeviceCommandKey(secret));
});
