// Roadmap 4.3: the device record inside the vault.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  emptyVaultDocument,
  normaliseVaultDocument,
  normaliseDeviceName,
  listDevices,
  findDevice,
  addDevice,
  renameDevice,
  removeDevice,
  deviceSecretBytes,
  deviceIdBytes,
  DEVICE_NAME_MAX_LENGTH,
} from '../lib/crypto/vault-document.js';
import { generateDevice, deriveDeviceKeys } from '../lib/crypto/device.js';
import { encryptVault, decryptVault } from '../lib/crypto/vault.js';
import { generateVaultKey } from '../lib/crypto/vault-key.js';
import { randomBytes } from '../lib/crypto/random.js';
import { bytesEqual, toBase64Url } from '../lib/crypto/encoding.js';

test('a fresh vault has no devices', () => {
  const doc = emptyVaultDocument();

  assert.deepEqual(listDevices(doc), []);
  assert.equal(doc.v, 1);
});

test('adding a device stores its id, secret and name', async () => {
  const { deviceId, deviceSecret } = await generateDevice();
  const doc = addDevice(emptyVaultDocument(), {
    deviceId,
    deviceSecret,
    name: 'Greenhouse humidity',
  });

  const [entry] = listDevices(doc);
  assert.equal(entry.name, 'Greenhouse humidity');
  assert.ok(bytesEqual(deviceIdBytes(entry), deviceId));
  assert.ok(bytesEqual(deviceSecretBytes(entry), deviceSecret));
  assert.ok(Date.parse(entry.added_at) > 0);
});

test('the stored secret still derives the keys the device will use', async () => {
  // The point of keeping DEVICE_SECRET rather than the derived keys: a board
  // re-derives from the same 32 bytes on every boot, so the vault has to hold
  // the input, not the output.
  const device = await generateDevice();
  const doc = addDevice(emptyVaultDocument(), {
    deviceId: device.deviceId,
    deviceSecret: device.deviceSecret,
    name: 'Bench sensor',
  });

  const rederived = await deriveDeviceKeys(deviceSecretBytes(listDevices(doc)[0]));
  assert.ok(bytesEqual(rederived.dataKey, device.dataKey));
  assert.ok(bytesEqual(rederived.signPub, device.signPub));
});

test('edits never mutate the document they were given', async () => {
  // A 409 from PUT /vault means refetching and re-applying, which is only safe
  // if the copy being retried from was never touched.
  const device = await generateDevice();
  const before = emptyVaultDocument();
  const after = addDevice(before, { ...device, name: 'Front door' });

  assert.equal(listDevices(before).length, 0);
  assert.equal(listDevices(after).length, 1);

  const renamed = renameDevice(after, toBase64Url(device.deviceId), 'Back door');
  assert.equal(listDevices(after)[0].name, 'Front door');
  assert.equal(listDevices(renamed)[0].name, 'Back door');
});

test('rename touches nothing but the name', async () => {
  const device = await generateDevice();
  const doc = addDevice(emptyVaultDocument(), { ...device, name: 'Old name' });
  const renamed = renameDevice(doc, toBase64Url(device.deviceId), 'New name');

  const [before] = listDevices(doc);
  const [after] = listDevices(renamed);
  assert.equal(after.id, before.id);
  assert.equal(after.secret, before.secret);
  assert.equal(after.added_at, before.added_at);
  assert.equal(after.name, 'New name');
});

test('remove drops exactly one device', async () => {
  const first = await generateDevice();
  const second = await generateDevice();
  let doc = addDevice(emptyVaultDocument(), { ...first, name: 'One' });
  doc = addDevice(doc, { ...second, name: 'Two' });

  const pruned = removeDevice(doc, toBase64Url(first.deviceId));
  assert.equal(listDevices(pruned).length, 1);
  assert.equal(listDevices(pruned)[0].name, 'Two');
  assert.equal(findDevice(pruned, toBase64Url(first.deviceId)), null);
});

test('the same DEVICE_ID cannot be added twice', async () => {
  const device = await generateDevice();
  const doc = addDevice(emptyVaultDocument(), { ...device, name: 'One' });

  assert.throws(() => addDevice(doc, { ...device, name: 'Again' }), /already in the vault/);
});

test('rename and remove refuse an unknown DEVICE_ID', () => {
  const doc = emptyVaultDocument();
  const stranger = toBase64Url(randomBytes(16));

  assert.throws(() => renameDevice(doc, stranger, 'Nope'), /no such device/);
  assert.throws(() => removeDevice(doc, stranger), /no such device/);
});

test('names are cleaned of anything that could render as something else', () => {
  assert.equal(normaliseDeviceName('  Loft   sensor  '), 'Loft sensor');
  // A right-to-left override can make "gnp.txt" display as "txt.png"; the same
  // trick on a device name would make one device look like another.
  assert.equal(normaliseDeviceName('Loft\u202Esensor'), 'Loftsensor');
  assert.equal(normaliseDeviceName('Loft \u200Bsensor'), 'Loft sensor');
});

test('names must be non-empty and bounded', () => {
  assert.throws(() => normaliseDeviceName(''), /cannot be empty/);
  assert.throws(() => normaliseDeviceName('   '), /cannot be empty/);
  assert.throws(() => normaliseDeviceName('\u202A\u202B'), /cannot be empty/);
  assert.throws(() => normaliseDeviceName(null), TypeError);
  assert.throws(
    () => normaliseDeviceName('x'.repeat(DEVICE_NAME_MAX_LENGTH + 1)),
    /cannot exceed/,
  );
  assert.equal(normaliseDeviceName('x'.repeat(DEVICE_NAME_MAX_LENGTH)).length, 64);
});

test('add rejects wrong-sized key material', async () => {
  const { deviceSecret } = await generateDevice();

  assert.throws(
    () => addDevice(emptyVaultDocument(), { deviceId: randomBytes(8), deviceSecret, name: 'x' }),
    TypeError,
  );
  assert.throws(
    () =>
      addDevice(emptyVaultDocument(), {
        deviceId: randomBytes(16),
        deviceSecret: randomBytes(16),
        name: 'x',
      }),
    TypeError,
  );
});

test('reading a vault written by a stranger client drops what it cannot parse', () => {
  const good = {
    id: toBase64Url(randomBytes(16)),
    secret: toBase64Url(randomBytes(32)),
    name: 'Kept',
  };

  const { document, dropped } = normaliseVaultDocument({
    v: 1,
    devices: [
      good,
      { id: good.id, secret: good.secret, name: 'Duplicate id' },
      { id: toBase64Url(randomBytes(4)), secret: good.secret, name: 'Short id' },
      { id: toBase64Url(randomBytes(16)), secret: 'not base64url!!', name: 'Bad secret' },
      { id: toBase64Url(randomBytes(16)), secret: good.secret, name: '' },
      null,
    ],
    somethingNewerClientsAdded: true,
  });

  assert.equal(dropped, 5);
  assert.equal(listDevices(document).length, 1);
  assert.equal(listDevices(document)[0].name, 'Kept');
  // Unrecognised top-level keys do not survive the read, so nothing downstream
  // can start depending on a field this version does not define.
  assert.deepEqual(Object.keys(document).sort(), ['devices', 'v']);
});

test('a never-written vault normalises to an empty document', () => {
  for (const contents of [null, undefined, {}, { devices: 'not an array' }]) {
    const { document, dropped } = normaliseVaultDocument(contents);
    assert.deepEqual(listDevices(document), []);
    assert.equal(dropped, 0);
  }
  assert.throws(() => normaliseVaultDocument([]), TypeError);
  assert.throws(() => normaliseVaultDocument('a string'), TypeError);
});

test('a document with devices round-trips through the sealed vault', async () => {
  // The end-to-end shape of roadmap 4.3: mint a device, put it in the document,
  // seal, and confirm what comes back out still derives the same keys.
  const vaultKey = generateVaultKey();
  const device = await generateDevice();

  const doc = addDevice(emptyVaultDocument(), { ...device, name: 'Roof rain gauge' });
  const blob = await encryptVault(doc, vaultKey, 1);
  const { document: reopened } = normaliseVaultDocument(await decryptVault(blob, vaultKey, 1));

  const [entry] = listDevices(reopened);
  assert.equal(entry.name, 'Roof rain gauge');
  assert.ok(bytesEqual(deviceSecretBytes(entry), device.deviceSecret));

  // The name must not be recoverable from the blob itself.
  assert.ok(!Buffer.from(blob).includes(Buffer.from('Roof rain gauge', 'utf8')));
});
