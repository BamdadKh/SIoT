// Roadmap 11.2: the dashboard half of device commands.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { encryptCommand, decryptCommand, commandAad } from '../lib/crypto/command.js';
import { generateDevice, deriveDeviceCommandKey } from '../lib/crypto/device.js';
import {
  emptyVaultDocument,
  addDevice,
  findDevice,
  reserveCommandSeq,
  normaliseVaultDocument,
} from '../lib/crypto/vault-document.js';
import { toBase64Url } from '../lib/crypto/encoding.js';

async function device() {
  const d = await generateDevice();
  return { ...d, key: await deriveDeviceCommandKey(d.deviceSecret) };
}

test('a command round-trips with its sequence, type and args', async () => {
  const d = await device();
  const sealed = await encryptCommand({
    deviceId: d.deviceId,
    commandKey: d.key,
    commandSeq: 7,
    type: 'set_target',
    args: { on: true, level: 40 },
  });
  assert.equal(sealed.nonce.length, 12);

  const opened = await decryptCommand({ deviceId: d.deviceId, commandKey: d.key, ...sealed });
  assert.equal(opened.command_seq, 7n);
  assert.equal(opened.type, 'set_target');
  assert.deepEqual(opened.args, { on: true, level: 40 });
});

test('nonces are random: the same command twice differs', async () => {
  const d = await device();
  const base = { deviceId: d.deviceId, commandKey: d.key, commandSeq: 1, type: 'x' };
  const a = await encryptCommand(base);
  const b = await encryptCommand(base);
  assert.notDeepEqual(a.nonce, b.nonce);
  assert.notDeepEqual(a.ciphertext, b.ciphertext);
});

test('a command will not open for another device, another key, or if tampered', async () => {
  const d = await device();
  const other = await device();
  const sealed = await encryptCommand({
    deviceId: d.deviceId,
    commandKey: d.key,
    commandSeq: 1,
    type: 'x',
  });

  await assert.rejects(decryptCommand({ deviceId: other.deviceId, commandKey: d.key, ...sealed }));
  await assert.rejects(decryptCommand({ deviceId: d.deviceId, commandKey: other.key, ...sealed }));
  sealed.ciphertext[0] ^= 1;
  await assert.rejects(decryptCommand({ deviceId: d.deviceId, commandKey: d.key, ...sealed }));
});

test('the data key cannot open a command: the keys are separate', async () => {
  const d = await device();
  const sealed = await encryptCommand({
    deviceId: d.deviceId,
    commandKey: d.key,
    commandSeq: 1,
    type: 'x',
  });
  await assert.rejects(decryptCommand({ deviceId: d.deviceId, commandKey: d.dataKey, ...sealed }));
});

test('AAD is version || DEVICE_ID || class', async () => {
  const d = await device();
  const aad = commandAad(d.deviceId);
  assert.equal(aad.length, 18);
  assert.equal(aad[0], 1);
  assert.equal(aad[17], 1);
});

test('bad input is refused before encrypting', async () => {
  const d = await device();
  const base = { deviceId: d.deviceId, commandKey: d.key, commandSeq: 1, type: 'x' };
  await assert.rejects(encryptCommand({ ...base, commandSeq: 0 }), RangeError);
  await assert.rejects(encryptCommand({ ...base, type: '' }), TypeError);
  await assert.rejects(encryptCommand({ ...base, args: { big: 'x'.repeat(2000) } }), RangeError);
});

test('reserveCommandSeq hands out 1, 2, 3 and leaves the input untouched', async () => {
  const d = await device();
  const id = toBase64Url(d.deviceId);
  const doc = addDevice(emptyVaultDocument(), {
    deviceId: d.deviceId,
    deviceSecret: d.deviceSecret,
    name: 'Lock',
  });

  const one = reserveCommandSeq(doc, id);
  const two = reserveCommandSeq(one.document, id);
  assert.deepEqual([one.commandSeq, two.commandSeq], [1, 2]);
  assert.equal(findDevice(doc, id).nextCommandSeq, 1);
  assert.equal(findDevice(two.document, id).nextCommandSeq, 3);
});

test('the counter survives a vault read, and a corrupt one resets to 1', async () => {
  const d = await device();
  const id = toBase64Url(d.deviceId);
  let doc = addDevice(emptyVaultDocument(), {
    deviceId: d.deviceId,
    deviceSecret: d.deviceSecret,
    name: 'Lock',
  });
  doc = reserveCommandSeq(doc, id).document;

  const reread = normaliseVaultDocument(JSON.parse(JSON.stringify(doc))).document;
  assert.equal(findDevice(reread, id).nextCommandSeq, 2);

  doc.devices[0].nextCommandSeq = -5;
  assert.equal(findDevice(normaliseVaultDocument(doc).document, id).nextCommandSeq, 1);
});

test('reserving for an unknown device throws', () => {
  assert.throws(() => reserveCommandSeq(emptyVaultDocument(), 'nope'), /no such device/);
});
