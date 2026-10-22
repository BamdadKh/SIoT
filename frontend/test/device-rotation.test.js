// Roadmap 8.4 / design 9.3: a rotated device keeps its history readable.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  emptyVaultDocument,
  normaliseVaultDocument,
  addDevice,
  findDevice,
  setDeviceSchema,
  setPendingSecret,
  promotePendingSecret,
  secretForSeq,
  deviceIdBytes,
  deviceSecretBytes,
} from '../lib/crypto/vault-document.js';
import {
  generateDevice,
  generateDeviceSecret,
  deriveDeviceDataKey,
  deriveDeviceKeys,
} from '../lib/crypto/device.js';
import { encryptRecord, decryptRecord } from '../lib/crypto/record.js';
import { toBase64Url, bytesEqual } from '../lib/crypto/encoding.js';

async function docWithDevice() {
  const device = await generateDevice();
  let doc = addDevice(emptyVaultDocument(), {
    deviceId: device.deviceId,
    deviceSecret: device.deviceSecret,
    name: 'Greenhouse',
  });
  doc = setDeviceSchema(doc, toBase64Url(device.deviceId), [
    { key: 'temp', type: 'number', widget: 'value', label: 'Temperature' },
  ]);
  return { device, doc, id: toBase64Url(device.deviceId) };
}

test('set then promote moves the old secret to retired and keeps name and schema', async () => {
  const { device, doc, id } = await docWithDevice();
  const next = generateDeviceSecret();

  const parked = setPendingSecret(doc, id, next);
  assert.equal(findDevice(parked, id).pending, toBase64Url(next));
  assert.equal(findDevice(parked, id).secret, toBase64Url(device.deviceSecret), 'secret untouched');

  const promoted = promotePendingSecret(parked, id, '41');
  const entry = findDevice(promoted, id);
  assert.equal(entry.secret, toBase64Url(next));
  assert.equal('pending' in entry, false);
  assert.deepEqual(entry.retired, [{ secret: toBase64Url(device.deviceSecret), through_seq: '41' }]);
  assert.equal(entry.name, 'Greenhouse');
  assert.deepEqual(entry.schema, findDevice(doc, id).schema);
  assert.equal(entry.added_at, findDevice(doc, id).added_at);
  assert.equal('retired' in findDevice(doc, id), false, 'input document is not mutated');
});

test('retrying set with the same bytes is a no-op; a stale promote does not double-retire', async () => {
  const { doc, id } = await docWithDevice();
  const next = generateDeviceSecret();

  const parked = setPendingSecret(doc, id, next);
  assert.equal(setPendingSecret(parked, id, next), parked);

  const promoted = promotePendingSecret(parked, id, '5');
  assert.throws(() => promotePendingSecret(promoted, id, '5'), /no pending/);

  // pending equal to secret: marker cleared, nothing appended.
  const stale = { ...promoted, devices: promoted.devices.map((d) => ({ ...d, pending: d.secret })) };
  const cleared = findDevice(promotePendingSecret(stale, id, '5'), id);
  assert.equal(cleared.retired.length, 1);
  assert.equal('pending' in cleared, false);
});

test('setPendingSecret refuses the current secret and unknown devices', async () => {
  const { device, doc, id } = await docWithDevice();
  assert.throws(() => setPendingSecret(doc, id, device.deviceSecret), /current secret/);
  assert.throws(() => setPendingSecret(doc, id, new Uint8Array(5)), /32 bytes/);
  assert.throws(() => setPendingSecret(doc, toBase64Url(new Uint8Array(16)), generateDeviceSecret()), /no such device/);
});

test('a boundary moving backwards is refused; an equal one is allowed', async () => {
  const { doc, id } = await docWithDevice();
  let current = promotePendingSecret(setPendingSecret(doc, id, generateDeviceSecret()), id, '100');

  const again = setPendingSecret(current, id, generateDeviceSecret());
  assert.throws(() => promotePendingSecret(again, id, '99'), /lower than/);
  assert.throws(() => promotePendingSecret(again, id, '-1'), /decimal/);
  assert.throws(() => promotePendingSecret(again, id, String(1n << 64n)), /uint64/);

  current = promotePendingSecret(again, id, '100');
  assert.equal(findDevice(current, id).retired.length, 2);
});

test('normalise round-trips retired and pending, sorts, and counts malformed items', async () => {
  const { device, doc, id } = await docWithDevice();
  const a = toBase64Url(generateDeviceSecret());
  const b = toBase64Url(generateDeviceSecret());
  const entry = {
    ...findDevice(doc, id),
    retired: [
      { secret: b, through_seq: '900' },
      { secret: 'short', through_seq: '1' },
      { secret: a, through_seq: '20' },
      { secret: a, through_seq: 20 },
      null,
    ],
    pending: toBase64Url(generateDeviceSecret()),
  };

  const { document, retiredDropped, dropped } = normaliseVaultDocument({ devices: [entry] });
  assert.equal(dropped, 0);
  assert.equal(retiredDropped, 3);
  const read = findDevice(document, id);
  assert.deepEqual(read.retired.map((r) => r.through_seq), ['20', '900']);
  assert.equal(read.pending, entry.pending);
  assert.equal(read.secret, toBase64Url(device.deviceSecret));

  const bad = normaliseVaultDocument({ devices: [{ ...entry, pending: 'nope' }] });
  assert.equal(bad.retiredDropped, 4);
  assert.equal('pending' in findDevice(bad.document, id), false);
});

test('an entry never rotated reads back without retired or pending', async () => {
  const { doc, id } = await docWithDevice();
  const read = findDevice(normaliseVaultDocument(doc).document, id);
  assert.equal('retired' in read, false);
  assert.equal('pending' in read, false);
});

test('secretForSeq at, below and above each boundary, past 2^53', () => {
  const s1 = toBase64Url(generateDeviceSecret());
  const s2 = toBase64Url(generateDeviceSecret());
  const s3 = toBase64Url(generateDeviceSecret());
  const big = (1n << 60n) + 7n;
  const entry = {
    secret: s3,
    retired: [
      { secret: s1, through_seq: '10' },
      { secret: s2, through_seq: String(big) },
    ],
  };

  assert.equal(secretForSeq(entry, '0'), s1);
  assert.equal(secretForSeq(entry, '10'), s1);
  assert.equal(secretForSeq(entry, '11'), s2);
  assert.equal(secretForSeq(entry, String(big)), s2);
  assert.equal(secretForSeq(entry, String(big + 1n)), s3);
  assert.equal(secretForSeq(entry, String((1n << 64n) - 1n)), s3);
  // Two doubles-adjacent values above 2^53 still separate.
  assert.equal(secretForSeq({ secret: s3, retired: [{ secret: s1, through_seq: String((1n << 53n) + 1n) }] }, String((1n << 53n) + 2n)), s3);
  assert.equal(secretForSeq({ secret: s1 }, '5'), s1);
});

test('the new secret derives a different sign_pub from the old one', async () => {
  const a = await deriveDeviceKeys(generateDeviceSecret());
  const b = await deriveDeviceKeys(generateDeviceSecret());
  assert.equal(bytesEqual(a.signPub, b.signPub), false);
  assert.equal(a.signPub.length, 32);
});

test('records from before and after a rotation both open through secretForSeq', async () => {
  const { device, doc, id } = await docWithDevice();
  const next = generateDeviceSecret();
  const throughSeq = (1n << 55n) + 3n;
  const rotated = promotePendingSecret(setPendingSecret(doc, id, next), id, String(throughSeq));
  const entry = findDevice(normaliseVaultDocument(rotated).document, id);
  const idBytes = deviceIdBytes(entry);

  const oldSeq = throughSeq;
  const newSeq = throughSeq + 1n;
  const oldRecord = await encryptRecord({
    dataKey: await deriveDeviceDataKey(device.deviceSecret),
    deviceId: idBytes,
    seq: oldSeq,
    payload: { temp: 20 },
  });
  const newRecord = await encryptRecord({
    dataKey: await deriveDeviceDataKey(next),
    deviceId: idBytes,
    seq: newSeq,
    payload: { temp: 21 },
  });

  for (const [seq, record, expected] of [
    [oldSeq, oldRecord, 20],
    [newSeq, newRecord, 21],
  ]) {
    const secret = deviceSecretBytes({ secret: secretForSeq(entry, String(seq)) });
    const payload = await decryptRecord({
      dataKey: await deriveDeviceDataKey(secret),
      deviceId: idBytes,
      seq,
      nonce: record.nonce,
      ciphertext: record.ciphertext,
    });
    assert.equal(payload.temp, expected);
  }

  // The wrong side of the boundary does not open, which is what the pick buys.
  await assert.rejects(
    decryptRecord({
      dataKey: await deriveDeviceDataKey(next),
      deviceId: idBytes,
      seq: oldSeq,
      nonce: oldRecord.nonce,
      ciphertext: oldRecord.ciphertext,
    }),
  );
});
