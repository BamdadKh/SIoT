// Roadmap 10.2 (payload, bounds) and 10.3 (dual-key open, allowlist).
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  buildNotificationPayload,
  validateNotification,
  openAnyRecord,
  NOTIFICATION_MESSAGE_MAX_BYTES,
} from '../lib/crypto/notification.js';
import { encryptRecord, composeSeq } from '../lib/crypto/record.js';
import { generateDevice } from '../lib/crypto/device.js';

async function sealed(device, key, seq, payload) {
  const { nonce, ciphertext } = await encryptRecord({
    dataKey: key,
    deviceId: device.deviceId,
    seq,
    payload,
  });
  return { dataKey: device.dataKey, notifyKey: device.notifyKey, deviceId: device.deviceId, seq, nonce, ciphertext };
}

test('a reading opens as a reading, a notification as a notification, from one boot', async () => {
  const d = await generateDevice();
  const reading = await sealed(d, d.dataKey, composeSeq(1, 1), { t: 5, r: { temp: 21.5 } });
  const note = await sealed(
    d,
    d.notifyKey,
    composeSeq(1, 2),
    buildNotificationPayload({ t: 6, severity: 'alert', message: 'Door left open' }),
  );

  const a = await openAnyRecord(reading);
  const b = await openAnyRecord(note);
  assert.equal(a.kind, 'reading');
  assert.deepEqual(a.payload.r, { temp: 21.5 });
  assert.equal(b.kind, 'notification');
  assert.deepEqual(b.notification, { deviceTime: 6, severity: 'alert', message: 'Door left open' });
});

test('a record that opens under neither key throws, so the caller counts it unopened', async () => {
  const d = await generateDevice();
  const stranger = await generateDevice();
  const rec = await sealed(stranger, stranger.dataKey, composeSeq(1, 1), { t: 1, r: {} });
  await assert.rejects(openAnyRecord({ ...rec, deviceId: d.deviceId, dataKey: d.dataKey, notifyKey: d.notifyKey }));
});

test('the data key and the notify key are not interchangeable for a reader', async () => {
  const d = await generateDevice();
  const note = await sealed(
    d,
    d.notifyKey,
    composeSeq(1, 1),
    buildNotificationPayload({ severity: 'info', message: 'hi' }),
  );
  // Someone granted only the data key sees an unopenable record, not the alert.
  await assert.rejects(openAnyRecord({ ...note, notifyKey: d.commandKey }));
});

test('the library bounds the message and the severity set', () => {
  const base = { severity: 'info', message: 'ok' };
  assert.throws(() => buildNotificationPayload({ ...base, severity: 'fatal' }), TypeError);
  assert.throws(() => buildNotificationPayload({ ...base, message: '' }), TypeError);
  assert.throws(
    () => buildNotificationPayload({ ...base, message: 'x'.repeat(NOTIFICATION_MESSAGE_MAX_BYTES + 1) }),
    RangeError,
  );
  // Bytes, not characters: 61 two-byte characters is 122 bytes.
  assert.throws(() => buildNotificationPayload({ ...base, message: 'é'.repeat(61) }), RangeError);
  buildNotificationPayload({ ...base, message: 'x'.repeat(NOTIFICATION_MESSAGE_MAX_BYTES) });
});

test('the allowlist rejects anything that is not exactly a notification', () => {
  const ok = { t: 0, type: 'notification', severity: 'warning', message: 'hello' };
  assert.deepEqual(validateNotification(ok), { deviceTime: null, severity: 'warning', message: 'hello' });

  for (const bad of [
    null,
    'str',
    [],
    { ...ok, type: 'reading' },
    { ...ok, severity: 'panic' },
    { ...ok, message: 5 },
    { ...ok, message: '' },
    { ...ok, message: '‮​' },
    { ...ok, message: 'x'.repeat(NOTIFICATION_MESSAGE_MAX_BYTES + 1) },
    { ...ok, t: 'now' },
    { ...ok, t: -1 },
    { t: 1, r: { a: 1 } },
  ]) {
    assert.equal(validateNotification(bad), null);
  }
});

test('hostile content is returned as inert text with only three members', () => {
  const evil = JSON.parse(
    '{"type":"notification","severity":"info","message":"<img src=x onerror=alert(1)>","__proto__":{"x":1},"html":"<b>"}',
  );
  const out = validateNotification(evil);
  assert.deepEqual(Object.keys(out).sort(), ['deviceTime', 'message', 'severity']);
  assert.equal(out.message, '<img src=x onerror=alert(1)>');
});

test('a well-keyed record with a malformed notification payload is flagged, not rendered', async () => {
  const d = await generateDevice();
  const rec = await sealed(d, d.notifyKey, composeSeq(1, 1), { type: 'notification', severity: 'nope', message: 'x' });
  assert.equal((await openAnyRecord(rec)).kind, 'malformed-notification');
});
