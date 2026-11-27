// Roadmap 10.3 and 10.4: notifications across devices, and their read state.
//
// What is held here is every claim the Notifications list makes: that one
// device's notifications stay in signed `seq` order whatever the server's
// timestamps say, that only devices are interleaved by arrival time, that unread
// is judged against the vault's mark and nothing else, and that a mark only
// moves forward.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  describeUnread,
  isUnread,
  mergeNotifications,
  notificationsIn,
  readMarks,
} from '../app/src/lib/notifications.js';
import { readRecord } from '../app/src/lib/records.js';
import { buildDashboard } from '../app/src/lib/dashboard.js';
import { buildCsvExport, buildJsonExport } from '../app/src/lib/export-records.js';
import { valueMatchesField } from '../lib/crypto/device-schema.js';
import {
  addDevice,
  markNotificationsSeen,
  normaliseVaultDocument,
  emptyVaultDocument,
} from '../lib/crypto/vault-document.js';
import { toBase64Url } from '../lib/crypto/encoding.js';

const seq = (boot, counter) => ((BigInt(boot) << 32n) | BigInt(counter)).toString();
const at = (second) => `2026-11-26T10:00:${String(second).padStart(2, '0')}Z`;

const reading = (counter, second, r = { temp: 20 }) => ({
  seq: seq(1, counter),
  receivedAt: at(second),
  kind: 'reading',
  payload: { t: 0, r },
  notification: null,
  error: null,
});
const notice = (counter, second, message = `n${counter}`, severity = 'alert') => ({
  seq: seq(1, counter),
  receivedAt: at(second),
  kind: 'notification',
  payload: null,
  notification: { deviceTime: null, severity, message },
  error: null,
});

test('notificationsIn keeps only notifications, newest seq first, including malformed ones', () => {
  const records = [
    reading(1, 1),
    notice(2, 2),
    { ...reading(3, 3), kind: null, payload: null, error: 'x' },
    { ...notice(4, 4), kind: 'malformed-notification', notification: null },
    reading(5, 5),
  ];
  const found = notificationsIn(records);
  assert.deepEqual(
    found.map((item) => item.seq),
    [seq(1, 4), seq(1, 2)],
  );
  assert.equal(found[0].notification, null, 'malformed is kept, not dropped, and not rendered');
});

test('the merge never reorders one device against its own seq, even when the server lies about time', () => {
  // Device A's arrival times run backwards against its sequence; the server
  // could do that. A sort on arrival time would put A's seq 2 above seq 3.
  const a = notificationsIn([notice(2, 50), notice(3, 10)]);
  const b = notificationsIn([notice(7, 30)]);
  const merged = mergeNotifications([
    { deviceId: 'A', name: 'Door', seenThrough: null, notifications: a },
    { deviceId: 'B', name: 'Tank', seenThrough: null, notifications: b },
  ]);
  const aOnly = merged.filter((item) => item.deviceId === 'A').map((item) => item.seq);
  assert.deepEqual(aOnly, [seq(1, 3), seq(1, 2)]);
  assert.equal(merged.length, 3);
});

test('across devices the newer arrival comes first', () => {
  const merged = mergeNotifications([
    { deviceId: 'A', name: null, seenThrough: null, notifications: notificationsIn([notice(1, 5)]) },
    { deviceId: 'B', name: null, seenThrough: null, notifications: notificationsIn([notice(1, 9)]) },
  ]);
  assert.deepEqual(
    merged.map((item) => item.deviceId),
    ['B', 'A'],
  );
});

test('unread is judged against the vault mark only', () => {
  assert.equal(isUnread(seq(1, 5), null), true);
  assert.equal(isUnread(seq(1, 5), seq(1, 5)), false);
  assert.equal(isUnread(seq(1, 6), seq(1, 5)), true);
  // A later boot is always above an earlier boot's mark.
  assert.equal(isUnread(seq(2, 0), seq(1, 9000)), true);

  const merged = mergeNotifications([
    {
      deviceId: 'A',
      name: 'Door',
      seenThrough: seq(1, 3),
      notifications: notificationsIn([notice(2, 1), notice(3, 2), notice(4, 3)]),
    },
  ]);
  assert.deepEqual(
    merged.map((item) => item.unread),
    [true, false, false],
  );
});

test('readMarks advances each device to its highest unread seq and skips devices with none', () => {
  const merged = mergeNotifications([
    {
      deviceId: 'A',
      name: null,
      seenThrough: null,
      notifications: notificationsIn([notice(2, 1), notice(9, 2)]),
    },
    { deviceId: 'B', name: null, seenThrough: seq(1, 4), notifications: notificationsIn([notice(4, 3)]) },
  ]);
  assert.deepEqual([...readMarks(merged)], [['A', seq(1, 9)]]);
});

test('a quiet account is never told it has no alerts', () => {
  for (const text of [describeUnread(0, 0), describeUnread(0, 3)]) {
    assert.doesNotMatch(text, /no (alerts|notifications)/i);
  }
  assert.equal(describeUnread(2, 5), '2 unread.');
});

/* --- the shared reading of a record -------------------------------------- */

test('readRecord gives a notification no readings and no problem', () => {
  const read = readRecord(notice(1, 1));
  assert.equal(read.kind, 'notification');
  assert.deepEqual(read.readings, []);
  assert.equal(read.problem, null);
  assert.equal(read.notification.message, 'n1');

  // A record written before kinds existed reads as a reading.
  const legacy = readRecord({ seq: seq(1, 1), payload: { t: 0, r: { a: 1 } }, error: null });
  assert.equal(legacy.kind, 'reading');
  assert.equal(legacy.readings.length, 1);
});

test('a notification between two readings does not break a graph', () => {
  const schema = { v: 1, fields: [{ key: 'temp', type: 'number', widget: 'graph' }] };
  const [panel] = buildDashboard(
    schema,
    [reading(1, 1), notice(2, 2), reading(3, 3)],
    valueMatchesField,
  );
  assert.equal(panel.series.breaks, 0);
  assert.equal(panel.series.points, 2);
});

test('the export names a notification as one and defuses its text in CSV', () => {
  const records = [reading(1, 1), notice(2, 2, '=HYPERLINK("http://x")', 'critical')];
  const doc = JSON.parse(
    buildJsonExport({
      deviceName: 'Door',
      deviceId: 'AAAAAAAAAAAAAAAAAAAAAA',
      exportedAt: new Date(0),
      records,
    }),
  );
  assert.equal(doc.notification_count, 1);
  assert.equal(doc.unopened_count, 0);
  assert.equal(doc.records[1].status, 'notification');
  assert.deepEqual(doc.records[1].notification, {
    severity: 'critical',
    message: '=HYPERLINK("http://x")',
  });

  const csv = buildCsvExport({ records });
  assert.match(csv.split('\r\n')[0], /notification_severity,notification_message/);
  assert.match(csv, /critical,"'=HYPERLINK\(""http:\/\/x""\)"/);
});

/* --- read state in the vault --------------------------------------------- */

function docWithDevice() {
  const deviceId = new Uint8Array(16).fill(1);
  const document = addDevice(emptyVaultDocument(), {
    deviceId,
    deviceSecret: new Uint8Array(32).fill(2),
    name: 'Door',
  });
  return { document, id: toBase64Url(deviceId) };
}

test('the read mark only moves forward and survives a round trip through the vault', () => {
  const { document, id } = docWithDevice();
  const marked = markNotificationsSeen(document, id, seq(1, 5));
  assert.equal(marked.devices[0].notifications_seen_through, seq(1, 5));
  assert.equal(document.devices[0].notifications_seen_through, undefined, 'not mutated');

  // Backwards or equal is the same document, so a caller can skip the write.
  assert.equal(markNotificationsSeen(marked, id, seq(1, 4)), marked);
  assert.equal(markNotificationsSeen(marked, id, seq(1, 5)), marked);

  const { document: reread } = normaliseVaultDocument(JSON.parse(JSON.stringify(marked)));
  assert.equal(reread.devices[0].notifications_seen_through, seq(1, 5));
});

test('an unparseable read mark reads as none, so nothing is hidden as read', () => {
  const { document } = docWithDevice();
  const raw = JSON.parse(JSON.stringify(document));
  raw.devices[0].notifications_seen_through = 99;
  const { document: reread, dropped } = normaliseVaultDocument(raw);
  assert.equal(dropped, 0, 'the device itself survives');
  assert.equal(reread.devices[0].notifications_seen_through, undefined);
});

test('marking an unknown device or a malformed seq is refused', () => {
  const { document, id } = docWithDevice();
  assert.throws(() => markNotificationsSeen(document, 'nope', seq(1, 1)));
  assert.throws(() => markNotificationsSeen(document, id, '-1'));
  assert.throws(() => markNotificationsSeen(document, id, (1n << 64n).toString()));
});
