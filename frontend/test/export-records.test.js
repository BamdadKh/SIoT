// Roadmap 6.4: exporting a device's history.
//
// Fetching and decryption are injected, so this runs the real cursor loop and the
// real formatters against an in-memory "server". The claims worth holding are the
// ones an export can get quietly wrong: a row lost at a page boundary, a gap that
// exists on screen and not in the file, an unopenable record that vanishes, and a
// text reading that a spreadsheet would execute.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  buildCsvExport,
  buildJsonExport,
  collectHistory,
} from '../app/src/lib/export-records.js';

const seq = (bootEpoch, msgCounter) => ((BigInt(bootEpoch) << 32n) | BigInt(msgCounter)).toString();

/** `(boot, counter)` pairs to what `GET /records` would return, ascending. */
function serverWith(pairs) {
  const rows = pairs.map(([boot, counter], index) => ({
    seq: seq(boot, counter),
    nonce: 'n',
    ciphertext: `c${index}`,
    created_at: new Date(Date.UTC(2026, 0, 1, 0, 0, index)).toISOString(),
  }));

  const requests = [];
  const fetchPage = (pageSize) => async (afterSeq) => {
    requests.push(afterSeq);
    const from = afterSeq === undefined ? 0 : rows.findIndex((r) => r.seq === afterSeq) + 1;
    return rows.slice(from, from + pageSize);
  };
  return { rows, fetchPage, requests };
}

/** Opens every record as `{ t, r: { n: <index> } }` unless told a ciphertext is bad. */
const opener = (payloadFor, refuse = new Set()) => async (raw) => {
  if (refuse.has(raw.ciphertext)) throw new Error('This record did not open.');
  return payloadFor(raw);
};

const exportOf = (records, extra = {}) => ({
  deviceName: 'Greenhouse',
  deviceId: 'AAAAAAAAAAAAAAAAAAAAAA',
  exportedAt: new Date(Date.UTC(2026, 5, 1)),
  records,
  ...extra,
});

/* --- the cursor loop ----------------------------------------------------- */

test('the loop returns every record whatever the page size, including exact multiples', async () => {
  for (const total of [0, 1, 2, 3, 4, 6, 7]) {
    const pairs = Array.from({ length: total }, (_, i) => [1, i + 1]);
    const { fetchPage } = serverWith(pairs);
    const records = await collectHistory({
      fetchPage: fetchPage(3),
      openRecord: opener(() => ({ t: 1, r: { n: 1 } })),
      pageSize: 3,
    });
    assert.equal(records.length, total, `${total} records`);
    assert.deepEqual(
      records.map((r) => r.seq),
      pairs.map(([b, c]) => seq(b, c)),
    );
  }
});

test('the cursor is the last seq of the previous page', async () => {
  const { fetchPage, requests, rows } = serverWith([[1, 1], [1, 2], [1, 3], [1, 4]]);
  await collectHistory({
    fetchPage: fetchPage(2),
    openRecord: opener(() => ({ t: 1, r: {} })),
    pageSize: 2,
  });
  // 4 records at 2 a page: a full page, a full page, then the empty one that ends it.
  assert.deepEqual(requests, [undefined, rows[1].seq, rows[3].seq]);
});

test('progress is reported after every page', async () => {
  const { fetchPage } = serverWith([[1, 1], [1, 2], [1, 3]]);
  const seen = [];
  await collectHistory({
    fetchPage: fetchPage(2),
    openRecord: opener(() => ({ t: 1, r: {} }), new Set(['c1'])),
    pageSize: 2,
    onProgress: (p) => seen.push(p),
  });
  assert.deepEqual(seen, [
    { fetched: 2, unopened: 1 },
    { fetched: 3, unopened: 1 },
  ]);
});

test('a server that repeats or reorders is refused rather than looped on', async () => {
  const repeating = async () => [
    { seq: seq(1, 1), nonce: 'n', ciphertext: 'a', created_at: 'x' },
    { seq: seq(1, 1), nonce: 'n', ciphertext: 'a', created_at: 'x' },
  ];
  await assert.rejects(
    collectHistory({ fetchPage: repeating, openRecord: opener(() => ({})), pageSize: 2 }),
    /out of order/,
  );
});

test('an abort stops the walk between pages', async () => {
  const { fetchPage } = serverWith([[1, 1], [1, 2], [1, 3], [1, 4]]);
  const controller = new AbortController();
  await assert.rejects(
    collectHistory({
      fetchPage: fetchPage(2),
      openRecord: opener(() => ({ t: 1, r: {} })),
      pageSize: 2,
      signal: controller.signal,
      onProgress: () => controller.abort(),
    }),
    /abort/i,
  );
});

/* --- what the file says -------------------------------------------------- */

async function gappedHistory() {
  // Boot 1: messages 1, 2, then 6 (three missing). Boot 3: message 1 (a restart).
  const { fetchPage } = serverWith([[1, 1], [1, 2], [1, 6], [3, 1]]);
  return collectHistory({
    fetchPage: fetchPage(500),
    // c2 is the one the key will not open.
    openRecord: opener(
      (raw) => ({ t: raw.ciphertext === 'c0' ? 0 : 1_780_000_000, r: { temp_c: 21.5, n: BigInt(raw.ciphertext.slice(1)) } }),
      new Set(['c2']),
    ),
  });
}

test('the JSON carries the gap, the restart and the unopened record, not just the screen', async () => {
  const records = await gappedHistory();
  const doc = JSON.parse(buildJsonExport(exportOf(records)));

  assert.equal(doc.format, 'siot-export/v1');
  assert.equal(doc.device.name, 'Greenhouse');
  assert.equal(doc.record_count, 4);
  assert.equal(doc.unopened_count, 1);
  assert.deepEqual(doc.seq_range, { first: seq(1, 1), last: seq(3, 1) });

  const [first, second, third, fourth] = doc.records;
  assert.equal(first.sequence_note, null);
  assert.equal(second.sequence_note, null);

  // The record the key would not open is a record, in place, with no readings.
  assert.equal(third.status, 'unopened');
  assert.equal(third.readings, null);
  assert.match(third.problem, /did not open/);
  // ...and the gap before it is claimed even though that record is unreadable,
  // since `seq` is the server's and needs no key.
  assert.equal(third.sequence_note.kind, 'gap');
  assert.equal(third.sequence_note.missing, 3);
  assert.match(third.sequence_note.text, /Possible missing data: 3 records/);

  assert.equal(fourth.sequence_note.kind, 'restart');
  assert.equal(fourth.boot_epoch, 3);
  assert.equal(fourth.msg_counter, 1);
});

test('t = 0 is no clock, and the two timestamps stay separate fields', async () => {
  const doc = JSON.parse(buildJsonExport(exportOf(await gappedHistory())));
  assert.equal(doc.records[0].device_time_unix, null);
  assert.equal(doc.records[1].device_time_unix, 1_780_000_000);
  assert.match(doc.records[1].received_at, /^2026-01-01T00:00:01/);
  assert.ok(doc.timestamps.received_at && doc.timestamps.device_time_unix);
});

test('JSON keeps every digit of a uint64 reading and names a NaN instead of hiding it', () => {
  const big = 2n ** 63n + 1n;
  const text = buildJsonExport(
    exportOf([
      {
        seq: seq(1, 1),
        receivedAt: 'x',
        payload: { t: 1, r: { counter: big, temp_c: Number.NaN, up: Number.POSITIVE_INFINITY } },
        error: null,
      },
    ]),
  );
  // As text, not through JSON.parse, which would round it: the file is the claim.
  assert.match(text, /"counter": 9223372036854775809/);
  const record = JSON.parse(text).records[0];
  assert.equal(record.readings.temp_c, null);
  assert.deepEqual(record.non_finite_readings, { temp_c: 'NaN', up: 'Infinity' });
});

test('a reading named __proto__ is an entry in the file like any other', () => {
  const r = {};
  Object.defineProperty(r, '__proto__', { value: 7, enumerable: true, configurable: true, writable: true });
  const text = buildJsonExport(
    exportOf([{ seq: seq(1, 1), receivedAt: 'x', payload: { t: 1, r }, error: null }]),
  );
  assert.equal(Object.hasOwn(JSON.parse(text).records[0].readings, '__proto__'), true);
});

test('CSV: one row per record, gap and problem visible in the row, readings blank where absent', async () => {
  const records = await gappedHistory();
  records[1].payload = { t: 1_780_000_000, r: { temp_c: 22, extra: 'x' } }; // a reading only this record carries
  const lines = buildCsvExport(exportOf(records)).trimEnd().split('\r\n');

  assert.equal(lines.length, 1 + 4);
  assert.equal(
    lines[0],
    'seq,boot_epoch,msg_counter,received_at,device_time_utc,status,sequence_note,temp_c,n,extra',
  );

  // Row count matches the record count, so the cursor loop cannot have dropped one.
  const cells = lines.slice(1).map((line) => line.split(','));
  assert.equal(cells[0][4], ''); // t = 0: blank, never 1970
  assert.equal(cells[1][4], new Date(1_780_000_000 * 1000).toISOString());
  assert.equal(cells[2][5], 'unopened');
  assert.match(lines[3], /Possible missing data: 3 records/);
  assert.match(lines[3], /did not open/);
  assert.match(lines[4], /restarted 2 times/);
  assert.equal(cells[0][9], ''); // `extra` absent on the first record: blank
});

test('CSV defuses text a spreadsheet would run, and leaves numbers alone', () => {
  const csv = buildCsvExport(
    exportOf([
      {
        seq: seq(1, 1),
        receivedAt: 'x',
        payload: { t: 1, r: { note: '=HYPERLINK("http://evil","x")', delta: -5, tag: '+1', ok: 'fine' } },
        error: null,
      },
    ]),
  );
  const [, row] = csv.trimEnd().split('\r\n');
  assert.ok(row.includes(`"'=HYPERLINK(""http://evil"",""x"")"`), row);
  assert.ok(row.includes(',-5,'), 'a real number stays a number');
  assert.ok(row.includes(",'+1,"), row);
  assert.ok(row.endsWith(',fine'));
});

test('CSV defuses a column name too, since it is device-supplied text', () => {
  const csv = buildCsvExport(
    exportOf([{ seq: seq(1, 1), receivedAt: 'x', payload: { t: 1, r: { '=cmd': 1 } }, error: null }]),
  );
  assert.match(csv.split('\r\n')[0], /,'=cmd$/);
});

test('a reading named like a fixed column gets its own column instead of merging into it', () => {
  const csv = buildCsvExport(
    exportOf([{ seq: seq(1, 1), receivedAt: 'x', payload: { t: 1, r: { seq: 9, status: 'hot' } }, error: null }]),
  );
  const [header, row] = csv.trimEnd().split('\r\n');
  assert.ok(header.endsWith(',reading_seq,reading_status'), header);
  assert.ok(row.endsWith(',9,hot'), row);
  assert.ok(row.startsWith(`${seq(1, 1)},1,1,`));
});

test('a payload that is not a record is a row with a problem, not a crash', () => {
  const csv = buildCsvExport(
    exportOf([{ seq: seq(1, 1), receivedAt: 'x', payload: [1, 2], error: null }]),
  );
  assert.match(csv, /unreadable/);
  assert.match(csv, /not a record map/);
});

test('an empty history still produces a well-formed file of each kind', () => {
  const doc = JSON.parse(buildJsonExport(exportOf([])));
  assert.equal(doc.record_count, 0);
  assert.deepEqual(doc.seq_range, { first: null, last: null });
  assert.deepEqual(doc.records, []);
  assert.equal(buildCsvExport(exportOf([])).trimEnd().split('\r\n').length, 1);
});
