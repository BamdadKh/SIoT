// Design 7.4: the server's only three checks on a record, and nothing else.
//
// Signature, `seq` monotonicity and nonce well-formedness, each refused with
// its own status, plus the read route's ordering and scoping. The ciphertext is
// random bytes throughout: that the server accepts them is the point, since it
// has no way to tell them from a real reading.
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import {
  newAccount,
  newDevice,
  newDeviceKeys,
  seqOf,
  signedRecord,
  startApp,
  upload,
} from './helpers.js';

let app: Awaited<ReturnType<typeof startApp>>;
before(async () => {
  app = await startApp();
});
after(async () => {
  await app.close();
});

test('a correctly signed record is accepted and moves last_seq and last_seen_at', async () => {
  const account = await newAccount(app);
  const device = await newDevice(app, account);

  assert.equal((await upload(app, signedRecord(device, seqOf(1, 0)))).statusCode, 201);

  const list = await app.inject({
    method: 'GET',
    url: '/siot/devices',
    headers: { cookie: account.cookie },
  });
  const row = list.json().devices.find((d: { device_id: string }) => d.device_id === device.id);
  assert.equal(row.last_seq, seqOf(1, 0));
  assert.ok(row.last_seen_at);
});

test('check 1: a signature by any other key is 401', async () => {
  const account = await newAccount(app);
  const device = await newDevice(app, account);
  const stranger = crypto.generateKeyPairSync('ed25519').privateKey;
  const response = await upload(app, signedRecord(device, seqOf(1, 1), { signer: stranger }));
  assert.equal(response.statusCode, 401);
});

test('check 1: a tampered ciphertext no longer verifies', async () => {
  const account = await newAccount(app);
  const device = await newDevice(app, account);
  const body = signedRecord(device, seqOf(1, 1));
  const bytes = Buffer.from(body.ciphertext, 'base64url');
  bytes[0]! ^= 1;
  const response = await upload(app, { ...body, ciphertext: bytes.toString('base64url') });
  assert.equal(response.statusCode, 401);
});

test('check 2: a replayed or older seq is 409, and the stored history is unchanged', async () => {
  const account = await newAccount(app);
  const device = await newDevice(app, account);
  const first = signedRecord(device, seqOf(1, 5));
  assert.equal((await upload(app, first)).statusCode, 201);
  assert.equal((await upload(app, first)).statusCode, 409, 'the identical record again');
  assert.equal((await upload(app, signedRecord(device, seqOf(1, 4)))).statusCode, 409);

  const { rows } = await app.pg.query<{ count: string }>(
    'select count(*) from records where device_id = $1',
    [device.idBytes],
  );
  assert.equal(rows[0]!.count, '1');
});

test('check 2: two uploads racing at the same seq cannot both land', async () => {
  const account = await newAccount(app);
  const device = await newDevice(app, account);
  const seq = seqOf(1, 1);
  const results = await Promise.all([
    upload(app, signedRecord(device, seq)),
    upload(app, signedRecord(device, seq)),
    upload(app, signedRecord(device, seq)),
  ]);
  const statuses = results.map((response) => response.statusCode).sort();
  assert.deepEqual(statuses, [201, 409, 409]);
});

test('check 3: a nonce that disagrees with the seq is 400, even when signed', async () => {
  const account = await newAccount(app);
  const device = await newDevice(app, account);
  const response = await upload(app, signedRecord(device, seqOf(1, 2), { nonceSeq: seqOf(1, 3) }));
  assert.equal(response.statusCode, 400);
});

test('the full uint64 range is accepted, and one past it is not', async () => {
  const account = await newAccount(app);
  const device = await newDevice(app, account);
  const max = ((1n << 64n) - 1n).toString();
  assert.equal((await upload(app, signedRecord(device, max))).statusCode, 201);
  const over = { ...signedRecord(device, max), seq: (1n << 64n).toString() };
  assert.equal((await upload(app, over)).statusCode, 400);
});

test('an unknown device is 404, and an extra field is a 400 rather than ignored', async () => {
  assert.equal((await upload(app, signedRecord(newDeviceKeys(), seqOf(1, 1)))).statusCode, 404);

  const account = await newAccount(app);
  const device = await newDevice(app, account);
  const response = await app.inject({
    method: 'POST',
    url: '/siot/records',
    payload: { ...signedRecord(device, seqOf(1, 1)), plaintext: 'nope' },
  });
  assert.equal(response.statusCode, 400);
});

test('reading back is owner-scoped and ordered by seq in both directions', async () => {
  const owner = await newAccount(app);
  const other = await newAccount(app);
  const device = await newDevice(app, owner);
  for (const counter of [1, 2, 3, 7]) {
    assert.equal((await upload(app, signedRecord(device, seqOf(2, counter)))).statusCode, 201);
  }

  const read = (cookie: string, query: string) =>
    app.inject({ method: 'GET', url: `/siot/devices/${device.id}/records${query}`, headers: { cookie } });

  const asc = (await read(owner.cookie, '')).json().records.map((r: { seq: string }) => r.seq);
  assert.deepEqual(asc, [1, 2, 3, 7].map((c) => seqOf(2, c)));

  const desc = (await read(owner.cookie, '?order=desc&limit=2')).json().records;
  assert.deepEqual(
    desc.map((r: { seq: string }) => r.seq),
    [seqOf(2, 7), seqOf(2, 3)],
  );

  const older = (await read(owner.cookie, `?order=desc&before_seq=${seqOf(2, 3)}`)).json().records;
  assert.deepEqual(
    older.map((r: { seq: string }) => r.seq),
    [seqOf(2, 2), seqOf(2, 1)],
  );

  assert.equal((await read(other.cookie, '')).statusCode, 404);
  assert.equal(
    (await app.inject({ method: 'GET', url: `/siot/devices/${device.id}/records` })).statusCode,
    401,
  );
});
