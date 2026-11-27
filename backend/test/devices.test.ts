// Roadmap 4.2 and 4.9: registering and deleting a device, server side.
//
// The delete is the half of 4.9's test the server owns: records, grants and
// queued commands go with the row, the `DEVICE_ID` is free to register again,
// and another account cannot tell "not yours" from "not there". The vault half
// (orphan and unregistered states, the order of the two deletes) is client code
// and is not reached from here.
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';

import { newAccount, newDevice, random, seqOf, signedRecord, startApp, upload } from './helpers.js';

let app: Awaited<ReturnType<typeof startApp>>;
before(async () => {
  app = await startApp();
});
after(async () => {
  await app.close();
});

async function count(table: string, column: string, id: Buffer) {
  const { rows } = await app.pg.query<{ count: string }>(
    `select count(*) from ${table} where ${column} = $1`,
    [id],
  );
  return Number(rows[0]!.count);
}

test('a DEVICE_ID is unique across every account, not per account', async () => {
  const first = await newAccount(app);
  const second = await newAccount(app);
  const device = await newDevice(app, first);
  const response = await app.inject({
    method: 'POST',
    url: '/siot/devices/register',
    headers: { cookie: second.cookie },
    payload: { device_id: device.id, sign_pub: device.signPub },
  });
  assert.equal(response.statusCode, 409);
});

test('registration needs a session and exact byte lengths', async () => {
  const account = await newAccount(app);
  const anonymous = await app.inject({
    method: 'POST',
    url: '/siot/devices/register',
    payload: { device_id: random(16), sign_pub: random(32) },
  });
  assert.equal(anonymous.statusCode, 401);

  const short = await app.inject({
    method: 'POST',
    url: '/siot/devices/register',
    headers: { cookie: account.cookie },
    payload: { device_id: random(15), sign_pub: random(32) },
  });
  assert.equal(short.statusCode, 400);
});

test('the list is scoped to the caller', async () => {
  const first = await newAccount(app);
  const second = await newAccount(app);
  const mine = await newDevice(app, first);
  await newDevice(app, second);
  const list = await app.inject({ method: 'GET', url: '/siot/devices', headers: { cookie: first.cookie } });
  assert.deepEqual(
    list.json().devices.map((d: { device_id: string }) => d.device_id),
    [mine.id],
  );
  assert.match(String(list.headers['cache-control']), /no-store/);
});

test('deleting a device takes its records, grants and commands, and frees the id', async () => {
  const account = await newAccount(app);
  const device = await newDevice(app, account);
  const peer = await newDevice(app, account);

  assert.equal((await upload(app, signedRecord(device, seqOf(1, 1)))).statusCode, 201);
  for (const [a, b] of [
    [peer, device],
    [device, peer],
  ]) {
    const grant = await app.inject({
      method: 'POST',
      url: '/siot/grants',
      headers: { cookie: account.cookie },
      payload: { device_a_id: a!.id, device_b_id: b!.id, ciphertext: random(60) },
    });
    assert.equal(grant.statusCode, 201);
  }
  const queued = await app.inject({
    method: 'POST',
    url: `/siot/devices/${device.id}/commands`,
    headers: { cookie: account.cookie },
    payload: { nonce: random(12), ciphertext: random(40) },
  });
  assert.equal(queued.statusCode, 201);

  const removed = await app.inject({
    method: 'DELETE',
    url: `/siot/devices/${device.id}`,
    headers: { cookie: account.cookie },
  });
  assert.equal(removed.statusCode, 204);

  assert.equal(await count('devices', 'device_id', device.idBytes), 0);
  assert.equal(await count('records', 'device_id', device.idBytes), 0);
  // Both grant columns cascade, by design: neither direction is openable afterwards.
  assert.equal(await count('grants', 'device_a_id', device.idBytes), 0);
  assert.equal(await count('grants', 'device_b_id', device.idBytes), 0);
  assert.equal(await count('device_commands', 'device_id', device.idBytes), 0);
  assert.equal(await count('devices', 'device_id', peer.idBytes), 1, 'the peer is untouched');

  const again = await app.inject({
    method: 'POST',
    url: '/siot/devices/register',
    headers: { cookie: account.cookie },
    payload: { device_id: device.id, sign_pub: device.signPub },
  });
  assert.equal(again.statusCode, 201, 'the DEVICE_ID can be registered again');
});

test('another account gets the same 404 as a device that does not exist', async () => {
  const owner = await newAccount(app);
  const other = await newAccount(app);
  const device = await newDevice(app, owner);

  const theirs = await app.inject({
    method: 'DELETE',
    url: `/siot/devices/${device.id}`,
    headers: { cookie: other.cookie },
  });
  const nobodys = await app.inject({
    method: 'DELETE',
    url: `/siot/devices/${random(16)}`,
    headers: { cookie: other.cookie },
  });
  assert.equal(theirs.statusCode, 404);
  assert.equal(nobodys.statusCode, 404);
  assert.equal(theirs.body, nobodys.body);
  assert.equal(await count('devices', 'device_id', device.idBytes), 1);
});

test('a deleted device uploading gets 404, which the firmware latches on', async () => {
  const account = await newAccount(app);
  const device = await newDevice(app, account);
  await app.inject({
    method: 'DELETE',
    url: `/siot/devices/${device.id}`,
    headers: { cookie: account.cookie },
  });
  assert.equal((await upload(app, signedRecord(device, seqOf(1, 1)))).statusCode, 404);
});
