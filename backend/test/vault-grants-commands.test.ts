// The three remaining compare-and-swap and ownership boundaries: the vault
// version (3.1), grant ownership (8.2), and the command queue's delivery,
// signed ack and prune (11.2, 11.4). Each was verified once by a throwaway
// probe; these keep them verified.
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import { b64, newAccount, newDevice, random, startApp } from './helpers.js';

let app: Awaited<ReturnType<typeof startApp>>;
before(async () => {
  app = await startApp();
});
after(async () => {
  await app.close();
});

/* --- vault (3.1) ---------------------------------------------------------- */

const putVault = (cookie: string, version: number) =>
  app.inject({
    method: 'PUT',
    url: '/siot/vault',
    headers: { cookie },
    payload: { vault_version: version, ciphertext: random(64) },
  });

test('a never-written vault reads as version 0 with no blob, not a 404', async () => {
  const account = await newAccount(app);
  const response = await app.inject({ method: 'GET', url: '/siot/vault', headers: { cookie: account.cookie } });
  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.json(), { vault_version: 0, ciphertext: null });
});

test('a vault write must be exactly current + 1', async () => {
  const account = await newAccount(app);
  assert.equal((await putVault(account.cookie, 1)).statusCode, 200);
  assert.equal((await putVault(account.cookie, 1)).statusCode, 409, 'a retry finds it consumed');
  assert.equal((await putVault(account.cookie, 3)).statusCode, 409, 'no skipping ahead');
  assert.equal((await putVault(account.cookie, 2)).statusCode, 200);
});

test('two tabs saving at once: exactly one lands', async () => {
  const account = await newAccount(app);
  const results = await Promise.all([1, 2, 3, 4].map(() => putVault(account.cookie, 1)));
  const statuses = results.map((response) => response.statusCode).sort();
  assert.deepEqual(statuses, [200, 409, 409, 409]);
});

/* --- grants (8.2) ---------------------------------------------------------- */

test('a grant needs both devices to be the caller\'s, and keeps every epoch', async () => {
  const owner = await newAccount(app);
  const other = await newAccount(app);
  const a = await newDevice(app, owner);
  const b = await newDevice(app, owner);
  const foreign = await newDevice(app, other);

  const grant = (cookie: string | undefined, from: string, to: string) =>
    app.inject({
      method: 'POST',
      url: '/siot/grants',
      headers: cookie ? { cookie } : {},
      payload: { device_a_id: from, device_b_id: to, ciphertext: random(60) },
    });

  assert.equal((await grant(owner.cookie, a.id, b.id)).statusCode, 201);
  assert.equal((await grant(owner.cookie, a.id, b.id)).statusCode, 201, 'a second epoch, not a replace');
  assert.equal((await grant(owner.cookie, a.id, foreign.id)).statusCode, 403);
  assert.equal((await grant(owner.cookie, foreign.id, b.id)).statusCode, 403);
  assert.equal((await grant(undefined, a.id, b.id)).statusCode, 401);

  // Public, because device A's firmware polls it without a session.
  const list = await app.inject({ method: 'GET', url: `/siot/devices/${a.id}/grants` });
  assert.equal(list.statusCode, 200);
  assert.equal(list.json().grants.length, 2);
  const none = await app.inject({ method: 'GET', url: `/siot/devices/${b.id}/grants` });
  assert.deepEqual(none.json(), { grants: [] });
});

/* --- commands (11.2, 11.4) ------------------------------------------------- */

test('commands queue in order, poll publicly, and are owner-scoped to write', async () => {
  const owner = await newAccount(app);
  const other = await newAccount(app);
  const device = await newDevice(app, owner);

  const queue = (cookie: string | undefined) =>
    app.inject({
      method: 'POST',
      url: `/siot/devices/${device.id}/commands`,
      headers: cookie ? { cookie } : {},
      payload: { nonce: random(12), ciphertext: random(40) },
    });

  const first = await queue(owner.cookie);
  const second = await queue(owner.cookie);
  assert.equal(first.statusCode, 201);
  assert.ok(BigInt(second.json().cursor) > BigInt(first.json().cursor));
  assert.equal((await queue(other.cookie)).statusCode, 404);
  assert.equal((await queue(undefined)).statusCode, 401);

  const poll = await app.inject({ method: 'GET', url: `/siot/devices/${device.id}/commands` });
  assert.deepEqual(
    poll.json().commands.map((c: { cursor: string }) => c.cursor),
    [first.json().cursor, second.json().cursor],
  );
  const unknown = await app.inject({ method: 'GET', url: `/siot/devices/${random(16)}/commands` });
  assert.deepEqual(unknown.json().commands, []);
});

test('an ack is signed by the device, prunes up to its cursor, and replays as a no-op', async () => {
  const owner = await newAccount(app);
  const device = await newDevice(app, owner);
  const cursors: string[] = [];
  for (let index = 0; index < 2; index += 1) {
    const response = await app.inject({
      method: 'POST',
      url: `/siot/devices/${device.id}/commands`,
      headers: { cookie: owner.cookie },
      payload: { nonce: random(12), ciphertext: random(40) },
    });
    cursors.push(response.json().cursor);
  }

  // device_id (16B) || up_to (8B BE), per roadmap 11.4.
  const ack = (upTo: string, signer = device.privateKey) => {
    const bytes = Buffer.alloc(8);
    bytes.writeBigUInt64BE(BigInt(upTo));
    const sig = crypto.sign(null, Buffer.concat([device.idBytes, bytes]), signer);
    return app.inject({
      method: 'POST',
      url: `/siot/devices/${device.id}/commands/ack`,
      payload: { up_to: upTo, sig: b64(sig) },
    });
  };

  const stranger = crypto.generateKeyPairSync('ed25519').privateKey;
  assert.equal((await ack(cursors[1]!, stranger)).statusCode, 401);

  assert.deepEqual((await ack(cursors[0]!)).json(), { pruned: 1 });
  assert.deepEqual((await ack(cursors[0]!)).json(), { pruned: 0 }, 'replay prunes nothing');

  const left = await app.inject({ method: 'GET', url: `/siot/devices/${device.id}/commands` });
  assert.deepEqual(
    left.json().commands.map((c: { cursor: string }) => c.cursor),
    [cursors[1]],
  );
});
