// Roadmap 4.8: joining the vault's device records against the server's.
//
// These live under `frontend/app/`, unlike everything else this suite covers,
// and are reached by a relative path rather than the `@siot/crypto` alias. That
// is the whole reason `device-list.js` holds no crypto and no React: the three
// join outcomes are tedious to reproduce by hand (an orphan needs a vault entry
// deleted out from under a registered device) and easy to get subtly wrong.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  joinDevices,
  shortDeviceId,
  PAIRED,
  UNREGISTERED,
  ORPHAN,
} from '../app/src/lib/device-list.js';

/** A vault entry, minus the `secret` the join never looks at. */
const vaultDevice = (id, name) => ({ id, name, added_at: '2026-01-01T00:00:00.000Z' });

const serverDevice = (id, lastSeenAt = null, lastSeq = '0') => ({
  device_id: id,
  last_seq: lastSeq,
  last_seen_at: lastSeenAt,
});

test('a device in both is paired, named from the vault and dated from the server', () => {
  const joined = joinDevices(
    [vaultDevice('aaa', 'Greenhouse humidity')],
    [serverDevice('aaa', '2026-08-01T10:00:00.000Z', '4294967297')],
  );

  assert.equal(joined.length, 1);
  assert.deepEqual(joined[0], {
    id: 'aaa',
    name: 'Greenhouse humidity',
    state: PAIRED,
    lastSeq: '4294967297',
    lastSeenAt: '2026-08-01T10:00:00.000Z',
  });
});

test('a device the vault has and the server does not is unregistered', () => {
  const [device] = joinDevices([vaultDevice('aaa', 'Half-added sensor')], []);

  assert.equal(device.state, UNREGISTERED);
  assert.equal(device.name, 'Half-added sensor');
  // Nothing to report: the server has never heard of it, so neither field is a
  // claim this client is entitled to make.
  assert.equal(device.lastSeq, null);
  assert.equal(device.lastSeenAt, null);
});

test('a device the server has and the vault does not is an orphan with no name', () => {
  const [device] = joinDevices([], [serverDevice('bbb', '2026-08-01T10:00:00.000Z')]);

  assert.equal(device.state, ORPHAN);
  // The name only ever existed in the vault, so there is genuinely none to show.
  // Inventing one from the id would make the loss look smaller than it is.
  assert.equal(device.name, null);
  assert.equal(device.lastSeenAt, '2026-08-01T10:00:00.000Z');
});

test('vault order is kept, and orphans come last', () => {
  const joined = joinDevices(
    [vaultDevice('ccc', 'Third added'), vaultDevice('aaa', 'First added')],
    [serverDevice('aaa'), serverDevice('zzz'), serverDevice('ccc')],
  );

  // Not sorted by id or by name: the vault's order is the order they were added
  // in, and the server's (creation time) would silently disagree with it.
  assert.deepEqual(
    joined.map((device) => device.id),
    ['ccc', 'aaa', 'zzz'],
  );
  assert.equal(joined[2].state, ORPHAN);
});

test('the mixed case resolves each device independently', () => {
  const joined = joinDevices(
    [vaultDevice('aaa', 'Paired'), vaultDevice('bbb', 'Unregistered')],
    [serverDevice('aaa'), serverDevice('ccc')],
  );

  assert.deepEqual(
    joined.map((device) => device.state),
    [PAIRED, UNREGISTERED, ORPHAN],
  );
});

test('two devices sharing a name stay two devices', () => {
  // Names are not identifiers and are not unique. `DEVICE_ID` is the only key on
  // either side, and a join that deduplicated by name would lose one of these.
  const joined = joinDevices(
    [vaultDevice('aaa', 'sensor'), vaultDevice('bbb', 'sensor')],
    [serverDevice('aaa'), serverDevice('bbb')],
  );

  assert.equal(joined.length, 2);
  assert.deepEqual(
    joined.map((device) => device.id),
    ['aaa', 'bbb'],
  );
});

test('empty on both sides joins to nothing', () => {
  assert.deepEqual(joinDevices([], []), []);
});

test('a shortened DEVICE_ID keeps both ends', () => {
  // A 128-bit id is 22 base64url characters. Keeping only the front would make
  // two ids look identical exactly when telling them apart is what matters.
  const id = 'AAAAAAAAAAAAAAAABBBBBB';
  const short = shortDeviceId(id);

  assert.equal(short, 'AAAAAA…BBBBBB');
  assert.ok(short.startsWith(id.slice(0, 6)));
  assert.ok(short.endsWith(id.slice(-6)));
});

test('an id short enough to read whole is left alone', () => {
  assert.equal(shortDeviceId('AAAABBBB'), 'AAAABBBB');
});
