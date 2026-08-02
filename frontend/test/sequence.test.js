import test from 'node:test';
import assert from 'node:assert/strict';

import { splitSeq, describeSequence } from '../app/src/lib/sequence.js';

test('a device with no accepted records has no sequence to describe', () => {
  assert.equal(splitSeq('0'), null);
  assert.equal(splitSeq(null), null);
  assert.equal(splitSeq(undefined), null);
  assert.equal(describeSequence('0'), null);
});

test('splits seq into boot_epoch and msg_counter', () => {
  // (3 << 32) | 412
  const seq = ((3n << 32n) | 412n).toString();
  assert.deepEqual(splitSeq(seq), { bootEpoch: 3n, msgCounter: 412n });
  assert.equal(describeSequence(seq), 'Boot 3, message 412');
});

test('the first record of the first boot is boot 1, message 0', () => {
  assert.deepEqual(splitSeq((1n << 32n).toString()), { bootEpoch: 1n, msgCounter: 0n });
});

test('survives the full uint64 range, where Number would silently round', () => {
  const bootEpoch = 0xffffffffn;
  const msgCounter = 0xfffffffen;
  const seq = ((bootEpoch << 32n) | msgCounter).toString();

  assert.deepEqual(splitSeq(seq), { bootEpoch, msgCounter });

  // The property the BigInt is there for: the same value through a double comes
  // back wrong, and quietly.
  assert.notEqual(String(Number(seq)), seq);
});

test('a boot_epoch past 2^21 is where a Number-based split would first lie', () => {
  const seq = ((0x400000n << 32n) | 7n).toString();
  assert.deepEqual(splitSeq(seq), { bootEpoch: 0x400000n, msgCounter: 7n });
  assert.ok(Number(seq) > Number.MAX_SAFE_INTEGER);
});

test('a value that is not a sequence number is not guessed at', () => {
  assert.equal(splitSeq('not a number'), null);
  assert.equal(splitSeq(''), null); // BigInt('') is 0n, which is "no records"
  assert.equal(splitSeq('-1'), null);
  assert.equal(splitSeq('1.5'), null);
  assert.equal(describeSequence('not a number'), null);
});
