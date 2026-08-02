// Roadmap 4.8 / design 5.6: how liveness is worded.
//
// The assertions worth having here are the negative ones. Two claims this must
// never make: that a device is "offline" (the client knows it has not received a
// record, not why), and that any particular gap is too long (devices report on
// wildly different schedules). Both are easy to reintroduce as a "helpful"
// status line later, so they are pinned.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { describeLastSeen, exactLastSeen } from '../app/src/lib/last-seen.js';

const NOW = new Date('2026-08-02T12:00:00.000Z');
const ago = (ms) => new Date(NOW.getTime() - ms).toISOString();

const MINUTE = 60 * 1000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

test('a device that has never reported says so without calling it dead', () => {
  assert.equal(describeLastSeen(null, NOW), 'No records yet');
});

test('the coarsest unit that fits is the one used', () => {
  assert.equal(describeLastSeen(ago(30 * 1000), NOW), 'Last record just now');
  assert.match(describeLastSeen(ago(5 * MINUTE), NOW), /minutes? ago$/);
  assert.match(describeLastSeen(ago(3 * HOUR), NOW), /hours? ago$/);
  assert.match(describeLastSeen(ago(2 * DAY), NOW), /days? ago$/);
  assert.match(describeLastSeen(ago(70 * DAY), NOW), /months? ago$/);
  assert.match(describeLastSeen(ago(800 * DAY), NOW), /years? ago$/);
});

test('a gap of exactly one unit gets the word rather than the digit', () => {
  // `numeric: 'auto'` is why: "yesterday" and "last year" over "1 day ago" and
  // "1 year ago". Pinned because dropping it reads as a regression in the other
  // direction, and because it is what the assertions above have to allow for.
  assert.equal(describeLastSeen(ago(25 * HOUR), NOW), 'Last record yesterday');
  assert.equal(describeLastSeen(ago(400 * DAY), NOW), 'Last record last year');
});

test('no gap, however long, is described as offline or as an error', () => {
  // A sensor that wakes hourly is healthy at 59 minutes and a doorbell is not.
  // No threshold can tell those apart, so none is applied: every gap gets the
  // same shape of sentence and the person who chose the interval judges it.
  for (const elapsed of [MINUTE, HOUR, DAY, 30 * DAY, 900 * DAY]) {
    const text = describeLastSeen(ago(elapsed), NOW);
    assert.match(text, /^Last record /);
    assert.doesNotMatch(text, /offline|dead|down|unreachable|inactive/i);
  }
});

test('a record timestamped in the future is named, not rendered as a schedule', () => {
  // A server clock running ahead would otherwise produce "in 3 minutes", which
  // reads like something is expected rather than like something is wrong.
  const text = describeLastSeen(new Date(NOW.getTime() + 3 * MINUTE).toISOString(), NOW);

  assert.equal(text, 'Last record is timestamped in the future');
  assert.doesNotMatch(text, /^in /);
});

test('an unparseable timestamp is reported rather than swallowed', () => {
  // The value comes from the server, which is untrusted. `Date.parse` returning
  // NaN must not fall through into arithmetic that produces a confident phrase.
  assert.equal(describeLastSeen('not a date', NOW), 'Last record at an unreadable time');
});

test('the exact timestamp is available beside the relative one', () => {
  assert.equal(exactLastSeen(null), undefined);
  assert.equal(exactLastSeen('not a date'), undefined);
  assert.equal(exactLastSeen(ago(HOUR)), new Date(ago(HOUR)).toLocaleString());
});
