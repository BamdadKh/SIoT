// Roadmap 6.3: reading a device's records once they have been opened.
//
// Under `frontend/app/`, reached by a relative path rather than the
// `@siot/crypto` alias, which is why `records.js` holds no crypto and no React
// (the same split `device-list.js` and `use-vault-devices.js` already use). The
// decryption itself is covered by `record.test.js` and the published vectors;
// what is here is everything this client is allowed to *claim* on the strength
// of a record, which is the part that is easy to overstate by accident.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  describeDeviceTime,
  describeStep,
  describeStepText,
  formatReading,
  readPayload,
  sequenceSteps,
} from '../app/src/lib/records.js';

/** `(boot_epoch << 32) | msg_counter`, as the server sends it: a decimal string. */
const seq = (bootEpoch, msgCounter) => ((BigInt(bootEpoch) << 32n) | BigInt(msgCounter)).toString();

/* --- gaps ---------------------------------------------------------------- */

test('consecutive records in one boot have nothing between them', () => {
  assert.equal(describeStep(seq(7, 41), seq(7, 42)), null);
});

test('a jump in msg_counter within a boot is a gap, sized', () => {
  const step = describeStep(seq(7, 41), seq(7, 45));
  assert.equal(step.kind, 'gap');
  assert.equal(step.missing, 3n);
  assert.equal(step.bootEpoch, 7n);
  assert.equal(step.from, 41n);
  assert.equal(step.to, 45n);
});

test('a boot boundary is a restart, never a gap', () => {
  // The counter resets on every boot and whether a boot's first record carries
  // 0 or 1 is the firmware's business, so there is no missing count to claim
  // here however far apart the two counters happen to be.
  const step = describeStep(seq(7, 900), seq(8, 0));
  assert.equal(step.kind, 'restart');
  assert.equal(step.from, 7n);
  assert.equal(step.to, 8n);
  assert.equal(step.missing, undefined);
});

test('several boots with nothing delivered are reported as several restarts', () => {
  const step = describeStep(seq(3, 12), seq(7, 0));
  assert.equal(step.kind, 'restart');
  assert.match(describeStepText(step), /restarted 4 times/);
});

test('gap phrasing never diagnoses a cause', () => {
  // Same rule as `last-seen.js`: a record dropped by firmware that could not
  // deliver it, a record the server is withholding, and a device that was reset
  // are indistinguishable from here, so nothing may be asserted about which.
  const text = describeStepText(describeStep(seq(7, 41), seq(7, 45)));
  assert.match(text, /Possible missing data/);
  assert.doesNotMatch(text, /offline|failed|error|lost|server dropped/i);
});

test('one missing record is singular', () => {
  assert.match(describeStepText(describeStep(seq(2, 5), seq(2, 7))), /1 record between/);
});

test('the sequence never being reused means a step is never negative', () => {
  // `seq > last_seq` is enforced server-side (design 7.4 check 2), so this pair
  // cannot arrive from a conforming server; if it ever does, saying nothing is
  // the right answer rather than reporting a negative gap.
  assert.equal(describeStep(seq(4, 9), seq(4, 9)), null);
  assert.equal(describeStep(seq(4, 9), seq(4, 8)), null);
});

test('steps are keyed by the later record, and only where there is something to say', () => {
  const steps = sequenceSteps([
    { seq: seq(1, 0) },
    { seq: seq(1, 1) },
    { seq: seq(1, 5) },
    { seq: seq(2, 0) },
  ]);
  assert.deepEqual([...steps.keys()], [2, 3]);
  assert.equal(steps.get(2).kind, 'gap');
  assert.equal(steps.get(3).kind, 'restart');
});

test('a single record has no steps at all, because adjacency needs two', () => {
  assert.equal(sequenceSteps([{ seq: seq(1, 0) }]).size, 0);
  assert.equal(sequenceSteps([]).size, 0);
});

test('the counter reaching its full uint32 width is still exact', () => {
  // The whole reason this goes through BigInt: `seq` leaves the safe-integer
  // range once `boot_epoch` passes 2^21, and rounding here would silently
  // invent or erase missing records.
  const step = describeStep(seq(4_000_000, 4_294_967_290), seq(4_000_000, 4_294_967_295));
  assert.equal(step.kind, 'gap');
  assert.equal(step.missing, 4n);
});

/* --- payload shape ------------------------------------------------------- */

test('an ordinary payload reads as its readings', () => {
  const parsed = readPayload({ t: 1_785_000_000, r: { temp_c: 21.4, rssi: -64, ok: true } });
  assert.equal(parsed.problem, null);
  assert.equal(parsed.deviceTime, 1_785_000_000);
  assert.deepEqual(parsed.readings, [
    { key: 'temp_c', value: 21.4 },
    { key: 'rssi', value: -64 },
    { key: 'ok', value: true },
  ]);
  assert.deepEqual(parsed.unsupported, []);
});

test('t = 0 is a device with no clock, never 1970', () => {
  const parsed = readPayload({ t: 0, r: { n: 1 } });
  assert.equal(parsed.deviceTime, null);
  assert.equal(parsed.problem, null);
  assert.equal(describeDeviceTime(parsed.deviceTime), 'No clock');
  assert.doesNotMatch(describeDeviceTime(parsed.deviceTime), /1970/);
});

test('a payload with no t at all is still a reading', () => {
  // `seq` is the authoritative order (design 7.1), so a timestamp is not what
  // makes a record usable.
  const parsed = readPayload({ r: { n: 1 } });
  assert.equal(parsed.problem, null);
  assert.equal(parsed.deviceTime, null);
});

test('a payload that is not a record map is named, not thrown', () => {
  for (const payload of [null, 42, 'readings', [1, 2, 3]]) {
    const parsed = readPayload(payload);
    assert.equal(parsed.problem, 'The payload is not a record map.');
    assert.deepEqual(parsed.readings, []);
  }
});

test('a payload missing r, or with a non-map r, is named', () => {
  assert.match(readPayload({ t: 1 }).problem, /carries no readings/);
  assert.match(readPayload({ t: 1, r: 5 }).problem, /not a map/);
  assert.match(readPayload({ t: 1, r: [1, 2] }).problem, /not a map/);
});

test('a non-numeric or impossible timestamp is named rather than rendered', () => {
  assert.match(readPayload({ t: 'now', r: {} }).problem, /not a number/);
  assert.match(readPayload({ t: -1, r: {} }).problem, /not a time/);
});

test('a nested value is set aside by name rather than rendered as [object Object]', () => {
  // Legal CBOR, illegal payload. Phase 7.2's schema validator is the real
  // allowlist; this is the minimum that has to hold before there is a schema.
  const parsed = readPayload({ t: 1, r: { temp: 21, extra: { a: 1 }, list: [1] } });
  assert.equal(parsed.problem, null);
  assert.deepEqual(parsed.readings, [{ key: 'temp', value: 21 }]);
  assert.deepEqual(parsed.unsupported, ['extra', 'list']);
});

test('null is a reading, not an unsupported value', () => {
  const parsed = readPayload({ t: 1, r: { unread: null } });
  assert.deepEqual(parsed.readings, [{ key: 'unread', value: null }]);
  assert.deepEqual(parsed.unsupported, []);
});

/* --- rendering values ---------------------------------------------------- */

test('a float carrying its conversion noise is trimmed for display', () => {
  // 21.4 through a half-width CBOR float and back. The exact value stays in the
  // export (6.4), which is the artifact that has to be lossless.
  assert.equal(formatReading(21.399999618530273), '21.4');
  assert.equal(formatReading(21), '21');
  assert.equal(formatReading(-64), '-64');
});

test('an integer outside the safe range keeps every digit', () => {
  // The CBOR decoder hands these back as bigint rather than rounding, and
  // formatting must not put the rounding back.
  assert.equal(formatReading(18_446_744_073_709_551_615n), '18446744073709551615');
});

test('booleans, null and text render as themselves', () => {
  assert.equal(formatReading(true), 'true');
  assert.equal(formatReading(false), 'false');
  assert.equal(formatReading(null), 'null');
  assert.equal(formatReading('open'), 'open');
});
