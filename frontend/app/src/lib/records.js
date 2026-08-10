/**
 * Reading a device's records once they have been opened (roadmap 6.3).
 *
 * Two jobs, both of them about the difference between what a record *says* and
 * what this client is entitled to claim on the strength of it.
 *
 * **Gaps.** `seq` is `(boot_epoch << 32) | msg_counter` and the counter advances
 * once per record, so two adjacent records from one boot whose counters differ by
 * more than one mean records that were built and never arrived. Firmware drops a
 * record it cannot deliver rather than buffering it (roadmap 5.6), so this is an
 * ordinary outcome of a flaky network, not evidence of anything: it is surfaced
 * as a signal and never as an error. What it must not do is claim more than it
 * knows, and there are three places where the obvious implementation would:
 *
 *   - **Across a `boot_epoch` boundary there is no gap to claim.** The counter
 *     resets on every boot and whether the first record of a boot carries 0 or 1
 *     is the firmware's business (the same reason `sequence.js` says "boot 3,
 *     message 412" rather than "412 records"). A restart is reported as a
 *     restart, which is a true statement about the sequence, and nothing is
 *     asserted about what either boot did or did not send.
 *   - **At the edge of a page there is no gap either.** Adjacency in a response
 *     is adjacency in what the server holds, because a page is contiguous in
 *     `seq` between its bounds. Adjacency to a record that was never fetched is
 *     not adjacency at all, so only pairs actually held are compared.
 *   - **A gap is a lower bound on what is missing, like every other freshness
 *     signal here.** A server can withhold a whole run of records at the end of
 *     the sequence and nothing on this side can tell that from a device that has
 *     stopped reporting. That is the same asymmetry `last-seen.js` is built
 *     around, and the phrasing follows it: what is said is that records are
 *     missing, never why.
 *
 * **Payload shape.** `{ t, r }` (design 7.3, `docs/protocol.md`). The CBOR
 * profile has already refused tags, byte strings and non-text map keys by the
 * time anything gets here, but it has not refused a *record* that is an array,
 * or an `r` holding a nested map, because those are legal CBOR and illegal
 * payloads. Phase 7.2's schema validator is the real allowlist; this is the
 * minimum that has to hold before there is a schema to check against, and it
 * follows the same discipline `vault-document.js` uses for entries it cannot
 * parse: name what was wrong with the record, keep it in the list, and let the
 * screen say so rather than quietly showing a shorter history than the device
 * has.
 *
 * No React and no crypto in this file, so `node --test` reaches it directly.
 */

import { splitSeq } from './sequence.js';

/** How many records a page asks for. */
export const RECORDS_PAGE_SIZE = 50;

/**
 * The scalars a reading value is allowed to be. Deliberately not "anything the
 * CBOR decoder produced": an array or a map in `r` is a payload this version
 * does not understand, and rendering `[object Object]` in a dashboard is worse
 * than saying so.
 */
function isScalar(value) {
  return (
    typeof value === 'string' ||
    typeof value === 'number' ||
    typeof value === 'bigint' ||
    typeof value === 'boolean' ||
    value === null
  );
}

/**
 * Turns one decoded payload into something a screen can render, or names why it
 * cannot.
 *
 * @param {unknown} payload the CBOR-decoded plaintext.
 * @returns {{ deviceTime: number|null, readings: Array<{ key: string, value: unknown }>,
 *             unsupported: string[], problem: string|null }}
 *          `deviceTime` is Unix seconds, or null when the device said it has no
 *          clock (`t = 0`, which must never render as 1970) or carried no `t`.
 */
export function readPayload(payload) {
  const empty = { deviceTime: null, readings: [], unsupported: [], problem: null };

  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
    return { ...empty, problem: 'The payload is not a record map.' };
  }

  // `t` absent is tolerated the same way a clockless device's 0 is: `seq` is the
  // authoritative order (design 7.1), so a payload without a timestamp is still
  // a perfectly good reading and the arrival time is on the row regardless.
  let deviceTime = null;
  if (payload.t !== undefined) {
    if (typeof payload.t !== 'number' && typeof payload.t !== 'bigint') {
      return { ...empty, problem: 'The payload timestamp is not a number.' };
    }
    const seconds = Number(payload.t);
    if (!Number.isFinite(seconds) || seconds < 0) {
      return { ...empty, problem: 'The payload timestamp is not a time.' };
    }
    // 0 is the protocol's "this device has no clock", not the Unix epoch.
    deviceTime = seconds === 0 ? null : seconds;
  }

  if (payload.r === undefined) {
    return { ...empty, deviceTime, problem: 'The payload carries no readings.' };
  }
  if (typeof payload.r !== 'object' || payload.r === null || Array.isArray(payload.r)) {
    return { ...empty, deviceTime, problem: 'The payload readings are not a map.' };
  }

  const readings = [];
  const unsupported = [];
  for (const [key, value] of Object.entries(payload.r)) {
    if (isScalar(value)) readings.push({ key, value });
    else unsupported.push(key);
  }

  return { deviceTime, readings, unsupported, problem: null };
}

/**
 * One reading value as text.
 *
 * `bigint` is not a hypothetical: the CBOR decoder hands back a `bigint` for any
 * integer outside the safe-integer range rather than silently rounding it, and
 * `String()` is the only formatting that does not put that back.
 *
 * @param {unknown} value
 * @returns {string}
 */
export function formatReading(value) {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) return String(value);
    // Floats arrive with whatever precision the device's own conversion left
    // behind: 21.399999618530273 is a half-width float saying 21.4. Trimming to
    // seven significant digits is a display choice and the exact value is still
    // in the export (6.4), which is the artifact that has to stay lossless.
    return Number.isInteger(value) ? String(value) : String(Number(value.toPrecision(7)));
  }
  return String(value);
}

/**
 * What sits between two adjacent records.
 *
 * @param {string} previousSeq the lower `seq`, as the server sends it.
 * @param {string} nextSeq the higher `seq`.
 * @returns {{ kind: 'gap', missing: bigint, bootEpoch: bigint, from: bigint, to: bigint }
 *          | { kind: 'restart', from: bigint, to: bigint }
 *          | null} null when the two are consecutive within one boot.
 */
export function describeStep(previousSeq, nextSeq) {
  const previous = splitSeq(previousSeq);
  const next = splitSeq(nextSeq);
  if (!previous || !next) return null;

  if (previous.bootEpoch !== next.bootEpoch) {
    return { kind: 'restart', from: previous.bootEpoch, to: next.bootEpoch };
  }

  const missing = next.msgCounter - previous.msgCounter - 1n;
  if (missing <= 0n) return null;

  return {
    kind: 'gap',
    missing,
    bootEpoch: next.bootEpoch,
    from: previous.msgCounter,
    to: next.msgCounter,
  };
}

/**
 * The steps between every adjacent pair in a run of records.
 *
 * Takes the records in ascending `seq` order and returns one entry per pair,
 * indexed by the position of the *later* record, so a screen rendering
 * newest-first can look up what sits above each row without re-deriving it.
 *
 * @param {Array<{ seq: string }>} ascending
 * @returns {Map<number, ReturnType<typeof describeStep>>} keyed by index, only
 *          where there is something to say.
 */
export function sequenceSteps(ascending) {
  const steps = new Map();
  for (let index = 1; index < ascending.length; index += 1) {
    const step = describeStep(ascending[index - 1].seq, ascending[index].seq);
    if (step) steps.set(index, step);
  }
  return steps;
}

/**
 * A gap or a restart as a sentence.
 *
 * Worded as an observation about the sequence rather than a diagnosis, for the
 * reason `last-seen.js` never says "offline": a record that was built and never
 * delivered, a record the server is withholding, and a device that was reset
 * mid-run are indistinguishable from here.
 *
 * @param {ReturnType<typeof describeStep>} step
 * @returns {string}
 */
export function describeStepText(step) {
  if (!step) return '';

  if (step.kind === 'restart') {
    const boots = step.to - step.from;
    return boots === 1n
      ? `The device restarted here: boot ${step.from} ended and boot ${step.to} began.`
      : `The device restarted ${boots} times here, between boot ${step.from} and boot ${step.to}.` +
          ' Any records those boots sent did not arrive.';
  }

  const plural = step.missing === 1n ? 'record' : 'records';
  return (
    `Possible missing data: ${step.missing} ${plural} between message ${step.from} and message ` +
    `${step.to} of boot ${step.bootEpoch} never arrived.`
  );
}

/**
 * The device's own timestamp, rendered as a time and labelled by the caller as
 * the device's rather than the server's. Never collapsed with `created_at`: one
 * is authenticated and comes from a clock nothing verifies, the other is when
 * the upload landed and is only as trustworthy as the server.
 *
 * @param {number|null} deviceTime Unix seconds, or null for a clockless device.
 * @returns {string}
 */
export function describeDeviceTime(deviceTime) {
  if (deviceTime === null) return 'No clock';
  const when = new Date(deviceTime * 1000);
  if (!Number.isFinite(when.getTime())) return 'Unreadable';
  return when.toLocaleString();
}
