/**
 * Reading `last_seq` back apart (design 7.1, 7.2).
 *
 * `seq` is `(boot_epoch << 32) | msg_counter`, a uint64, and the server holds the
 * highest one it has accepted per device. As a bare number it tells a reader
 * nothing: 12884901888 is a device that has booted three times and sent nothing
 * since. Split, it says exactly that.
 *
 * **Always `BigInt`, never `Number`.** A uint64 does not survive a double: the
 * value overflows `Number.MAX_SAFE_INTEGER` as soon as `boot_epoch` passes
 * 2^21, and the failure is silent rounding rather than an error. `pg` hands the
 * column back as a string for the same reason, so the string is what arrives
 * here and it must not be coerced on the way in.
 *
 * Free of React and of crypto, so `node --test` reaches it directly.
 */

/** Bits 0-31. `msg_counter` resets to 0 on every boot and counts records. */
const COUNTER_MASK = 0xffffffffn;

/**
 * @param {string|null|undefined} lastSeq as the server sends it: a decimal string.
 * @returns {{ bootEpoch: bigint, msgCounter: bigint }|null}
 *          null when the device has never had a record accepted, or when the
 *          value is not a sequence number at all.
 */
export function splitSeq(lastSeq) {
  if (lastSeq === null || lastSeq === undefined) return null;

  let seq;
  try {
    seq = BigInt(lastSeq);
  } catch {
    return null;
  }

  // `last_seq` starts at 0 and the check in design 7.4 is `seq > last_seq`, so a
  // stored 0 means nothing has ever been accepted rather than "boot 0, message
  // 0". `boot_epoch` is incremented before the first record of every boot, so a
  // real sequence number is always at least 1 << 32.
  if (seq <= 0n) return null;

  return { bootEpoch: seq >> 32n, msgCounter: seq & COUNTER_MASK };
}

/**
 * The same value as a sentence.
 *
 * Deliberately not "412 records": `msg_counter` is the counter's value at the
 * newest record the server accepted, and whether the first record of a boot
 * carries 0 or 1 is the firmware's business. Naming the two components claims
 * only what the number actually says.
 *
 * @param {string|null|undefined} lastSeq
 * @returns {string|null} null when there is no sequence to describe.
 */
export function describeSequence(lastSeq) {
  const parts = splitSeq(lastSeq);
  if (!parts) return null;
  return `Boot ${parts.bootEpoch}, message ${parts.msgCounter}`;
}
