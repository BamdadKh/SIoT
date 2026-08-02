/**
 * `seq` handling and the byte layouts derived from it (design Section 7).
 *
 * `seq` is a device-persisted uint64, `(boot_epoch << 32) | msg_counter`, so it
 * overflows a JS `number` and travels as a decimal string on the wire — same
 * reasoning as `vault_version`/`last_seq` elsewhere. This is the one place that
 * string is parsed, bounds-checked, and turned into the nonce and AAD bytes that
 * `POST /records` verifies against, so the two can't drift into checking
 * different things.
 */

import { Type } from '@sinclair/typebox';
import { PROTOCOL_VERSION, RECORD_TYPE_V1, SEQ_MAX_DIGITS, UINT64_MAX } from './wire-format.js';

/** A decimal `numeric(20,0)` string, digit-count-bounded so it can't overflow a uint64 before the value check even runs. */
export const SeqString = Type.String({ pattern: `^[0-9]{1,${SEQ_MAX_DIGITS}}$` });

/** Throws if `value` isn't representable as a uint64 — the digit-count bound in `SeqString` still allows e.g. `99999999999999999999`. */
export function parseSeq(value: string): bigint {
  const seq = BigInt(value);
  if (seq > UINT64_MAX) {
    throw new Error(`seq ${value} exceeds uint64 range`);
  }
  return seq;
}

/** `seq` as 8 bytes big-endian, the tail of both the nonce and the AAD. */
export function seqToBytes(seq: bigint): Buffer {
  const bytes = Buffer.alloc(8);
  bytes.writeBigUInt64BE(seq);
  return bytes;
}

/** `nonce (12B) = 0x00000000 || seq (8B, big-endian)` (design 7.2). */
export function buildNonce(seq: bigint): Buffer {
  return Buffer.concat([Buffer.alloc(4), seqToBytes(seq)]);
}

/**
 * `AAD = version(1B) || DEVICE_ID(16B) || record_type(1B) || seq(8B)` (design 7.3).
 * `version` and `record_type` are fixed v1 protocol constants, not wire fields —
 * see `PROTOCOL_VERSION`/`RECORD_TYPE_V1` in `wire-format.ts`.
 */
export function buildAad(deviceId: Buffer, seq: bigint): Buffer {
  return Buffer.concat([
    Buffer.from([PROTOCOL_VERSION]),
    deviceId,
    Buffer.from([RECORD_TYPE_V1]),
    seqToBytes(seq),
  ]);
}
