/**
 * The keys needed to open one device's records across secret rotations
 * (design 9.3) and across the two record kinds (roadmap 10.3).
 *
 * A rotated device has several secrets and a record at a given `seq` was written
 * under exactly one of them (`secretForSeq`). Each secret yields two keys that can
 * have sealed a record: `device_data_key` for readings and `device_notify_key` for
 * notifications. Nothing on the wire says which, by design (ROADMAP 10.0: the
 * record type stays inside the ciphertext), so the reader holds both.
 *
 * Each distinct secret's pair is derived at most once per ring, lazily, so a page
 * that sits wholly after the last rotation derives one pair, not one per retired
 * secret. Callers `zero()` the ring in a `finally`, the same derive-use-zero shape
 * the single key had: a key that outlives its page is a key sitting in memory
 * while the tab idles.
 */

import {
  deriveDeviceDataKey,
  deriveDeviceNotifyKey,
  deviceSecretBytes,
  fromBase64Url,
  openAnyRecord,
  secretForSeq,
} from '@siot/crypto';

/**
 * @param {{ secret: string, retired?: Array<{ secret: string, through_seq: string }> }} entry
 * @returns {{
 *   keyFor: (seq: string) => Promise<Uint8Array>,
 *   keysFor: (seq: string) => Promise<{ dataKey: Uint8Array, notifyKey: Uint8Array }>,
 *   zero: () => void,
 * }}
 */
export function openKeyRing(entry) {
  /** @type {Map<string, Promise<{ dataKey: Uint8Array, notifyKey: Uint8Array }>>} */
  const pairs = new Map();

  function keysFor(seq) {
    const secret = secretForSeq(entry, seq);
    let pair = pairs.get(secret);
    if (!pair) {
      const bytes = deviceSecretBytes({ secret });
      pair = Promise.all([deriveDeviceDataKey(bytes), deriveDeviceNotifyKey(bytes)]).then(
        ([dataKey, notifyKey]) => ({ dataKey, notifyKey }),
      );
      pairs.set(secret, pair);
    }
    return pair;
  }

  return {
    keysFor,
    async keyFor(seq) {
      return (await keysFor(seq)).dataKey;
    },
    zero() {
      for (const pending of pairs.values()) {
        // A derivation still in flight is zeroed when it lands.
        pending.then(
          ({ dataKey, notifyKey }) => {
            dataKey.fill(0);
            notifyKey.fill(0);
          },
          () => {},
        );
      }
      pairs.clear();
    },
  };
}

/**
 * Opens one raw record from `GET /devices/:id/records` under whichever key fits.
 *
 * The one place the hook, the export and the notification poll all open a
 * record, so the three cannot disagree about what a record is. A record that
 * opens under neither key is returned with `error` set rather than thrown: it
 * stays in the list (6.3), counted and shown in place.
 *
 * @param {ReturnType<typeof openKeyRing>} ring
 * @param {Uint8Array} deviceId 16 bytes
 * @param {{ seq: string, nonce: string, ciphertext: string, created_at: string }} raw
 * @returns {Promise<{ seq: string, receivedAt: string, kind: string|null,
 *   payload: unknown, notification: object|null, error: string|null }>}
 */
export async function openRawRecord(ring, deviceId, raw) {
  const base = { seq: raw.seq, receivedAt: raw.created_at };
  try {
    const { dataKey, notifyKey } = await ring.keysFor(raw.seq);
    const opened = await openAnyRecord({
      dataKey,
      notifyKey,
      deviceId,
      seq: BigInt(raw.seq),
      nonce: fromBase64Url(raw.nonce),
      ciphertext: fromBase64Url(raw.ciphertext),
    });
    return {
      ...base,
      kind: opened.kind,
      payload: opened.kind === 'reading' ? opened.payload : null,
      notification: opened.kind === 'notification' ? opened.notification : null,
      error: null,
    };
  } catch (failure) {
    return { ...base, kind: null, payload: null, notification: null, error: failure.message };
  }
}
