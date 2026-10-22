/**
 * The data keys needed to open one device's records across secret rotations
 * (design 9.3).
 *
 * A rotated device has several secrets and a record at a given `seq` was written
 * under exactly one of them (`secretForSeq`). This derives each distinct secret's
 * `device_data_key` at most once per ring, lazily, so a page that sits wholly
 * after the last rotation derives one key, not one per retired secret. Callers
 * `zero()` the ring in a `finally`, the same derive-use-zero shape the single key
 * had: a key that outlives its page is a key sitting in memory while the tab idles.
 */

import { deriveDeviceDataKey, deviceSecretBytes, secretForSeq } from '@siot/crypto';

/**
 * @param {{ secret: string, retired?: Array<{ secret: string, through_seq: string }> }} entry
 * @returns {{ keyFor: (seq: string) => Promise<Uint8Array>, zero: () => void }}
 */
export function openKeyRing(entry) {
  /** @type {Map<string, Promise<Uint8Array>>} */
  const keys = new Map();

  return {
    keyFor(seq) {
      const secret = secretForSeq(entry, seq);
      let key = keys.get(secret);
      if (!key) {
        key = deriveDeviceDataKey(deviceSecretBytes({ secret }));
        keys.set(secret, key);
      }
      return key;
    },
    zero() {
      for (const pending of keys.values()) {
        // A derivation still in flight is zeroed when it lands.
        pending.then((key) => key.fill(0), () => {});
      }
      keys.clear();
    },
  };
}
