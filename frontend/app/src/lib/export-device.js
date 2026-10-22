/**
 * The real fetch and the real decryption behind an export (roadmap 6.4).
 *
 * `export-records.js` is where the format lives and is what `node --test`
 * covers; this is the thin half that needs the browser: the API, and a key
 * derived from the vault entry. It is the same derive-use-zero shape as
 * `use-device-records.js`, for the same reason: a key that outlives the export
 * is a key sitting in memory for as long as the tab stays open.
 *
 * Returns strings and holds no copy of them. What happens next (a `Blob`, an
 * object URL, revoking it once the download has started) belongs to the caller
 * that offers the button, which is also where the cost of a plaintext file gets
 * stated at the moment of the click.
 */

import { decryptRecord, deviceIdBytes, fromBase64Url } from '@siot/crypto';
import { fetchRecords } from './api.js';
import { openKeyRing } from './record-keys.js';
import {
  EXPORT_PAGE_SIZE,
  buildCsvExport,
  buildJsonExport,
  collectHistory,
} from './export-records.js';

/**
 * @param {{ id: string, secret: string, name: string,
 *           retired?: Array<{ secret: string, through_seq: string }> }} entry the vault's
 *        record of the device; `retired` is what keeps pre-rotation records openable.
 * @param {{ format: 'json'|'csv', onProgress?: (p: { fetched: number, unopened: number }) => void,
 *           signal?: AbortSignal }} options
 * @returns {Promise<{ text: string, mime: string, extension: string, recordCount: number,
 *                     unopened: number }>}
 */
export async function exportDeviceRecords(entry, { format, onProgress, signal }) {
  const idBytes = deviceIdBytes({ id: entry.id });
  // One key per secret the device has had, derived on first use (design 9.3).
  const ring = openKeyRing(entry);

  try {
    const records = await collectHistory({
      pageSize: EXPORT_PAGE_SIZE,
      onProgress,
      signal,
      fetchPage: async (afterSeq) =>
        (
          await fetchRecords(entry.id, {
            order: 'asc',
            limit: EXPORT_PAGE_SIZE,
            ...(afterSeq === undefined ? {} : { afterSeq }),
          })
        ).records,
      openRecord: async (raw) =>
        decryptRecord({
          dataKey: await ring.keyFor(raw.seq),
          deviceId: idBytes,
          seq: BigInt(raw.seq),
          nonce: fromBase64Url(raw.nonce),
          ciphertext: fromBase64Url(raw.ciphertext),
        }),
    });

    const unopened = records.filter((record) => record.error !== null).length;
    const built = { deviceName: entry.name, deviceId: entry.id, exportedAt: new Date(), records };
    return format === 'csv'
      ? { text: buildCsvExport(built), mime: 'text/csv', extension: 'csv', recordCount: records.length, unopened }
      : {
          text: buildJsonExport(built),
          mime: 'application/json',
          extension: 'json',
          recordCount: records.length,
          unopened,
        };
  } finally {
    ring.zero();
  }
}
