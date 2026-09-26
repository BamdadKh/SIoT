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

import {
  decryptRecord,
  deriveDeviceDataKey,
  deviceIdBytes,
  deviceSecretBytes,
  fromBase64Url,
} from '@siot/crypto';
import { fetchRecords } from './api.js';
import {
  EXPORT_PAGE_SIZE,
  buildCsvExport,
  buildJsonExport,
  collectHistory,
} from './export-records.js';

/**
 * @param {{ id: string, secret: string, name: string }} entry the vault's record of the device.
 * @param {{ format: 'json'|'csv', onProgress?: (p: { fetched: number, unopened: number }) => void,
 *           signal?: AbortSignal }} options
 * @returns {Promise<{ text: string, mime: string, extension: string, recordCount: number }>}
 */
export async function exportDeviceRecords(entry, { format, onProgress, signal }) {
  const idBytes = deviceIdBytes({ id: entry.id });
  const dataKey = await deriveDeviceDataKey(deviceSecretBytes({ secret: entry.secret }));

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
      openRecord: (raw) =>
        decryptRecord({
          dataKey,
          deviceId: idBytes,
          seq: BigInt(raw.seq),
          nonce: fromBase64Url(raw.nonce),
          ciphertext: fromBase64Url(raw.ciphertext),
        }),
    });

    const built = { deviceName: entry.name, deviceId: entry.id, exportedAt: new Date(), records };
    return format === 'csv'
      ? { text: buildCsvExport(built), mime: 'text/csv', extension: 'csv', recordCount: records.length }
      : {
          text: buildJsonExport(built),
          mime: 'application/json',
          extension: 'json',
          recordCount: records.length,
        };
  } finally {
    dataKey.fill(0);
  }
}
