/**
 * Turning a device's whole history into a file (roadmap 6.4).
 *
 * There is no server-side half and there must not be one: a CSV endpoint has to
 * read the readings to know its columns, and the server cannot read anything.
 * Everything here runs on records this browser has already fetched and opened,
 * and produces a string for the caller to hand to the disk.
 *
 * **A file on disk is outside every guarantee in the design document.** It is
 * plaintext, it is not in the vault, and nothing can follow it. That is a
 * legitimate thing to want, and it is why what the file *says* has to be at
 * least as honest as the screen was: it is the artifact that outlives the UI.
 * Three consequences shape everything below:
 *
 *   - **Gaps and restarts travel with the rows.** A CSV whose rows run
 *     continuously across a `seq` gap is a lie about the data, so the row after
 *     a gap or a restart says so in a `sequence_note` column (and the JSON does
 *     the same per record), using the exact wording the screen uses.
 *   - **A record that would not open is a row, not an omission.** After a
 *     re-provisioning (roadmap 8.4) the old records are genuinely unopenable,
 *     and an export that dropped them would report a shorter history than the
 *     device has. They appear with `status` = `unopened` and no readings, and
 *     the header counts them.
 *   - **Two timestamps, never merged.** `received_at` is the server's clock at
 *     arrival and is only as trustworthy as the server. `device_time` is inside
 *     the authenticated payload but comes from a clock nothing verifies, and
 *     `t = 0` means "no clock" and is blank, never 1970. `seq` is the sole
 *     authoritative order, so it is what the file is sorted by.
 *
 * JSON is the lossless format (integers beyond 2^53 keep every digit, and a NaN
 * a failed sensor read produced is recorded rather than turned into a lie). CSV
 * is the format people actually open, and is not lossless: a missing reading and
 * a null one are both blank, and text that a spreadsheet would execute is
 * defused (see `csvCell`).
 *
 * No React and no crypto in this file, so `node --test` reaches it directly. The
 * fetch and the decryption are injected; `export-device.js` supplies the real ones.
 */

import { describeStepText, readPayload, sequenceSteps } from './records.js';
import { splitSeq } from './sequence.js';

/** The route's own maximum (roadmap 6.2). Fewer round trips than the screen's 50. */
export const EXPORT_PAGE_SIZE = 500;

export const EXPORT_FORMAT = 'siot-export/v1';

/* --- walking the history ------------------------------------------------- */

/**
 * Fetches every record a device has, oldest first, and opens each one.
 *
 * A loop over `after_seq`, because the route is cursor paginated. A device
 * reporting every thirty seconds for a year is thousands of round trips, so
 * `onProgress` fires after every page: a silent freeze is indistinguishable from
 * a hang.
 *
 * @param {object} options
 * @param {(afterSeq: string|undefined) => Promise<Array<{ seq: string, nonce: string,
 *          ciphertext: string, created_at: string }>>} options.fetchPage ascending,
 *        strictly after the cursor, at most `pageSize`.
 * @param {(record: object) => Promise<unknown>} options.openRecord the decoded
 *        payload, or a throw for a record that will not open.
 * @param {(progress: { fetched: number, unopened: number }) => void} [options.onProgress]
 * @param {AbortSignal} [options.signal]
 * @param {number} [options.pageSize] must match what `fetchPage` asks the server for.
 * @returns {Promise<Array<{ seq: string, receivedAt: string, payload: unknown, error: string|null }>>}
 */
export async function collectHistory({
  fetchPage,
  openRecord,
  onProgress,
  signal,
  pageSize = EXPORT_PAGE_SIZE,
}) {
  const records = [];
  let unopened = 0;
  let cursor;

  for (;;) {
    signal?.throwIfAborted();
    const page = await fetchPage(cursor);

    for (const raw of page) {
      // The cursor loop's own safety: a server that repeats or reorders would
      // otherwise make this loop forever, or silently emit a file whose order
      // is not `seq`. Refusing is louder than either.
      if (records.length > 0 && BigInt(raw.seq) <= BigInt(records[records.length - 1].seq)) {
        throw new Error('The server returned records out of order; the export was stopped.');
      }
      try {
        const payload = await openRecord(raw);
        records.push({ seq: raw.seq, receivedAt: raw.created_at, payload, error: null });
      } catch (failure) {
        unopened += 1;
        records.push({ seq: raw.seq, receivedAt: raw.created_at, payload: null, error: failure.message });
      }
    }

    onProgress?.({ fetched: records.length, unopened });

    // A short page means nothing more after the cursor. An exact multiple costs
    // one extra, empty fetch, which is the price of not trusting a count.
    if (page.length < pageSize) return records;
    cursor = page[page.length - 1].seq;
  }
}

/* --- the shared reading of a record -------------------------------------- */

/**
 * One record, with everything both formats need worked out once so the two
 * cannot disagree about it.
 */
function describeRecords(records) {
  const steps = sequenceSteps(records);

  return records.map((record, index) => {
    const parts = splitSeq(record.seq);
    const step = steps.get(index);
    const opened = record.error === null ? readPayload(record.payload) : null;

    let status = 'ok';
    let problem = null;
    if (record.error !== null) {
      status = 'unopened';
      problem = record.error;
    } else if (opened.problem !== null) {
      status = 'unreadable';
      problem = opened.problem;
    }

    return {
      seq: record.seq,
      bootEpoch: parts ? parts.bootEpoch : null,
      msgCounter: parts ? parts.msgCounter : null,
      receivedAt: record.receivedAt,
      deviceTime: opened ? opened.deviceTime : null,
      readings: opened ? opened.readings : [],
      unsupported: opened ? opened.unsupported : [],
      status,
      problem,
      sequenceNote: step
        ? {
            kind: step.kind,
            text: describeStepText(step),
            ...(step.kind === 'gap' ? { missing: step.missing } : {}),
          }
        : null,
    };
  });
}

function isoFromSeconds(seconds) {
  if (seconds === null) return null;
  const when = new Date(seconds * 1000);
  return Number.isFinite(when.getTime()) ? when.toISOString() : null;
}

function summarise(described) {
  return {
    recordCount: described.length,
    unopenedCount: described.filter((row) => row.status !== 'ok').length,
    first: described.length > 0 ? described[0].seq : null,
    last: described.length > 0 ? described[described.length - 1].seq : null,
  };
}

/* --- JSON ---------------------------------------------------------------- */

/**
 * Serialises the restricted value set this file produces. `JSON.stringify`
 * throws on a bigint and there is no replacer that emits a bare number, so this
 * is the smallest thing that keeps a uint64 reading's digits. A `Map` is an
 * object: reading keys come from a device, and `obj['__proto__'] = ...` on a
 * plain object is not an entry.
 */
function jsonText(value, level = 0) {
  if (value === null) return 'null';
  if (typeof value === 'bigint') return value.toString();
  if (typeof value !== 'object') return JSON.stringify(value);

  const inner = '  '.repeat(level + 1);
  const outer = '  '.repeat(level);

  if (Array.isArray(value)) {
    if (value.length === 0) return '[]';
    return `[\n${value.map((item) => inner + jsonText(item, level + 1)).join(',\n')}\n${outer}]`;
  }

  const entries = value instanceof Map ? [...value] : Object.entries(value);
  const kept = entries.filter(([, item]) => item !== undefined);
  if (kept.length === 0) return '{}';
  return `{\n${kept
    .map(([key, item]) => `${inner}${JSON.stringify(key)}: ${jsonText(item, level + 1)}`)
    .join(',\n')}\n${outer}}`;
}

/**
 * The lossless export.
 *
 * @param {object} options
 * @param {string} options.deviceName the name from the vault, for the header.
 * @param {string} options.deviceId base64url.
 * @param {Date} options.exportedAt
 * @param {Array} options.records what `collectHistory` returned.
 * @returns {string}
 */
export function buildJsonExport({ deviceName, deviceId, exportedAt, records }) {
  const described = describeRecords(records);
  const summary = summarise(described);

  const document = {
    format: EXPORT_FORMAT,
    device: { name: deviceName, id: deviceId },
    exported_at: exportedAt.toISOString(),
    seq_range: { first: summary.first, last: summary.last },
    record_count: summary.recordCount,
    unopened_count: summary.unopenedCount,
    timestamps: {
      received_at: "the server's clock when the upload arrived; only as trustworthy as the server",
      device_time_unix:
        "the device's own clock, inside the authenticated payload but verified by nothing; null means the device reported no clock",
    },
    records: described.map((row) => {
      const readings = new Map();
      const nonFinite = new Map();
      for (const { key, value } of row.readings) {
        if (typeof value === 'number' && !Number.isFinite(value)) {
          // JSON has no NaN or Infinity, and a failed sensor read is exactly how
          // a device produces one. Null in place, the real value named beside it.
          readings.set(key, null);
          nonFinite.set(key, String(value));
        } else {
          readings.set(key, value);
        }
      }

      return {
        seq: row.seq,
        boot_epoch: row.bootEpoch,
        msg_counter: row.msgCounter,
        received_at: row.receivedAt,
        device_time_unix: row.deviceTime,
        status: row.status,
        problem: row.problem,
        sequence_note: row.sequenceNote,
        readings: row.status === 'ok' ? readings : null,
        ...(nonFinite.size > 0 ? { non_finite_readings: nonFinite } : {}),
        ...(row.unsupported.length > 0 ? { unsupported_readings: row.unsupported } : {}),
      };
    }),
  };

  return `${jsonText(document)}\n`;
}

/* --- CSV ----------------------------------------------------------------- */

const FIXED_COLUMNS = [
  'seq',
  'boot_epoch',
  'msg_counter',
  'received_at',
  'device_time_utc',
  'status',
  'sequence_note',
];

/**
 * One cell, quoted per RFC 4180.
 *
 * A spreadsheet treats a cell that begins `=`, `+`, `-`, `@`, tab or carriage
 * return as a formula, and a text reading is whatever the device's program
 * chose to say: `=HYPERLINK(...)` in a reading is a link somebody else picked,
 * clicked by the person who opened their own export. A leading apostrophe makes
 * the cell text in every spreadsheet that matters. Only text is defused; a
 * number is written as a number, which is why this takes the value's type.
 */
function csvCell(value) {
  if (value === null || value === undefined) return '';
  let text = typeof value === 'string' ? value : String(value);
  if (typeof value === 'string' && /^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

/**
 * A reading key that collides with a fixed column is renamed rather than
 * merged into it, since the two would otherwise be one column of unrelated
 * things. The rename is deterministic so a second export lines up with the first.
 */
function readingColumns(described) {
  const taken = new Set(FIXED_COLUMNS);
  const columnFor = new Map();

  for (const row of described) {
    for (const { key } of row.readings) {
      if (columnFor.has(key)) continue;
      let name = key;
      while (taken.has(name)) name = `reading_${name}`;
      taken.add(name);
      columnFor.set(key, name);
    }
  }
  return columnFor;
}

/**
 * The export people open.
 *
 * One row per record in `seq` order, columns from the union of reading keys seen
 * across the whole history in first-seen order: a schema would be tidier
 * (Phase 7), but the union is what stays correct for a device whose readings
 * changed shape partway through its life.
 *
 * @param {object} options
 * @param {Array} options.records what `collectHistory` returned.
 * @returns {string}
 */
export function buildCsvExport({ records }) {
  const described = describeRecords(records);
  const columnFor = readingColumns(described);
  const keys = [...columnFor.keys()];

  const lines = [[...FIXED_COLUMNS, ...columnFor.values()].map(csvCell).join(',')];

  for (const row of described) {
    const byKey = new Map(row.readings.map(({ key, value }) => [key, value]));
    const note = [row.sequenceNote?.text, row.problem].filter(Boolean).join(' ');

    const cells = [
      row.seq,
      row.bootEpoch === null ? '' : String(row.bootEpoch),
      row.msgCounter === null ? '' : String(row.msgCounter),
      row.receivedAt,
      isoFromSeconds(row.deviceTime) ?? '',
      row.status,
      note,
      ...keys.map((key) => (byKey.has(key) ? byKey.get(key) : '')),
    ];

    lines.push(cells.map(csvCell).join(','));
  }

  return `${lines.join('\r\n')}\r\n`;
}
