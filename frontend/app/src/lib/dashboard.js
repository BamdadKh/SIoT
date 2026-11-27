/**
 * What a device's dashboard shows, worked out from its schema and the records
 * this page has opened (roadmap 7.3).
 *
 * The widgets are drawn in React; everything they are entitled to claim is
 * decided here, where `node --test` reaches it. There is no per-device code in
 * this file and no widget the schema did not ask for: a panel exists because a
 * field was declared, and its shape is the field's widget hint, looked up in
 * the 7.2 allowlist rather than trusted as a name.
 *
 * Three rules, each the dashboard's version of one the rest of the client
 * already follows:
 *
 *   - **"Latest" means the newest record held, never "now".** The value on a
 *     panel comes with the record it came from, and the screen dates it by
 *     arrival. A server can withhold the newest records and nothing here can tell,
 *     the same asymmetry `last-seen.js` is built around, so no panel says a value
 *     is current.
 *   - **A graph is spaced by record, not by time, and breaks where the sequence
 *     does.** `seq` is the authoritative order (design 7.1); the arrival time is
 *     the server's and the device clock is unverified, so neither gets to place a
 *     point. A gap or a restart (`sequenceSteps`) and a record that would not open
 *     each end a line rather than being drawn across, because a line through
 *     missing records is a claim about readings nobody has.
 *   - **A value that is not its declared type is not drawn.** It is counted, and
 *     the latest one is shown as what it is, the way Readings shows it. Coercing
 *     it onto a graph would make the schema a liar about what the device said.
 *
 * No React and no crypto here, the same split `records.js` uses. The type check
 * is `valueMatchesField` from the schema module, passed in rather than imported:
 * `lib/crypto/` is reached by the `@siot/crypto` alias and nothing else, and
 * `node --test` cannot resolve the alias. One check, not a second copy of it.
 */

import { readRecord, sequenceSteps } from './records.js';

/**
 * @param {{ fields: Array<{ key: string, type: string, widget: string,
 *           min?: number, max?: number }> } | null} schema already normalised.
 * @param {Array<{ seq: string, receivedAt: string, payload: unknown, error: string|null }>} records
 *        ascending by `seq`, as `useDeviceRecords` holds them.
 * @param {(field: object, value: unknown) => boolean} matches `valueMatchesField`.
 * @returns {Array<{ field: object, latest: { value: unknown, seq: string,
 *           receivedAt: string, mismatch: boolean } | null,
 *           series: ReturnType<typeof buildSeries> | null }>}
 *          one panel per declared field, in the schema's order.
 */
export function buildDashboard(schema, records, matches) {
  if (!schema) return [];
  // A notification reads as a record with no readings: it is stepped over, not a
  // break in a line, since nothing is missing from the sequence (roadmap 10.3).
  const opened = records.map((record) => (record.error ? null : readRecord(record)));

  return schema.fields.map((field) => ({
    field,
    latest: latestReading(field, records, opened, matches),
    series: field.widget === 'graph' ? buildSeries(field, records, opened, matches) : null,
  }));
}

/** The newest record that opened and carries this field's key. */
function latestReading(field, records, opened, matches) {
  for (let index = records.length - 1; index >= 0; index -= 1) {
    const read = opened[index];
    if (!read || read.problem) continue;
    const reading = read.readings.find(({ key }) => key === field.key);
    if (!reading) continue;
    return {
      value: reading.value,
      seq: records[index].seq,
      receivedAt: records[index].receivedAt,
      mismatch: !matches(field, reading.value),
    };
  }
  return null;
}

/**
 * A numeric field as line segments over record positions.
 *
 * `x` is the record's index in the run held, counting every record including
 * the ones that did not open, so the spacing is one step per record the server
 * returned. A record that opened and simply did not carry this key does not
 * break the line: a sketch may send a reading on some passes only, and nothing
 * is missing from the sequence.
 *
 * @returns {{ segments: Array<Array<{ x: number, y: number }>>, points: number,
 *             span: number, low: number, high: number, mismatched: number,
 *             breaks: number }}
 *          `span` is the number of records the x axis covers; `low`/`high` the
 *          plotted range; `breaks` how many times the line had to stop.
 */
function buildSeries(field, records, opened, matches) {
  const steps = sequenceSteps(records);
  const segments = [];
  let current = [];
  let mismatched = 0;

  const interrupt = () => {
    if (current.length > 0) segments.push(current);
    current = [];
  };

  for (let index = 0; index < records.length; index += 1) {
    if (steps.has(index)) interrupt();

    const read = opened[index];
    if (!read || read.problem) {
      interrupt();
      continue;
    }
    const reading = read.readings.find(({ key }) => key === field.key);
    if (!reading) continue;

    if (!matches(field, reading.value)) {
      mismatched += 1;
      interrupt();
      continue;
    }
    const y = Number(reading.value);
    if (!Number.isFinite(y)) {
      interrupt();
      continue;
    }
    current.push({ x: index, y });
  }
  interrupt();

  const points = segments.reduce((sum, segment) => sum + segment.length, 0);
  // Only a break between two drawn points is a break: a gap before the first
  // point or after the last one interrupts nothing on screen.
  const breaks = Math.max(0, segments.length - 1);

  const ys = segments.flat().map(({ y }) => y);
  const [low, high] = ys.length > 0 ? padRange(Math.min(...ys), Math.max(...ys)) : [0, 1];

  return { segments, points, span: records.length, low, high, mismatched, breaks };
}

/**
 * A flat line still needs a range to sit in. Padded symmetrically so a constant
 * reading draws through the middle rather than along an edge, where it would
 * read as a minimum.
 */
function padRange(low, high) {
  if (low < high) return [low, high];
  const pad = Math.abs(low) * 0.1 || 1;
  return [low - pad, high + pad];
}

/**
 * Where a value sits on a gauge's dial, clamped, with which side it fell off.
 * The needle cannot leave the dial, so a value outside the declared range has to
 * be said in words or the gauge would be showing the limit as the reading.
 *
 * @param {{ min: number, max: number }} field
 * @param {number|bigint} value
 * @returns {{ fraction: number, outside: 'below'|'above'|null }}
 */
export function gaugePosition(field, value) {
  const number = Number(value);
  if (Number.isNaN(number)) return { fraction: 0, outside: 'below' };
  if (number < field.min) return { fraction: 0, outside: 'below' };
  if (number > field.max) return { fraction: 1, outside: 'above' };
  return { fraction: (number - field.min) / (field.max - field.min), outside: null };
}
