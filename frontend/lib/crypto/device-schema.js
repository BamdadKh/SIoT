/**
 * What a device's readings mean (design Section 11, roadmap 7.1 and 7.2).
 *
 * A schema is a list of fields, one per reading key the device sends, each
 * saying what the value is, what to call it, and how a dashboard should show it.
 * It lives on the device's vault entry, sealed under `vault_key` with everything
 * else, so the server never learns that `t` is a bedroom temperature. Same
 * reasoning as the name.
 *
 * **A schema is untrusted input (design 11.1), and this file is the allowlist.**
 * Today every schema was typed by the account that reads it, but Phase 8 grants
 * hand one account's devices to another, and a schema is what drives rendering.
 * So nothing downstream of this file is allowed to look at a raw schema: the
 * only shapes that come out are the ones built here, from a fixed set of types,
 * a fixed set of widgets per type, bounded strings cleaned of invisibles, and
 * finite numbers. Unknown properties are not carried through, so there is no
 * field a later renderer could be tempted to trust because "it was in the
 * schema". No string from a schema is ever a class name, a URL, a style, a tag
 * or code; it is text React escapes, and that is all it is.
 *
 * Two entry points, deliberately not one:
 *
 *   - `normaliseSchema` reads what came out of the vault. Tolerant per field: one
 *     field it cannot parse is dropped and counted, the rest survive, the same
 *     rule `normaliseVaultDocument` applies to device entries.
 *   - `buildSchema` validates what a person is about to save. Strict: any field
 *     that would be dropped on read is refused here instead, with a message
 *     saying which and why, so nothing is written that a reader would discard.
 *
 * No React here; `node --test` reaches it directly.
 */

import { cleanDisplayText } from './display-text.js';

export const SCHEMA_VERSION = 1;

/**
 * Matches `SIOT_READING_NAME_MAX` in the device library. A key longer than the
 * firmware can send describes a reading that can never arrive.
 */
export const SCHEMA_KEY_MAX_LENGTH = 24;
export const SCHEMA_LABEL_MAX_LENGTH = 32;
export const SCHEMA_UNIT_MAX_LENGTH = 12;

/**
 * Bounds the document, not a guess at how many sensors a board has. The device
 * library caps a record at far fewer readings than this.
 */
export const SCHEMA_MAX_FIELDS = 32;

/**
 * The whole type allowlist, and which widgets each type may ask for. A widget
 * hint is a request a renderer may honour, never an instruction: the renderer
 * owns the mapping from these names to components, and a name not in this table
 * never reaches it.
 *
 * `toggle` renders state only. Writing back to a device is Phase 11's command
 * channel, and a schema declaring a toggle grants nothing by itself.
 */
export const SCHEMA_WIDGETS = Object.freeze({
  number: Object.freeze(['value', 'graph', 'gauge']),
  boolean: Object.freeze(['value', 'toggle']),
  text: Object.freeze(['value']),
});

export const SCHEMA_TYPES = Object.freeze(Object.keys(SCHEMA_WIDGETS));

/**
 * One field, validated, as a new object holding only what this file names.
 *
 * Throws `TypeError` with a message fit to show the person who typed it.
 *
 * @param {unknown} raw
 * @returns {{ key: string, label?: string, type: 'number'|'boolean'|'text',
 *             unit?: string, widget: string, min?: number, max?: number }}
 */
export function parseSchemaField(raw) {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    throw new TypeError('A field must be an object.');
  }

  const key = parseKey(raw.key);

  // `Object.hasOwn` rather than `in`: a key like `constructor` must not find
  // something on the prototype and pass as a type.
  if (typeof raw.type !== 'string' || !Object.hasOwn(SCHEMA_WIDGETS, raw.type)) {
    throw new TypeError(`${key}: the type must be one of ${SCHEMA_TYPES.join(', ')}.`);
  }
  const type = raw.type;

  if (typeof raw.widget !== 'string' || !SCHEMA_WIDGETS[type].includes(raw.widget)) {
    throw new TypeError(
      `${key}: a ${type} reading can be shown as ${SCHEMA_WIDGETS[type].join(' or ')}.`,
    );
  }
  const widget = raw.widget;

  const field = { key, type, widget };

  const label = optionalText(raw.label, SCHEMA_LABEL_MAX_LENGTH, `${key}: the label`);
  if (label) field.label = label;

  // A unit on a boolean or a string has nothing to qualify, so it is not kept
  // rather than refused: switching a field's type in the form should not make it
  // unsaveable because of a leftover the person can no longer see.
  if (type === 'number') {
    const unit = optionalText(raw.unit, SCHEMA_UNIT_MAX_LENGTH, `${key}: the unit`);
    if (unit) field.unit = unit;
  }

  // A gauge without a range is a needle with no dial. Required for a gauge and
  // dropped for everything else, for the same reason as the unit.
  if (widget === 'gauge') {
    const min = finite(raw.min, `${key}: the gauge minimum`);
    const max = finite(raw.max, `${key}: the gauge maximum`);
    if (!(min < max)) {
      throw new TypeError(`${key}: the gauge minimum must be below its maximum.`);
    }
    field.min = min;
    field.max = max;
  }

  return field;
}

/**
 * Validates a complete field list for saving. Refuses rather than repairs.
 *
 * @param {unknown[]} fields
 * @returns {{ v: number, fields: ReturnType<typeof parseSchemaField>[] } | null}
 *          null for an empty list: a device with no fields declared has no
 *          schema, and storing an empty one would be a second way to say that.
 */
export function buildSchema(fields) {
  if (!Array.isArray(fields)) throw new TypeError('Fields must be a list.');
  if (fields.length > SCHEMA_MAX_FIELDS) {
    throw new TypeError(`A device can declare at most ${SCHEMA_MAX_FIELDS} fields.`);
  }

  const parsed = [];
  const seen = new Set();
  for (const raw of fields) {
    const field = parseSchemaField(raw);
    // Two fields for one key would leave the renderer choosing between them.
    if (seen.has(field.key)) throw new TypeError(`${field.key} is declared twice.`);
    seen.add(field.key);
    parsed.push(field);
  }

  return parsed.length === 0 ? null : { v: SCHEMA_VERSION, fields: parsed };
}

/**
 * Reads a schema out of a vault entry.
 *
 * @param {unknown} raw
 * @returns {{ schema: ReturnType<typeof buildSchema>, dropped: number }}
 *          `dropped` counts fields that were present and could not be read. A
 *          schema that is not an object at all counts as one.
 */
export function normaliseSchema(raw) {
  if (raw === undefined || raw === null) return { schema: null, dropped: 0 };
  if (typeof raw !== 'object' || Array.isArray(raw) || !Array.isArray(raw.fields)) {
    return { schema: null, dropped: 1 };
  }
  // A newer schema version is a shape this client does not know. Reading it as
  // v1 would be guessing, and guessing is what the allowlist exists to prevent.
  if (raw.v !== SCHEMA_VERSION) return { schema: null, dropped: raw.fields.length || 1 };

  const fields = [];
  const seen = new Set();
  let dropped = 0;

  for (const entry of raw.fields.slice(0, SCHEMA_MAX_FIELDS)) {
    try {
      const field = parseSchemaField(entry);
      if (seen.has(field.key)) throw new TypeError('duplicate key');
      seen.add(field.key);
      fields.push(field);
    } catch {
      dropped += 1;
    }
  }
  dropped += Math.max(0, raw.fields.length - SCHEMA_MAX_FIELDS);

  return {
    schema: fields.length === 0 ? null : { v: SCHEMA_VERSION, fields },
    dropped,
  };
}

/**
 * The field declared for a reading key, or null.
 *
 * @param {ReturnType<typeof buildSchema>} schema
 * @param {string} key
 */
export function findSchemaField(schema, key) {
  return schema?.fields.find((field) => field.key === key) ?? null;
}

/**
 * Whether a decoded reading value is what its field says it is. `bigint` counts
 * as a number: the CBOR decoder produces one for any integer past 2^53.
 *
 * @param {{ type: string }} field
 * @param {unknown} value
 */
export function valueMatchesField(field, value) {
  if (field.type === 'number') return typeof value === 'number' || typeof value === 'bigint';
  if (field.type === 'boolean') return typeof value === 'boolean';
  if (field.type === 'text') return typeof value === 'string';
  return false;
}

/**
 * One record's readings, arranged by a schema.
 *
 * Declared fields come first, in the order the schema lists them, because that
 * order is a choice the owner made; whatever the device sent that no field
 * describes follows in the order it arrived. A declared field absent from this
 * record is simply not there: a sketch may send some readings on some passes,
 * and an empty slot would claim a value was expected and lost.
 *
 * A value that is not the declared type is kept, marked, and shown as what it
 * is. Hiding it would make the schema a filter on what the device said, and
 * coercing it would make the schema a liar about it.
 *
 * @param {ReturnType<typeof buildSchema>} schema
 * @param {Array<{ key: string, value: unknown }>} readings in wire order.
 * @returns {Array<{ key: string, value: unknown, field: object|null, mismatch: boolean }>}
 */
export function arrangeReadings(schema, readings) {
  const byKey = new Map(readings.map((reading) => [reading.key, reading]));
  const arranged = [];
  const placed = new Set();

  for (const field of schema?.fields ?? []) {
    const reading = byKey.get(field.key);
    if (!reading) continue;
    placed.add(field.key);
    arranged.push({ ...reading, field, mismatch: !valueMatchesField(field, reading.value) });
  }
  for (const reading of readings) {
    if (!placed.has(reading.key)) arranged.push({ ...reading, field: null, mismatch: false });
  }
  return arranged;
}

/**
 * The reading keys a run of records actually carried, with the type each first
 * appeared as, in the order first seen. This is what lets the form start from
 * what the device sends rather than from a key typed from memory, which is the
 * difference between a field that fills and one that silently never does.
 *
 * @param {Array<Array<{ key: string, value: unknown }>>} runs readings per record.
 * @returns {Array<{ key: string, type: 'number'|'boolean'|'text' }>} keys longer
 *          than a schema can hold are left out, since they cannot be declared.
 */
export function observedReadings(runs) {
  const found = new Map();
  for (const readings of runs) {
    for (const { key, value } of readings) {
      if (found.has(key) || key.length > SCHEMA_KEY_MAX_LENGTH) continue;
      const type = typeOfValue(value);
      if (type) found.set(key, type);
    }
  }
  return [...found].map(([key, type]) => ({ key, type }));
}

function typeOfValue(value) {
  if (typeof value === 'number' || typeof value === 'bigint') return 'number';
  if (typeof value === 'boolean') return 'boolean';
  if (typeof value === 'string') return 'text';
  return null;
}

/**
 * A reading key is matched byte for byte against what the device sends, so it
 * is refused rather than cleaned: a key quietly rewritten into a different
 * string is a field that silently never fills.
 */
function parseKey(raw) {
  if (typeof raw !== 'string' || raw.length === 0) {
    throw new TypeError('Every field needs the reading name the device sends.');
  }
  if (raw.length > SCHEMA_KEY_MAX_LENGTH) {
    throw new TypeError(`A reading name is at most ${SCHEMA_KEY_MAX_LENGTH} characters.`);
  }
  if (cleanDisplayText(raw) !== raw) {
    throw new TypeError(
      'A reading name cannot hold invisible characters or start or end with a space.',
    );
  }
  return raw;
}

function optionalText(raw, max, what) {
  if (raw === undefined || raw === null) return '';
  if (typeof raw !== 'string') throw new TypeError(`${what} must be text.`);
  const cleaned = cleanDisplayText(raw);
  if (cleaned.length > max) throw new TypeError(`${what} is at most ${max} characters.`);
  return cleaned;
}

function finite(raw, what) {
  if (typeof raw !== 'number' || !Number.isFinite(raw)) {
    throw new TypeError(`${what} must be a number.`);
  }
  return raw;
}
