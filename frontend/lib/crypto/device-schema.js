/**
 * A device's declared schema (design Sections 10 and 11.1; roadmap 7.1 and 7.2).
 *
 * A schema says which readings a device sends and how to draw them. It lives in
 * the vault entry beside the device, so the server never sees it, and it drives
 * the dashboard, so it is **untrusted input**: design 11.1 notes schemas can
 * arrive from granted devices belonging to other people, and a decrypted
 * attacker's blob reaching the DOM would hand them the keys this whole
 * architecture exists to protect.
 *
 * So there is exactly one way in, `normaliseSchema`, and it is an allowlist that
 * rebuilds the object field by field. Nothing is copied through from the input:
 * not an unknown key, not an unknown type, not a string that was never checked.
 * What comes out contains only members this file wrote, drawn from closed sets,
 * so a renderer cannot be handed anything this module did not construct. Labels
 * and units are the only free text, and they are plain strings for React to
 * escape; there is no path from here to markup, to a URL, or to code.
 *
 * Lives beside `vault-document.js` for the same reason: it describes what is
 * inside the sealed blob, and has no cipher of its own.
 */

export const SCHEMA_VERSION = 1;

/** Types a reading can have, mirroring the scalars the CBOR profile allows in `r`. */
export const FIELD_TYPES = Object.freeze(['number', 'boolean', 'text']);

/** Widgets the dashboard knows how to draw (roadmap 7.3). */
export const WIDGETS = Object.freeze(['graph', 'gauge', 'toggle', 'text']);

/** Which widget may draw which type. A gauge of a boolean is a bug, not a style. */
const WIDGETS_FOR_TYPE = Object.freeze({
  number: ['graph', 'gauge', 'text'],
  boolean: ['toggle', 'text'],
  text: ['text'],
});

/** Bounds, so a hostile schema cannot inflate the blob or the dashboard. */
export const SCHEMA_MAX_FIELDS = 32;
export const FIELD_KEY_MAX_LENGTH = 32;
export const FIELD_LABEL_MAX_LENGTH = 64;
export const FIELD_UNIT_MAX_LENGTH = 12;

/** The reading name a device sends in `r`. Narrow on purpose: it is a map key. */
const KEY_PATTERN = /^[A-Za-z0-9_.-]+$/;

/** Names that mean something to the object model and must never be a key. */
const RESERVED_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

export function emptySchema() {
  return { v: SCHEMA_VERSION, fields: [] };
}

/**
 * Same strip as a device name: controls, bidi overrides and zero-width
 * characters. Display integrity rather than XSS defence; React escapes markup.
 *
 * @param {unknown} value
 * @param {number} max
 * @returns {string | null} null when it is not usable text.
 */
function cleanText(value, max) {
  if (typeof value !== 'string') return null;
  const cleaned = value
    // eslint-disable-next-line no-control-regex -- stripping controls is the point
    .replace(/[\u0000-\u001F\u007F-\u009F​-‏‪-‮⁦-⁩﻿]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
  if (cleaned.length === 0 || cleaned.length > max) return null;
  return cleaned;
}

/** Own data properties only: an inherited `type` is not something the input said. */
function own(object, name) {
  return Object.prototype.hasOwnProperty.call(object, name) ? object[name] : undefined;
}

/**
 * @param {unknown} raw
 * @returns {{ key: string, label: string, type: string, widget: string, unit?: string, min?: number, max?: number }}
 * @throws {TypeError} with a reason, so a caller can count and say why.
 */
function normaliseField(raw) {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    throw new TypeError('field must be an object');
  }

  const key = own(raw, 'key');
  if (
    typeof key !== 'string' ||
    key.length === 0 ||
    key.length > FIELD_KEY_MAX_LENGTH ||
    !KEY_PATTERN.test(key) ||
    RESERVED_KEYS.has(key)
  ) {
    throw new TypeError('field key is not an allowed reading name');
  }

  const type = own(raw, 'type');
  if (typeof type !== 'string' || !FIELD_TYPES.includes(type)) {
    throw new TypeError('field type is not in the allowlist');
  }

  const widget = own(raw, 'widget');
  if (typeof widget !== 'string' || !WIDGETS_FOR_TYPE[type].includes(widget)) {
    throw new TypeError('widget is not in the allowlist for this type');
  }

  // A missing label falls back to the key rather than failing the field: the
  // key already passed a stricter check, so it is safe text.
  const rawLabel = own(raw, 'label');
  const label = rawLabel === undefined ? key : cleanText(rawLabel, FIELD_LABEL_MAX_LENGTH);
  if (label === null) throw new TypeError('field label is not usable text');

  const field = { key, label, type, widget };

  const rawUnit = own(raw, 'unit');
  if (rawUnit !== undefined) {
    if (type !== 'number') throw new TypeError('only a number can carry a unit');
    const unit = cleanText(rawUnit, FIELD_UNIT_MAX_LENGTH);
    if (unit === null) throw new TypeError('field unit is not usable text');
    field.unit = unit;
  }

  if (widget === 'gauge') {
    // A gauge without a range cannot be drawn; refuse rather than guess one.
    const min = own(raw, 'min');
    const max = own(raw, 'max');
    if (!Number.isFinite(min) || !Number.isFinite(max) || min >= max) {
      throw new TypeError('a gauge needs finite min below max');
    }
    field.min = min;
    field.max = max;
  } else if (own(raw, 'min') !== undefined || own(raw, 'max') !== undefined) {
    throw new TypeError('only a gauge takes a range');
  }

  return field;
}

/**
 * Rebuilds whatever came out of the vault (or a granted device) into a schema
 * the renderer can rely on, discarding fields it cannot vouch for.
 *
 * Dropping a bad field rather than rejecting the schema is the same trade
 * `normaliseVaultDocument` makes: one malformed field must not blank the rest of
 * a device's dashboard. It is not silent: the count comes back so a caller can
 * say "3 fields were ignored". Anything that is not an object at all is an empty
 * schema with everything counted as dropped, never an exception a caller might
 * swallow into rendering the raw input.
 *
 * @param {unknown} input
 * @returns {{ schema: ReturnType<typeof emptySchema>, dropped: number }}
 */
export function normaliseSchema(input) {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    return { schema: emptySchema(), dropped: input === undefined || input === null ? 0 : 1 };
  }

  const rawFields = own(input, 'fields');
  if (!Array.isArray(rawFields)) {
    return { schema: emptySchema(), dropped: own(input, 'fields') === undefined ? 0 : 1 };
  }

  const fields = [];
  const seen = new Set();
  let dropped = 0;

  for (const raw of rawFields) {
    // Past the cap everything is dropped, not just rejected: a thousand-field
    // schema is an attempt to make the dashboard expensive, not a device.
    if (fields.length >= SCHEMA_MAX_FIELDS) {
      dropped += 1;
      continue;
    }
    try {
      const field = normaliseField(raw);
      // Two fields claiming one reading would draw the same value twice.
      if (seen.has(field.key)) throw new Error('duplicate key');
      seen.add(field.key);
      fields.push(field);
    } catch {
      dropped += 1;
    }
  }

  return { schema: { v: SCHEMA_VERSION, fields }, dropped };
}
