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
 * `toggle` renders state, and sends only if the field names a declared command
 * (`command`) whose one argument is a boolean called `value`: "set the state to
 * X". That shape is idempotent by construction, which ROADMAP 11.0 asks the
 * schema to steer towards, since delivery is at-least-once. A toggle with no
 * command is a read-only switch, as before.
 */
export const SCHEMA_WIDGETS = Object.freeze({
  number: Object.freeze(['value', 'graph', 'gauge']),
  boolean: Object.freeze(['value', 'toggle']),
  text: Object.freeze(['value']),
});

export const SCHEMA_TYPES = Object.freeze(Object.keys(SCHEMA_WIDGETS));

/*
 * --- commands (roadmap 11.5) ----------------------------------------------
 *
 * A schema also says what a dashboard is allowed to *send*: the command types
 * the device accepts and the exact shape of each one's arguments. Same allowlist
 * discipline as rendering, pointed the other way. A dashboard can only send a
 * command the schema declares, with exactly the arguments it declares, each of
 * the declared type and inside the declared bounds. There is no free-form
 * channel to a device, because a device that used to be only a writer gains a
 * new resource-exhaustion surface the moment it can be sent anything at all.
 *
 * The names are matched byte for byte by firmware (`command.type()`,
 * `getBool("value", ...)`), so they are refused rather than cleaned, like a
 * reading key, and restricted to `[a-z0-9_]`: a command type is an identifier in
 * someone's sketch, not prose.
 */

/** Matches the firmware's `type_[33]`: 32 bytes and a terminator. */
export const COMMAND_TYPE_MAX_LENGTH = 32;
export const COMMAND_ARG_NAME_MAX_LENGTH = 24;
export const SCHEMA_MAX_COMMANDS = 16;
export const COMMAND_MAX_ARGS = 8;
/**
 * The default and the ceiling for a text argument, in UTF-8 bytes. 120 is the
 * notification message bound (10.2), for the same reason in the other direction.
 */
export const COMMAND_TEXT_DEFAULT_BYTES = 64;
export const COMMAND_TEXT_MAX_BYTES = 120;
export const COMMAND_ARG_TYPES = Object.freeze(['boolean', 'number', 'text']);

const IDENTIFIER = /^[a-z0-9_]+$/;

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

  // A link to a declared command, checked against the command list by the
  // caller, since a field on its own cannot know what else the schema declares.
  if (widget === 'toggle' && raw.command !== undefined && raw.command !== null && raw.command !== '') {
    field.command = parseIdentifier(raw.command, COMMAND_TYPE_MAX_LENGTH, `${key}: the command`);
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
 * One declared command, validated, as a new object holding only what this file
 * names. Throws `TypeError` with a message fit to show the person who typed it.
 *
 * @param {unknown} raw
 * @returns {{ type: string, label?: string, args: Array<{ name: string,
 *             type: 'boolean'|'number'|'text', min?: number, max?: number,
 *             max_bytes?: number }> }}
 */
export function parseSchemaCommand(raw) {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    throw new TypeError('A command must be an object.');
  }
  const type = parseIdentifier(raw.type, COMMAND_TYPE_MAX_LENGTH, 'A command type');
  const command = { type, args: [] };

  const label = optionalText(raw.label, SCHEMA_LABEL_MAX_LENGTH, `${type}: the label`);
  if (label) command.label = label;

  const args = raw.args ?? [];
  if (!Array.isArray(args)) throw new TypeError(`${type}: the arguments must be a list.`);
  if (args.length > COMMAND_MAX_ARGS) {
    throw new TypeError(`${type}: a command takes at most ${COMMAND_MAX_ARGS} arguments.`);
  }
  const seen = new Set();
  for (const rawArg of args) {
    if (typeof rawArg !== 'object' || rawArg === null || Array.isArray(rawArg)) {
      throw new TypeError(`${type}: an argument must be an object.`);
    }
    const name = parseIdentifier(
      rawArg.name,
      COMMAND_ARG_NAME_MAX_LENGTH,
      `${type}: an argument name`,
    );
    if (seen.has(name)) throw new TypeError(`${type}: ${name} is declared twice.`);
    seen.add(name);
    if (typeof rawArg.type !== 'string' || !COMMAND_ARG_TYPES.includes(rawArg.type)) {
      throw new TypeError(`${type}: ${name} must be one of ${COMMAND_ARG_TYPES.join(', ')}.`);
    }
    const arg = { name, type: rawArg.type };
    if (arg.type === 'number') {
      // Both bounds are required: an unbounded number is a device being asked to
      // cope with any value at all, which is the surface this exists to close.
      arg.min = finite(rawArg.min, `${type}: the minimum of ${name}`);
      arg.max = finite(rawArg.max, `${type}: the maximum of ${name}`);
      if (!(arg.min <= arg.max)) {
        throw new TypeError(`${type}: the minimum of ${name} must not be above its maximum.`);
      }
    }
    if (arg.type === 'text') {
      const bytes = rawArg.max_bytes ?? COMMAND_TEXT_DEFAULT_BYTES;
      if (!Number.isInteger(bytes) || bytes < 1 || bytes > COMMAND_TEXT_MAX_BYTES) {
        throw new TypeError(`${type}: ${name} can be at most ${COMMAND_TEXT_MAX_BYTES} bytes long.`);
      }
      arg.max_bytes = bytes;
    }
    command.args.push(arg);
  }
  return command;
}

/**
 * Whether a command is the shape a switch can send: one boolean called `value`.
 *
 * @param {{ args: Array<{ name: string, type: string }> } | null} command
 */
export function isSetStateCommand(command) {
  return (
    command !== null &&
    command.args.length === 1 &&
    command.args[0].name === 'value' &&
    command.args[0].type === 'boolean'
  );
}

/**
 * The command list a set of fields needs: what is already declared, plus a
 * set-state command (one boolean named `value`) for every switch that names a
 * command nobody has declared yet. This is how the Fields form declares a
 * switch's command without a second form for commands, and it only ever adds
 * the one shape a switch can send. A switch naming a command that exists in some
 * other shape is left for `buildSchema` to refuse by name.
 *
 * @param {Array<{ widget: string, command?: string }>} fields
 * @param {unknown[]} commands already declared.
 * @returns {unknown[]}
 */
export function withSetStateCommands(fields, commands) {
  const next = [...commands];
  const types = new Set(next.map((command) => command?.type));
  for (const field of fields) {
    if (field.widget !== 'toggle' || !field.command || types.has(field.command)) continue;
    types.add(field.command);
    next.push({ type: field.command, args: [{ name: 'value', type: 'boolean' }] });
  }
  return next;
}

/**
 * Validates a complete field list, and optionally a command list, for saving.
 * Refuses rather than repairs.
 *
 * @param {unknown[]} fields
 * @param {unknown[]} [commands]
 * @returns {{ v: number, fields: ReturnType<typeof parseSchemaField>[],
 *             commands?: ReturnType<typeof parseSchemaCommand>[] } | null}
 *          null when nothing is declared: a device with no fields and no commands
 *          has no schema, and storing an empty one would be a second way to say that.
 */
export function buildSchema(fields, commands = []) {
  if (!Array.isArray(fields)) throw new TypeError('Fields must be a list.');
  if (fields.length > SCHEMA_MAX_FIELDS) {
    throw new TypeError(`A device can declare at most ${SCHEMA_MAX_FIELDS} fields.`);
  }
  if (!Array.isArray(commands)) throw new TypeError('Commands must be a list.');
  if (commands.length > SCHEMA_MAX_COMMANDS) {
    throw new TypeError(`A device can declare at most ${SCHEMA_MAX_COMMANDS} commands.`);
  }

  const parsedCommands = [];
  const types = new Set();
  for (const raw of commands) {
    const command = parseSchemaCommand(raw);
    if (types.has(command.type)) throw new TypeError(`${command.type} is declared twice.`);
    types.add(command.type);
    parsedCommands.push(command);
  }

  const parsed = [];
  const seen = new Set();
  for (const raw of fields) {
    const field = parseSchemaField(raw);
    // Two fields for one key would leave the renderer choosing between them.
    if (seen.has(field.key)) throw new TypeError(`${field.key} is declared twice.`);
    seen.add(field.key);
    if (field.command !== undefined) {
      const target = parsedCommands.find((command) => command.type === field.command) ?? null;
      if (!target) {
        throw new TypeError(`${field.key}: the command ${field.command} is not declared.`);
      }
      if (!isSetStateCommand(target)) {
        throw new TypeError(
          `${field.key}: a switch can only send a command whose one argument is a boolean named value.`,
        );
      }
    }
    parsed.push(field);
  }

  if (parsed.length === 0 && parsedCommands.length === 0) return null;
  const schema = { v: SCHEMA_VERSION, fields: parsed };
  if (parsedCommands.length > 0) schema.commands = parsedCommands;
  return schema;
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

  let dropped = 0;

  // Commands first, so a field's link can be checked against what survived. A
  // command that will not parse is dropped and counted like a field; a switch
  // pointing at it then loses the link and stays a read-only switch, rather than
  // the field going too.
  const commands = [];
  const types = new Set();
  const rawCommands = Array.isArray(raw.commands) ? raw.commands : [];
  if (raw.commands !== undefined && !Array.isArray(raw.commands)) dropped += 1;
  for (const entry of rawCommands.slice(0, SCHEMA_MAX_COMMANDS)) {
    try {
      const command = parseSchemaCommand(entry);
      if (types.has(command.type)) throw new TypeError('duplicate type');
      types.add(command.type);
      commands.push(command);
    } catch {
      dropped += 1;
    }
  }
  dropped += Math.max(0, rawCommands.length - SCHEMA_MAX_COMMANDS);

  const fields = [];
  const seen = new Set();

  for (const entry of raw.fields.slice(0, SCHEMA_MAX_FIELDS)) {
    try {
      const field = parseSchemaField(entry);
      if (seen.has(field.key)) throw new TypeError('duplicate key');
      seen.add(field.key);
      if (field.command !== undefined) {
        const target = commands.find((command) => command.type === field.command) ?? null;
        if (!isSetStateCommand(target)) delete field.command;
      }
      fields.push(field);
    } catch {
      dropped += 1;
    }
  }
  dropped += Math.max(0, raw.fields.length - SCHEMA_MAX_FIELDS);

  if (fields.length === 0 && commands.length === 0) return { schema: null, dropped };
  const schema = { v: SCHEMA_VERSION, fields };
  if (commands.length > 0) schema.commands = commands;
  return { schema, dropped };
}

/**
 * The declared command of a type, or null.
 *
 * @param {ReturnType<typeof buildSchema>} schema
 * @param {string} type
 */
export function findSchemaCommand(schema, type) {
  return schema?.commands?.find((command) => command.type === type) ?? null;
}

/**
 * Builds the `args` for one command from values a screen collected, refusing
 * anything the declaration does not allow (roadmap 11.5). This is the last check
 * before `encryptCommand`, and it is the one that matters: a screen can only
 * ever hand it values, never shape.
 *
 * @param {ReturnType<typeof parseSchemaCommand>} command declared, normalised.
 * @param {Record<string, unknown>} values
 * @returns {Record<string, boolean|number|string>} a null-prototype object (what
 *          `encodeCbor` accepts besides a plain one), so an argument named
 *          `__proto__`, which the identifier rule allows, is an entry and not a
 *          prototype write.
 */
export function buildCommandArgs(command, values) {
  if (typeof values !== 'object' || values === null) {
    throw new TypeError('Command arguments must be an object.');
  }
  const declared = new Set(command.args.map((arg) => arg.name));
  for (const name of Object.keys(values)) {
    if (!declared.has(name)) throw new TypeError(`${command.type} takes no argument ${name}.`);
  }

  const args = Object.create(null);
  for (const arg of command.args) {
    if (!Object.hasOwn(values, arg.name)) {
      throw new TypeError(`${command.type} needs ${arg.name}.`);
    }
    const value = values[arg.name];
    if (arg.type === 'boolean') {
      if (typeof value !== 'boolean') throw new TypeError(`${arg.name} must be on or off.`);
    } else if (arg.type === 'number') {
      if (typeof value !== 'number' || !Number.isFinite(value)) {
        throw new TypeError(`${arg.name} must be a number.`);
      }
      if (value < arg.min || value > arg.max) {
        throw new RangeError(`${arg.name} must be between ${arg.min} and ${arg.max}.`);
      }
    } else {
      if (typeof value !== 'string') throw new TypeError(`${arg.name} must be text.`);
      if (new TextEncoder().encode(value).length > arg.max_bytes) {
        throw new RangeError(`${arg.name} can be at most ${arg.max_bytes} bytes.`);
      }
    }
    args[arg.name] = value;
  }
  return args;
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

function parseIdentifier(raw, max, what) {
  if (typeof raw !== 'string' || raw.length === 0) throw new TypeError(`${what} is required.`);
  if (raw.length > max) throw new TypeError(`${what} is at most ${max} characters.`);
  if (!IDENTIFIER.test(raw)) {
    throw new TypeError(`${what} can only use lowercase letters, digits and underscores.`);
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
