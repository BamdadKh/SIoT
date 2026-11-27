// Roadmap 11.5: a device's schema says what a dashboard may send it.
//
// The claims: a command is only what the schema declares, a switch can only
// point at the one idempotent shape ("set state to X"), arguments are checked
// for type and bounds before anything is encrypted, a field-only save cannot
// erase declared commands, and what is built actually opens on the device side.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  buildCommandArgs,
  buildSchema,
  findSchemaCommand,
  normaliseSchema,
  parseSchemaCommand,
  withSetStateCommands,
  COMMAND_TEXT_MAX_BYTES,
  SCHEMA_MAX_COMMANDS,
} from '../lib/crypto/device-schema.js';
import { addDevice, emptyVaultDocument, setDeviceSchema } from '../lib/crypto/vault-document.js';
import { decryptCommand, encryptCommand } from '../lib/crypto/command.js';
import { toBase64Url } from '../lib/crypto/encoding.js';

const relay = { key: 'relay', type: 'boolean', widget: 'toggle', command: 'set_relay' };
const setRelay = { type: 'set_relay', args: [{ name: 'value', type: 'boolean' }] };

test('a declared command keeps only what the allowlist names', () => {
  const parsed = parseSchemaCommand({
    type: 'set_level',
    label: 'Level',
    extra: 'dropped',
    args: [{ name: 'level', type: 'number', min: 0, max: 10, style: 'x' }],
  });
  assert.deepEqual(parsed, {
    type: 'set_level',
    label: 'Level',
    args: [{ name: 'level', type: 'number', min: 0, max: 10 }],
  });
});

test('command names are identifiers, refused rather than cleaned', () => {
  for (const type of ['', 'Set', 'set relay', 'set-relay', 'x'.repeat(33), 'sét']) {
    assert.throws(() => parseSchemaCommand({ type, args: [] }), TypeError, type);
  }
  assert.throws(() => parseSchemaCommand({ type: 'ok', args: [{ name: 'A', type: 'boolean' }] }));
});

test('a number argument needs both bounds, and text is capped', () => {
  assert.throws(() => parseSchemaCommand({ type: 'a', args: [{ name: 'n', type: 'number' }] }));
  assert.throws(() =>
    parseSchemaCommand({ type: 'a', args: [{ name: 'n', type: 'number', min: 2, max: 1 }] }),
  );
  assert.throws(() =>
    parseSchemaCommand({
      type: 'a',
      args: [{ name: 't', type: 'text', max_bytes: COMMAND_TEXT_MAX_BYTES + 1 }],
    }),
  );
  assert.equal(parseSchemaCommand({ type: 'a', args: [{ name: 't', type: 'text' }] }).args[0].max_bytes, 64);
  assert.throws(() => parseSchemaCommand({ type: 'a', args: [{ name: 'x', type: 'object' }] }));
});

test('a switch may only name a declared set-state command', () => {
  assert.ok(buildSchema([relay], [setRelay]).commands);
  assert.throws(() => buildSchema([relay], []), /not declared/);
  assert.throws(
    () => buildSchema([relay], [{ type: 'set_relay', args: [{ name: 'on', type: 'boolean' }] }]),
    /boolean named value/,
  );
  // Only a switch carries a command; on any other widget it is not kept.
  const schema = buildSchema([{ key: 't', type: 'number', widget: 'value', command: 'x' }]);
  assert.equal(schema.fields[0].command, undefined);
});

test('commands alone are a schema, and nothing at all is none', () => {
  assert.deepEqual(buildSchema([], [setRelay]).commands, [setRelay]);
  assert.equal(buildSchema([], []), null);
  assert.throws(
    () => buildSchema([], Array.from({ length: SCHEMA_MAX_COMMANDS + 1 }, (_, i) => ({ type: `c${i}` }))),
  );
  assert.throws(() => buildSchema([], [setRelay, setRelay]), /twice/);
});

test('reading is tolerant: a bad command is dropped and its switch goes read-only', () => {
  const { schema, dropped } = normaliseSchema({
    v: 1,
    fields: [relay, { key: 't', type: 'number', widget: 'value' }],
    commands: [{ type: 'set_relay', args: [{ name: 'value', type: 'number' }] }, { type: 'ok' }],
  });
  assert.equal(dropped, 1, 'the number argument without bounds');
  assert.equal(schema.fields.length, 2, 'the field survives');
  assert.equal(schema.fields[0].command, undefined, 'its link does not');
  assert.deepEqual(schema.commands.map((c) => c.type), ['ok']);
});

test('a schema written before commands existed reads back unchanged', () => {
  const old = { v: 1, fields: [{ key: 't', type: 'number', widget: 'value' }] };
  assert.deepEqual(normaliseSchema(old), { schema: old, dropped: 0 });
});

test('withSetStateCommands declares a switch command once, and only in the one shape', () => {
  const declared = withSetStateCommands([relay, { ...relay, key: 'other' }], []);
  assert.deepEqual(declared, [setRelay]);
  // An existing declaration of a different shape is left for buildSchema to refuse.
  const clash = [{ type: 'set_relay', args: [] }];
  assert.deepEqual(withSetStateCommands([relay], clash), clash);
  assert.throws(() => buildSchema([relay], withSetStateCommands([relay], clash)));
});

test('arguments are exactly what is declared, of the declared type, within bounds', () => {
  const level = parseSchemaCommand({
    type: 'set',
    args: [
      { name: 'level', type: 'number', min: 0, max: 10 },
      { name: 'note', type: 'text', max_bytes: 4 },
      { name: 'on', type: 'boolean' },
    ],
  });
  const ok = buildCommandArgs(level, { level: 3, note: 'hi', on: true });
  assert.deepEqual({ ...ok }, { level: 3, note: 'hi', on: true });

  assert.throws(() => buildCommandArgs(level, { level: 3, note: 'hi' }), /needs on/);
  assert.throws(() => buildCommandArgs(level, { level: 3, note: 'hi', on: true, x: 1 }), /no argument x/);
  assert.throws(() => buildCommandArgs(level, { level: 11, note: 'hi', on: true }), RangeError);
  assert.throws(() => buildCommandArgs(level, { level: NaN, note: 'hi', on: true }));
  assert.throws(() => buildCommandArgs(level, { level: '3', note: 'hi', on: true }));
  assert.throws(() => buildCommandArgs(level, { level: 3, note: 'héllo', on: true }), RangeError);
  assert.throws(() => buildCommandArgs(level, { level: 3, note: 'hi', on: 1 }));
});

test('an argument named __proto__ is an entry, not a prototype write', () => {
  const command = parseSchemaCommand({ type: 'p', args: [{ name: '__proto__', type: 'boolean' }] });
  const values = Object.create(null);
  values.__proto__ = true;
  const args = buildCommandArgs(command, values);
  assert.equal(Object.hasOwn(args, '__proto__'), true);
  assert.equal(Object.getPrototypeOf(args), null);
});

test('built args encrypt and open as the device would read them', async () => {
  const deviceId = new Uint8Array(16).fill(7);
  const commandKey = new Uint8Array(32).fill(9);
  const args = buildCommandArgs(findSchemaCommand(buildSchema([relay], [setRelay]), 'set_relay'), {
    value: false,
  });
  const sealed = await encryptCommand({ deviceId, commandKey, commandSeq: 4, type: 'set_relay', args });
  const opened = await decryptCommand({ deviceId, commandKey, ...sealed });
  assert.equal(opened.command_seq, 4n);
  assert.equal(opened.type, 'set_relay');
  assert.equal(opened.args.value, false);
});

test('saving fields without naming commands keeps the ones already declared', () => {
  const deviceId = new Uint8Array(16).fill(1);
  let doc = addDevice(emptyVaultDocument(), {
    deviceId,
    deviceSecret: new Uint8Array(32).fill(2),
    name: 'Pump',
  });
  const id = toBase64Url(deviceId);
  doc = setDeviceSchema(doc, id, [relay], [setRelay]);
  doc = setDeviceSchema(doc, id, [{ key: 't', type: 'number', widget: 'value' }]);
  assert.deepEqual(doc.devices[0].schema.commands, [setRelay]);
  // Clearing them is explicit.
  doc = setDeviceSchema(doc, id, [{ key: 't', type: 'number', widget: 'value' }], []);
  assert.equal(doc.devices[0].schema.commands, undefined);
});
