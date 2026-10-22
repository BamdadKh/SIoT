// Roadmap 7.1 and 7.2: what a device's readings mean, and the allowlist that
// stands between a schema and the screen.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  buildSchema,
  normaliseSchema,
  parseSchemaField,
  arrangeReadings,
  observedReadings,
  SCHEMA_MAX_FIELDS,
} from '../lib/crypto/device-schema.js';
import {
  addDevice,
  emptyVaultDocument,
  findDevice,
  normaliseVaultDocument,
  renameDevice,
  setDeviceSchema,
} from '../lib/crypto/vault-document.js';
import { generateDevice } from '../lib/crypto/device.js';
import { encryptVault, decryptVault } from '../lib/crypto/vault.js';
import { generateVaultKey } from '../lib/crypto/vault-key.js';
import { toBase64Url } from '../lib/crypto/encoding.js';

const temperature = { key: 'temp_c', type: 'number', widget: 'gauge', label: 'Bench', unit: '°C', min: -10, max: 50 };

test('a valid field comes back with only the properties the allowlist names', () => {
  const field = parseSchemaField({ ...temperature, onclick: 'alert(1)', html: '<b>x</b>' });
  assert.deepEqual(field, temperature);
});

test('units and gauge bounds are dropped where they mean nothing', () => {
  assert.deepEqual(
    parseSchemaField({ key: 'door', type: 'boolean', widget: 'toggle', unit: 'V', min: 0, max: 1 }),
    { key: 'door', type: 'boolean', widget: 'toggle' },
  );
  assert.deepEqual(
    parseSchemaField({ key: 'rssi', type: 'number', widget: 'graph', min: 0, max: 1 }),
    { key: 'rssi', type: 'number', widget: 'graph' },
  );
});

test('types and widgets outside the allowlist are refused', () => {
  for (const type of ['html', 'script', 'object', 'constructor', '__proto__', 'toString', 1, null]) {
    assert.throws(() => parseSchemaField({ key: 'a', type, widget: 'value' }), TypeError, String(type));
  }
  assert.throws(() => parseSchemaField({ key: 'a', type: 'text', widget: 'graph' }), TypeError);
  assert.throws(() => parseSchemaField({ key: 'a', type: 'boolean', widget: 'gauge' }), TypeError);
  assert.throws(() => parseSchemaField({ key: 'a', type: 'number', widget: 'iframe' }), TypeError);
});

test('a gauge needs a finite range with its ends the right way round', () => {
  const gauge = { key: 'a', type: 'number', widget: 'gauge' };
  assert.throws(() => parseSchemaField(gauge), TypeError);
  assert.throws(() => parseSchemaField({ ...gauge, min: 0, max: NaN }), TypeError);
  assert.throws(() => parseSchemaField({ ...gauge, min: '0', max: '10' }), TypeError);
  assert.throws(() => parseSchemaField({ ...gauge, min: 5, max: 5 }), TypeError);
  assert.throws(() => parseSchemaField({ ...gauge, min: 0, max: Infinity }), TypeError);
});

test('a reading key is refused rather than rewritten', () => {
  // Cleaning a key would make it a different string from the one the device
  // sends, so the field would never fill.
  for (const key of ['', ' temp', 'temp ', 'te‮mp', 'te​mp', 'a'.repeat(25), 7]) {
    assert.throws(() => parseSchemaField({ key, type: 'number', widget: 'value' }), TypeError);
  }
  assert.equal(parseSchemaField({ key: 'a'.repeat(24), type: 'text', widget: 'value' }).key.length, 24);
});

test('labels and units are cleaned of invisibles and bounded', () => {
  const field = parseSchemaField({
    key: 'k',
    type: 'number',
    widget: 'value',
    label: '  Bench‮  temp\u0000 ',
    unit: '​',
  });
  assert.equal(field.label, 'Bench temp');
  assert.equal(field.unit, undefined);
  assert.throws(
    () => parseSchemaField({ key: 'k', type: 'text', widget: 'value', label: 'x'.repeat(33) }),
    TypeError,
  );
});

test('a malicious schema is inert: nothing hostile survives normalisation', () => {
  // Design 11.1: the schema of a device granted from another account is
  // attacker-controlled. Everything that comes out of `normaliseSchema` is a
  // string React escapes, a number, or a name from the fixed tables; no field
  // can carry markup into a property a renderer would treat as anything else.
  const hostile = {
    v: 1,
    fields: [
      { key: '<img src=x onerror=a()>', type: 'text', widget: 'value' },
      { key: 'ok', type: 'number', widget: 'value', label: '<script>alert(1)</script>', dangerouslySetInnerHTML: { __html: '<b>' } },
      { key: 'x', type: 'html', widget: 'value' },
      { key: 'y', type: 'number', widget: 'javascript:alert(1)' },
      { key: 'z', type: { toString: () => 'number' }, widget: 'value' },
      { key: 'ok', type: 'text', widget: 'value' },
      '<script>',
      null,
      ['key', 'number'],
    ],
    __proto__: { polluted: true },
    style: 'position:fixed',
  };

  const { schema, dropped } = normaliseSchema(hostile);
  assert.equal(dropped, 7);
  assert.deepEqual(schema, {
    v: 1,
    fields: [
      { key: '<img src=x onerror=a()>', type: 'text', widget: 'value' },
      { key: 'ok', type: 'number', widget: 'value', label: '<script>alert(1)</script>' },
    ],
  });
  // The markup survives as text, which is what it is. It is a key that will
  // only ever match a reading of that exact name, and React renders it inert.
  for (const field of schema.fields) {
    for (const value of Object.values(field)) assert.ok(['string', 'number'].includes(typeof value));
  }
  assert.equal({}.polluted, undefined);
});

test('an unreadable or newer schema reads as none, counted', () => {
  assert.deepEqual(normaliseSchema(undefined), { schema: null, dropped: 0 });
  assert.deepEqual(normaliseSchema('fields'), { schema: null, dropped: 1 });
  assert.deepEqual(normaliseSchema({ fields: 'no' }), { schema: null, dropped: 1 });
  assert.deepEqual(normaliseSchema({ v: 2, fields: [temperature, temperature] }), { schema: null, dropped: 2 });
});

test('a schema past the field limit keeps the first fields and counts the rest', () => {
  const fields = Array.from({ length: SCHEMA_MAX_FIELDS + 3 }, (_, i) => ({ key: `k${i}`, type: 'text', widget: 'value' }));
  const { schema, dropped } = normaliseSchema({ v: 1, fields });
  assert.equal(schema.fields.length, SCHEMA_MAX_FIELDS);
  assert.equal(dropped, 3);
  assert.throws(() => buildSchema(fields), TypeError);
});

test('buildSchema refuses what normaliseSchema would drop, and an empty list is no schema', () => {
  assert.throws(() => buildSchema([temperature, temperature]), /declared twice/);
  assert.throws(() => buildSchema([{ key: 'a', type: 'html', widget: 'value' }]), TypeError);
  assert.equal(buildSchema([]), null);
  assert.deepEqual(buildSchema([temperature]), { v: 1, fields: [temperature] });
});

test('a schema rides on the vault entry, round-trips sealed, and survives a rename', async () => {
  const device = await generateDevice();
  const id = toBase64Url(device.deviceId);
  let doc = addDevice(emptyVaultDocument(), { ...device, name: 'Greenhouse' });

  doc = setDeviceSchema(doc, id, [temperature]);
  doc = renameDevice(doc, id, 'Greenhouse north');

  const vaultKey = generateVaultKey();
  const { document, schemaFieldsDropped } = normaliseVaultDocument(
    await decryptVault(await encryptVault(doc, vaultKey, 3), vaultKey, 3),
  );
  assert.equal(schemaFieldsDropped, 0);
  assert.deepEqual(findDevice(document, id).schema, { v: 1, fields: [temperature] });

  // Clearing it removes the property rather than storing an empty schema.
  const cleared = setDeviceSchema(document, id, []);
  assert.equal('schema' in findDevice(cleared, id), false);
  assert.throws(() => setDeviceSchema(document, id, [{ key: 'a', type: 'nope', widget: 'value' }]), TypeError);
});

test('a broken schema costs its fields, never the device that holds it', async () => {
  const device = await generateDevice();
  const entry = {
    id: toBase64Url(device.deviceId),
    secret: toBase64Url(device.deviceSecret),
    name: 'Kept',
    schema: { v: 1, fields: [temperature, { key: 'b', type: 'eval', widget: 'value' }] },
  };
  const { document, dropped, schemaFieldsDropped } = normaliseVaultDocument({ v: 1, devices: [entry] });
  assert.equal(dropped, 0);
  assert.equal(schemaFieldsDropped, 1);
  assert.deepEqual(findDevice(document, entry.id).schema.fields, [temperature]);
});

test('arrangeReadings puts declared fields first in schema order and marks a wrong type', () => {
  const schema = buildSchema([
    { key: 'hum', type: 'number', widget: 'value' },
    { key: 'temp_c', type: 'number', widget: 'graph', unit: '°C' },
    { key: 'absent', type: 'boolean', widget: 'value' },
  ]);
  const arranged = arrangeReadings(schema, [
    { key: 'rssi', value: -60 },
    { key: 'temp_c', value: 21.5 },
    { key: 'hum', value: 'wet' },
  ]);

  assert.deepEqual(
    arranged.map(({ key, mismatch }) => [key, mismatch]),
    [['hum', true], ['temp_c', false], ['rssi', false]],
  );
  assert.equal(arranged[1].field.unit, '°C');
  assert.equal(arranged[2].field, null);
  // A big integer the decoder handed back as a bigint is still a number.
  assert.equal(arrangeReadings(schema, [{ key: 'hum', value: 2n ** 60n }])[0].mismatch, false);
  // No schema is every reading as it arrived.
  assert.deepEqual(arrangeReadings(null, [{ key: 'a', value: 1 }]), [{ key: 'a', value: 1, field: null, mismatch: false }]);
});

test('observedReadings lists each key once with the type it first arrived as', () => {
  assert.deepEqual(
    observedReadings([
      [{ key: 'temp_c', value: 21 }, { key: 'door', value: true }],
      [{ key: 'temp_c', value: 'n/a' }, { key: 'note', value: 'hi' }, { key: 'nil', value: null }],
      [{ key: 'x'.repeat(25), value: 1 }, { key: 'big', value: 1n }],
    ]),
    [
      { key: 'temp_c', type: 'number' },
      { key: 'door', type: 'boolean' },
      { key: 'note', type: 'text' },
      { key: 'big', type: 'number' },
    ],
  );
});
