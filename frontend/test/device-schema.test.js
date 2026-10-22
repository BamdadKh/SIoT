// Roadmap 7.1 and 7.2: the schema shape, and the allowlist in front of it.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  normaliseSchema,
  emptySchema,
  SCHEMA_MAX_FIELDS,
  FIELD_LABEL_MAX_LENGTH,
} from '../lib/crypto/device-schema.js';
import {
  emptyVaultDocument,
  addDevice,
  setDeviceSchema,
  normaliseVaultDocument,
  findDevice,
} from '../lib/crypto/vault-document.js';
import { generateDevice } from '../lib/crypto/device.js';
import { toBase64Url } from '../lib/crypto/encoding.js';

const good = {
  v: 1,
  fields: [
    { key: 'temp_c', label: 'Temperature', type: 'number', widget: 'graph', unit: 'C' },
    { key: 'humidity', label: 'Humidity', type: 'number', widget: 'gauge', min: 0, max: 100 },
    { key: 'door', label: 'Door open', type: 'boolean', widget: 'toggle' },
    { key: 'note', type: 'text', widget: 'text' },
  ],
};

test('a well-formed schema passes through intact, label defaulting to the key', () => {
  const { schema, dropped } = normaliseSchema(good);

  assert.equal(dropped, 0);
  assert.equal(schema.fields.length, 4);
  assert.deepEqual(schema.fields[1], {
    key: 'humidity',
    label: 'Humidity',
    type: 'number',
    widget: 'gauge',
    min: 0,
    max: 100,
  });
  assert.equal(schema.fields[3].label, 'note');
});

test('nothing at all is the empty schema, not an error', () => {
  assert.deepEqual(normaliseSchema(undefined), { schema: emptySchema(), dropped: 0 });
  assert.deepEqual(normaliseSchema(null), { schema: emptySchema(), dropped: 0 });
});

test('a non-object schema is empty and counted, never thrown', () => {
  for (const input of ['<script>alert(1)</script>', 42, true, [], [{ key: 'a' }]]) {
    const { schema, dropped } = normaliseSchema(input);
    assert.deepEqual(schema, emptySchema());
    assert.equal(dropped, 1);
  }
});

test('unknown types and widgets are dropped, and the rest survive', () => {
  const { schema, dropped } = normaliseSchema({
    fields: [
      { key: 'a', type: 'html', widget: 'text' },
      { key: 'b', type: 'number', widget: 'iframe' },
      { key: 'c', type: 'number', widget: 'graph' },
    ],
  });

  assert.equal(dropped, 2);
  assert.deepEqual(
    schema.fields.map((f) => f.key),
    ['c'],
  );
});

test('a widget must suit the type: no gauge of a boolean, no toggle of a number', () => {
  const { schema, dropped } = normaliseSchema({
    fields: [
      { key: 'a', type: 'boolean', widget: 'gauge', min: 0, max: 1 },
      { key: 'b', type: 'number', widget: 'toggle' },
      { key: 'c', type: 'text', widget: 'graph' },
    ],
  });
  assert.equal(schema.fields.length, 0);
  assert.equal(dropped, 3);
});

test('a gauge needs a finite, ordered range, and nothing else may carry one', () => {
  const base = { key: 'g', type: 'number', widget: 'gauge' };
  for (const range of [
    {},
    { min: 5, max: 5 },
    { min: 9, max: 1 },
    { min: '0', max: '10' },
    { min: 0, max: Infinity },
    { min: NaN, max: 1 },
  ]) {
    assert.equal(normaliseSchema({ fields: [{ ...base, ...range }] }).dropped, 1);
  }
  assert.equal(
    normaliseSchema({ fields: [{ key: 'x', type: 'number', widget: 'graph', min: 0, max: 1 }] })
      .dropped,
    1,
  );
});

test('keys that could poison an object, or are not a reading name, are refused', () => {
  const keys = ['__proto__', 'constructor', 'prototype', '', 'a b', '<img>', 'x'.repeat(33), 'é'];
  const { schema, dropped } = normaliseSchema({
    fields: keys.map((key) => ({ key, type: 'number', widget: 'graph' })),
  });
  assert.equal(schema.fields.length, 0);
  assert.equal(dropped, keys.length);
});

test('duplicate keys keep the first only', () => {
  const { schema, dropped } = normaliseSchema({
    fields: [
      { key: 'a', type: 'number', widget: 'graph' },
      { key: 'a', type: 'text', widget: 'text' },
    ],
  });
  assert.equal(schema.fields.length, 1);
  assert.equal(schema.fields[0].type, 'number');
  assert.equal(dropped, 1);
});

test('labels lose controls and bidi overrides, and over-long ones are dropped', () => {
  const { schema } = normaliseSchema({
    fields: [{ key: 'a', label: '  Tem‮per​ature  (C) ', type: 'number', widget: 'graph' }],
  });
  assert.equal(schema.fields[0].label, 'Temperature (C)');

  assert.equal(
    normaliseSchema({
      fields: [
        { key: 'a', label: 'x'.repeat(FIELD_LABEL_MAX_LENGTH + 1), type: 'number', widget: 'graph' },
        { key: 'b', label: '​​', type: 'number', widget: 'graph' },
        { key: 'c', label: { toString: () => 'x' }, type: 'number', widget: 'graph' },
      ],
    }).dropped,
    3,
  );
});

test('a unit is for numbers only', () => {
  assert.equal(
    normaliseSchema({ fields: [{ key: 'a', type: 'text', widget: 'text', unit: 'C' }] }).dropped,
    1,
  );
});

test('the field count is capped', () => {
  const fields = Array.from({ length: SCHEMA_MAX_FIELDS + 10 }, (_, i) => ({
    key: `f${i}`,
    type: 'number',
    widget: 'graph',
  }));
  const { schema, dropped } = normaliseSchema({ fields });
  assert.equal(schema.fields.length, SCHEMA_MAX_FIELDS);
  assert.equal(dropped, 10);
});

// 7.2's "deliberately malicious payload" item.
test('a malicious schema is inert: nothing from it survives except allowlisted members', () => {
  const evil = JSON.parse(`{
    "v": 1,
    "__proto__": { "polluted": true },
    "html": "<script>alert(1)</script>",
    "fields": [
      { "key": "ok", "label": "<script>alert(1)</script>", "type": "number", "widget": "graph",
        "onclick": "steal()", "dangerouslySetInnerHTML": { "__html": "<img src=x onerror=alert(1)>" },
        "href": "javascript:alert(1)", "__proto__": { "polluted": true }, "constructor": { "prototype": {} } },
      { "key": "x", "type": "script", "widget": "text" },
      { "key": "y", "type": "number", "widget": "<img src=x onerror=alert(1)>" },
      { "key": "z", "type": { "toString": "x" }, "widget": "graph" },
      null, 7, "str", [], { "key": 5 }
    ]
  }`);

  const { schema, dropped } = normaliseSchema(evil);

  assert.equal(dropped, 8);
  assert.equal(schema.fields.length, 1);
  // Only the four members this module writes (no unit on this one).
  assert.deepEqual(Object.keys(schema.fields[0]).sort(), ['key', 'label', 'type', 'widget']);
  assert.deepEqual(Object.keys(schema).sort(), ['fields', 'v']);
  // The label is kept as inert text for React to escape; it is never markup.
  assert.equal(schema.fields[0].label, '<script>alert(1)</script>');
  assert.equal({}.polluted, undefined);
  assert.equal(schema.polluted, undefined);
});

test('inherited properties are not read as if the input had said them', () => {
  const proto = { key: 'a', type: 'number', widget: 'graph' };
  const field = Object.create(proto);
  assert.equal(normaliseSchema({ fields: [field] }).dropped, 1);
});

// Storage in the vault entry.
test('setDeviceSchema stores the cleaned schema on the entry and reports drops', async () => {
  const { deviceId, deviceSecret } = await generateDevice();
  const doc = addDevice(emptyVaultDocument(), { deviceId, deviceSecret, name: 'Greenhouse' });
  const id = toBase64Url(deviceId);

  const { document, dropped } = setDeviceSchema(doc, id, {
    fields: [
      { key: 'temp', type: 'number', widget: 'graph' },
      { key: 'bad', type: 'nope', widget: 'text' },
    ],
  });

  assert.equal(dropped, 1);
  assert.equal(findDevice(document, id).schema.fields.length, 1);
  // The input document is untouched: callers retry from it after a 409.
  assert.equal(findDevice(doc, id).schema, undefined);
});

test('a stored schema is re-run through the allowlist when the vault is read', async () => {
  const { deviceId, deviceSecret } = await generateDevice();
  const doc = addDevice(emptyVaultDocument(), { deviceId, deviceSecret, name: 'Greenhouse' });
  const id = toBase64Url(deviceId);
  doc.devices[0].schema = { fields: [{ key: 'a', type: 'html', widget: 'text' }, good.fields[0]] };

  const { document } = normaliseVaultDocument(JSON.parse(JSON.stringify(doc)));

  assert.deepEqual(
    findDevice(document, id).schema.fields.map((f) => f.key),
    ['temp_c'],
  );
});

test('an entry with no schema stays without one', async () => {
  const { deviceId, deviceSecret } = await generateDevice();
  const doc = addDevice(emptyVaultDocument(), { deviceId, deviceSecret, name: 'Plain' });
  const { document } = normaliseVaultDocument(doc);
  assert.equal('schema' in document.devices[0], false);
});

test('setDeviceSchema refuses a device that is not in the vault', () => {
  assert.throws(() => setDeviceSchema(emptyVaultDocument(), 'nope', good), /no such device/);
});
