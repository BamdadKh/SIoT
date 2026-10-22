// Roadmap 7.3: what a device's dashboard is entitled to draw.
//
// The widgets are React and are not reached from here; what is tested is every
// claim they make, which lives in `dashboard.js`: which record a "latest" value
// came from, where a graph has to stop rather than draw across missing records,
// and what a gauge says when the needle runs out of dial.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { buildDashboard as build, gaugePosition } from '../app/src/lib/dashboard.js';
import { valueMatchesField } from '../lib/crypto/device-schema.js';

const buildDashboard = (schema, records) => build(schema, records, valueMatchesField);

const seq = (boot, counter) => ((BigInt(boot) << 32n) | BigInt(counter)).toString();

function record(boot, counter, readings, extra = {}) {
  return {
    seq: seq(boot, counter),
    receivedAt: `2026-10-21T10:00:${String(counter).padStart(2, '0')}Z`,
    payload: { t: 0, r: readings },
    error: null,
    ...extra,
  };
}

const refused = (boot, counter) => ({ ...record(boot, counter, {}), payload: null, error: 'x' });

const schema = (...fields) => ({ v: 1, fields });
const graph = { key: 'temp', type: 'number', widget: 'graph' };

test('no schema means no dashboard, rather than one guessed from the readings', () => {
  assert.deepEqual(buildDashboard(null, [record(1, 1, { temp: 20 })]), []);
});

test('one panel per declared field, in the order the schema lists them', () => {
  const panels = buildDashboard(
    schema(
      { key: 'b', type: 'boolean', widget: 'toggle' },
      { key: 'a', type: 'number', widget: 'value' },
    ),
    [record(1, 1, { a: 1, b: true })],
  );
  assert.deepEqual(
    panels.map(({ field }) => field.key),
    ['b', 'a'],
  );
});

test('latest is the newest record that opened and carries the key', () => {
  const [panel] = buildDashboard(schema({ key: 'temp', type: 'number', widget: 'value' }), [
    record(1, 1, { temp: 19 }),
    record(1, 2, { temp: 21 }),
    record(1, 3, { humidity: 40 }),
    refused(1, 4),
  ]);
  assert.equal(panel.latest.value, 21);
  assert.equal(panel.latest.seq, seq(1, 2));
  assert.equal(panel.latest.mismatch, false);
});

test('a declared field the loaded records never carried has no latest value', () => {
  const [panel] = buildDashboard(schema({ key: 'temp', type: 'number', widget: 'value' }), [
    record(1, 1, { humidity: 40 }),
  ]);
  assert.equal(panel.latest, null);
});

test('a latest value of the wrong type is kept and marked, not skipped', () => {
  const [panel] = buildDashboard(schema(graph), [
    record(1, 1, { temp: 20 }),
    record(1, 2, { temp: 'hot' }),
  ]);
  assert.equal(panel.latest.value, 'hot');
  assert.equal(panel.latest.mismatch, true);
});

test('only a graph widget gets a series', () => {
  const panels = buildDashboard(
    schema(graph, { key: 'h', type: 'number', widget: 'gauge', min: 0, max: 100 }),
    [record(1, 1, { temp: 1, h: 2 })],
  );
  assert.ok(panels[0].series);
  assert.equal(panels[1].series, null);
});

test('a graph is spaced by record position, counting records that did not open', () => {
  const [{ series }] = buildDashboard(schema(graph), [
    record(1, 1, { temp: 1 }),
    record(1, 2, { temp: 2 }),
    record(1, 3, { temp: 3 }),
  ]);
  assert.deepEqual(series.segments, [
    [
      { x: 0, y: 1 },
      { x: 1, y: 2 },
      { x: 2, y: 3 },
    ],
  ]);
  assert.equal(series.span, 3);
  assert.equal(series.breaks, 0);
});

test('a gap in the sequence ends the line rather than drawing across it', () => {
  const [{ series }] = buildDashboard(schema(graph), [
    record(1, 1, { temp: 1 }),
    record(1, 2, { temp: 2 }),
    record(1, 9, { temp: 3 }),
  ]);
  assert.equal(series.segments.length, 2);
  assert.equal(series.breaks, 1);
  assert.deepEqual(series.segments[1], [{ x: 2, y: 3 }]);
});

test('a restart ends the line too', () => {
  const [{ series }] = buildDashboard(schema(graph), [
    record(1, 1, { temp: 1 }),
    record(2, 1, { temp: 2 }),
  ]);
  assert.equal(series.breaks, 1);
});

test('a record that would not open ends the line and still takes its place', () => {
  const [{ series }] = buildDashboard(schema(graph), [
    record(1, 1, { temp: 1 }),
    refused(1, 2),
    record(1, 3, { temp: 3 }),
  ]);
  assert.deepEqual(series.segments, [[{ x: 0, y: 1 }], [{ x: 2, y: 3 }]]);
});

test('a record that simply lacks the key does not break the line', () => {
  const [{ series }] = buildDashboard(schema(graph), [
    record(1, 1, { temp: 1 }),
    record(1, 2, { humidity: 50 }),
    record(1, 3, { temp: 3 }),
  ]);
  assert.equal(series.segments.length, 1);
  assert.equal(series.points, 2);
});

test('a mismatched value is counted, not drawn, and breaks the line', () => {
  const [{ series }] = buildDashboard(schema(graph), [
    record(1, 1, { temp: 1 }),
    record(1, 2, { temp: 'warm' }),
    record(1, 3, { temp: 3 }),
  ]);
  assert.equal(series.mismatched, 1);
  assert.equal(series.points, 2);
  assert.equal(series.breaks, 1);
});

test('a break before the first point or after the last is not a break', () => {
  const [{ series }] = buildDashboard(schema(graph), [
    refused(1, 1),
    record(1, 2, { temp: 2 }),
    record(1, 3, { temp: 3 }),
    refused(1, 4),
  ]);
  assert.equal(series.breaks, 0);
});

test('a constant reading gets a range it sits in the middle of', () => {
  const [{ series }] = buildDashboard(schema(graph), [
    record(1, 1, { temp: 20 }),
    record(1, 2, { temp: 20 }),
  ]);
  assert.ok(series.low < 20 && series.high > 20);
  assert.equal(20 - series.low, series.high - 20);
});

test('a bigint reading is plotted as a number', () => {
  const [{ series }] = buildDashboard(schema(graph), [record(1, 1, { temp: 2n ** 60n })]);
  assert.equal(typeof series.segments[0][0].y, 'number');
});

test('a gauge clamps the needle and says which side the value fell off', () => {
  const field = { min: 0, max: 100 };
  assert.deepEqual(gaugePosition(field, 25), { fraction: 0.25, outside: null });
  assert.deepEqual(gaugePosition(field, -5), { fraction: 0, outside: 'below' });
  assert.deepEqual(gaugePosition(field, 140), { fraction: 1, outside: 'above' });
  assert.deepEqual(gaugePosition(field, 100), { fraction: 1, outside: null });
});
