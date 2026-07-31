// Roadmap 1.4 — CSPRNG and salt helpers, plus the wire encoding they feed.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { randomBytes, generateSalt, SALT_BYTES } from '../lib/crypto/random.js';
import { toBase64Url, fromBase64Url, bytesEqual, utf8Bytes } from '../lib/crypto/encoding.js';

const libDir = path.resolve(fileURLToPath(new URL('.', import.meta.url)), '../lib');

test('salt is 128-bit and distinct per call', () => {
  assert.equal(SALT_BYTES, 16);

  const salts = new Set();
  for (let i = 0; i < 100; i += 1) {
    const salt = generateSalt();
    assert.equal(salt.length, 16);
    salts.add(toBase64Url(salt));
  }
  assert.equal(salts.size, 100);
});

test('randomBytes rejects nonsense lengths instead of returning something weak', () => {
  assert.throws(() => randomBytes(0), RangeError);
  assert.throws(() => randomBytes(-1), RangeError);
  assert.throws(() => randomBytes(1.5), RangeError);
});

test('Math.random appears nowhere in the client crypto', async () => {
  // Cheap, blunt, and worth having: the design forbids it outright, and this is
  // the kind of thing that gets added in a hurry and never noticed in review.
  const files = await readdir(libDir, { recursive: true, withFileTypes: true });
  const sources = files.filter((f) => f.isFile() && f.name.endsWith('.js'));
  assert.ok(sources.length > 0, 'found no sources to scan');

  for (const file of sources) {
    const text = await readFile(path.join(file.parentPath ?? file.path, file.name), 'utf8');
    const offending = text
      .split('\n')
      .filter((line) => !/^\s*(\/\/|\*|\/\*)/.test(line)) // comments may name it; code may not
      .filter((line) => /Math\.random/.test(line));
    assert.deepEqual(offending, [], `Math.random in ${file.name}`);
  }
});

test('base64url round-trips arbitrary bytes', () => {
  for (const length of [1, 2, 3, 16, 32, 60, 255]) {
    const bytes = randomBytes(length);
    assert.ok(bytesEqual(fromBase64Url(toBase64Url(bytes)), bytes), `failed at ${length} bytes`);
  }
});

test('base64url output is url-safe and unpadded', () => {
  for (let i = 0; i < 200; i += 1) {
    const encoded = toBase64Url(randomBytes(1 + (i % 40)));
    assert.match(encoded, /^[A-Za-z0-9_-]+$/);
  }
});

test('base64url matches a known value', () => {
  // 0xFB 0xFF 0xFE is the pair that exposes '+' and '/' in standard base64.
  assert.equal(toBase64Url(new Uint8Array([0xfb, 0xff, 0xfe])), '-__-');
  assert.equal(toBase64Url(utf8Bytes('siot')), 'c2lvdA');
  assert.ok(bytesEqual(fromBase64Url('c2lvdA'), utf8Bytes('siot')));
  assert.ok(bytesEqual(fromBase64Url('c2lvdA=='), utf8Bytes('siot')), 'padded input still parses');
});

test('base64url rejects non-base64url input', () => {
  assert.throws(() => fromBase64Url('not base64!'), TypeError);
  assert.throws(() => fromBase64Url('c2lv+A'), TypeError);
});
