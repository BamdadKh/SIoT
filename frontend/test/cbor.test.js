import test from 'node:test';
import assert from 'node:assert/strict';

import { encodeCbor, decodeCbor } from '../lib/crypto/cbor.js';

const hex = (bytes) => Buffer.from(bytes).toString('hex');
const bytes = (text) => Uint8Array.from(Buffer.from(text, 'hex'));

/*
 * The appendix A vectors from RFC 8949, restricted to the profile this codec
 * claims to implement. Pinning them means "our CBOR" is the real thing rather
 * than a private format that happens to round-trip with itself, which is the
 * failure a port would discover only when its own library refused the payload.
 */
test('encodes the RFC 8949 appendix A vectors that fall inside the profile', () => {
  const cases = [
    [0, '00'],
    [1, '01'],
    [10, '0a'],
    [23, '17'],
    [24, '1818'],
    [100, '1864'],
    [1000, '1903e8'],
    [1000000, '1a000f4240'],
    [-1, '20'],
    [-10, '29'],
    [-100, '3863'],
    [-1000, '3903e7'],
    [1.5, 'fb3ff8000000000000'],
    [-4.1, 'fbc010666666666666'],
    [false, 'f4'],
    [true, 'f5'],
    [null, 'f6'],
    ['', '60'],
    ['a', '6161'],
    ['IETF', '6449455446'],
    ['"\\', '62225c'],
    ['ü', '62c3bc'],
    [[], '80'],
    [[1, 2, 3], '83010203'],
    [{}, 'a0'],
    [{ a: 1, b: [2, 3] }, 'a26161016162820203'],
    [['a', { b: 'c' }], '826161a161626163'],
  ];

  for (const [value, expected] of cases) {
    assert.equal(hex(encodeCbor(value)), expected, `encoding ${JSON.stringify(String(value))}`);
    assert.deepEqual(decodeCbor(bytes(expected)), value, `decoding ${expected}`);
  }

  // A uint64 written from a bigint encodes the same way; it just does not decode
  // back to one while it still fits a double exactly (see the bigint test below).
  assert.equal(hex(encodeCbor(1000000000000n)), '1b000000e8d4a51000');
  assert.equal(decodeCbor(bytes('1b000000e8d4a51000')), 1000000000000);
});

test('decodes half and single precision floats a device may emit', () => {
  // A constrained device saving four bytes per reading is the reason these are
  // decodable at all; nothing here ever encodes them.
  assert.equal(decodeCbor(bytes('f93c00')), 1.0);
  assert.equal(decodeCbor(bytes('f94900')), 10.0);
  assert.equal(decodeCbor(bytes('f9c400')), -4.0);
  assert.equal(decodeCbor(bytes('f90001')), 5.960464477539063e-8);
  assert.equal(decodeCbor(bytes('fa47c35000')), 100000.0);
  assert.equal(decodeCbor(bytes('f97c00')), Number.POSITIVE_INFINITY);
  assert.ok(Number.isNaN(decodeCbor(bytes('f97e00'))));
});

test('map keys are encoded in RFC 8949 deterministic order, whatever order they arrive in', () => {
  // Not a requirement on a device: nothing verifies the encoding, because the
  // signature covers the bytes the device actually produced. It is what makes
  // the published vectors reproducible from either side.
  const one = encodeCbor({ humidity: 48, t: 1, temp_c: 2 });
  const other = encodeCbor({ temp_c: 2, t: 1, humidity: 48 });
  assert.equal(hex(one), hex(other));
  // Shortest key first, then bytewise: t, then temp_c, then humidity.
  assert.equal(hex(one), 'a3617401' + '6674656d705f6302' + '6868756d69646974791830');
});

test('a uint64 reading comes back as a bigint rather than a rounded double', () => {
  const encoded = encodeCbor({ counter: 2n ** 63n });
  assert.equal(decodeCbor(encoded).counter, 2n ** 63n);
  // And a value that does fit stays an ordinary number, so ordinary readings do
  // not force every consumer to handle two types.
  assert.equal(decodeCbor(encodeCbor({ n: 42 })).n, 42);
});

test('refuses everything outside the profile', () => {
  const refusals = [
    ['40', /byte strings/], // h''
    ['5501', /byte strings/],
    ['c11a514b67b0', /major type 6/], // tag 1, epoch time
    ['9f018201029fff', /indefinite/], // indefinite array
    ['7f657374726561646d696e67ff', /indefinite/], // indefinite text
    ['f7', /undefined/],
    ['f0', /simple value/],
    ['bf6161016162ff', /indefinite/], // indefinite map
    ['a201020102', /map keys must be text/],
    ['a2616101616101', /duplicate map key/],
    ['1c', /reserved additional information/],
    ['1b0000', /ended in the middle/],
    ['0000', /trailing byte/],
    ['9a7fffffff00', /declared length/], // huge array header, one byte of input
  ];

  for (const [encoded, pattern] of refusals) {
    assert.throws(() => decodeCbor(bytes(encoded)), pattern, `should refuse ${encoded}`);
  }
});

test('refuses to encode what it cannot represent', () => {
  assert.throws(() => encodeCbor(Number.NaN), /non-finite/);
  assert.throws(() => encodeCbor(Number.POSITIVE_INFINITY), /non-finite/);
  assert.throws(() => encodeCbor(new Uint8Array([1])), /cannot encode/);
  assert.throws(() => encodeCbor(() => {}), /cannot encode/);
  assert.throws(() => encodeCbor(2n ** 64n), /uint64 range/);
});

test('a record-shaped payload round-trips exactly', () => {
  const payload = {
    t: 1786000000,
    r: { temp_c: 21.5, humidity: 48, heater: false, label: 'north bench', spare: null },
  };
  assert.deepEqual(decodeCbor(encodeCbor(payload)), payload);
});
