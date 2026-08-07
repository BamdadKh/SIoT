/**
 * CBOR (RFC 8949), cut down to exactly what a record payload is (design 7.3).
 *
 * **Why a hand-rolled subset rather than a CBOR library.** The payload shape is
 * `{ t, r }` with scalar readings inside, and the decoder runs on a blob that
 * arrived from an untrusted server, which the vault's own rule already applies
 * to: this decodes what a device wrote, and a device is a program somebody else
 * wrote. Everything CBOR offers beyond this subset (tags, indefinite lengths,
 * bignums, semantic types) is surface with nothing on the other side of it. A
 * general library would accept all of it and hand the result to a dashboard.
 *
 * The subset, in both directions:
 *
 *   unsigned and negative integers, up to the full 64-bit range
 *   floats                          decoded at half, single and double width
 *   text strings                    UTF-8, definite length
 *   arrays and maps                 definite length only
 *   true, false, null
 *
 * Everything else is a decode error, by name: byte strings, tags, indefinite
 * lengths, `undefined`, and every other simple value. A port that needs one of
 * those is a port that has to change this file and `docs/protocol.md` together.
 *
 * **Encoding here is deterministic** (RFC 8949 section 4.2): shortest-form heads,
 * and map keys sorted by length and then by bytes. That is not a requirement the
 * protocol places on a device, since nothing verifies the encoding: the
 * signature covers whatever bytes the device actually produced. It is what
 * makes the published test vectors reproducible, and it costs a port nothing to
 * ignore.
 */

import { utf8Bytes, utf8String } from './encoding.js';

const MAJOR_UINT = 0;
const MAJOR_NEGINT = 1;
const MAJOR_BYTES = 2;
const MAJOR_TEXT = 3;
const MAJOR_ARRAY = 4;
const MAJOR_MAP = 5;
const MAJOR_SIMPLE = 7;

const UINT64_MAX = (1n << 64n) - 1n;

/* --- encoding ------------------------------------------------------------ */

class Writer {
  constructor() {
    this.bytes = [];
  }

  push(...values) {
    for (const value of values) this.bytes.push(value & 0xff);
  }

  /** Major type plus its argument, in the shortest form that holds it. */
  head(major, argument) {
    const value = BigInt(argument);
    if (value < 0n || value > UINT64_MAX) {
      throw new RangeError(`cbor: argument ${argument} is outside the uint64 range`);
    }
    const tag = major << 5;

    if (value < 24n) {
      this.push(tag | Number(value));
    } else if (value <= 0xffn) {
      this.push(tag | 24, Number(value));
    } else if (value <= 0xffffn) {
      this.push(tag | 25, Number(value >> 8n), Number(value & 0xffn));
    } else if (value <= 0xffffffffn) {
      this.push(tag | 26);
      for (let shift = 24n; shift >= 0n; shift -= 8n) this.push(Number((value >> shift) & 0xffn));
    } else {
      this.push(tag | 27);
      for (let shift = 56n; shift >= 0n; shift -= 8n) this.push(Number((value >> shift) & 0xffn));
    }
  }

  double(value) {
    this.push(0xfb);
    const view = new DataView(new ArrayBuffer(8));
    view.setFloat64(0, value, false);
    for (let i = 0; i < 8; i += 1) this.push(view.getUint8(i));
  }

  toBytes() {
    return Uint8Array.from(this.bytes);
  }
}

/**
 * @param {unknown} value
 * @returns {Uint8Array}
 */
export function encodeCbor(value) {
  const writer = new Writer();
  encodeInto(writer, value);
  return writer.toBytes();
}

function encodeInto(writer, value) {
  if (value === null) {
    writer.push(0xf6);
    return;
  }
  if (typeof value === 'boolean') {
    writer.push(value ? 0xf5 : 0xf4);
    return;
  }
  if (typeof value === 'bigint') {
    if (value >= 0n) writer.head(MAJOR_UINT, value);
    else writer.head(MAJOR_NEGINT, -1n - value);
    return;
  }
  if (typeof value === 'number') {
    // An integer-valued double still encodes as an integer, which is what makes
    // `t: 1786000000` the same eight bytes whichever side produced it.
    if (Number.isInteger(value)) {
      if (value >= 0) writer.head(MAJOR_UINT, BigInt(value));
      else writer.head(MAJOR_NEGINT, BigInt(-1 - value));
      return;
    }
    if (!Number.isFinite(value)) {
      // NaN and the infinities are encodable and mean nothing as a reading;
      // refusing them here keeps them out of the dashboard entirely.
      throw new TypeError('cbor: cannot encode a non-finite number');
    }
    writer.double(value);
    return;
  }
  if (typeof value === 'string') {
    const bytes = utf8Bytes(value);
    writer.head(MAJOR_TEXT, bytes.length);
    writer.push(...bytes);
    return;
  }
  if (Array.isArray(value)) {
    writer.head(MAJOR_ARRAY, value.length);
    for (const item of value) encodeInto(writer, item);
    return;
  }
  if (typeof value === 'object') {
    // Plain objects only. A `Map`, a `Set`, a `Date` or a typed array all reach
    // here as "an object" and `Object.entries` would quietly turn each of them
    // into something that is not what the caller meant: a Uint8Array becomes a
    // map of indices, which would encode a key as a reading.
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) {
      throw new TypeError(`cbor: cannot encode ${value.constructor?.name ?? 'this object'}`);
    }

    const entries = Object.entries(value).filter(([, item]) => item !== undefined);
    entries.sort(([a], [b]) => compareMapKeys(a, b));
    writer.head(MAJOR_MAP, entries.length);
    for (const [key, item] of entries) {
      encodeInto(writer, key);
      encodeInto(writer, item);
    }
    return;
  }

  throw new TypeError(`cbor: cannot encode ${typeof value}`);
}

/** RFC 8949 section 4.2.1: shorter keys first, then bytewise. */
function compareMapKeys(a, b) {
  const left = utf8Bytes(a);
  const right = utf8Bytes(b);
  if (left.length !== right.length) return left.length - right.length;
  for (let i = 0; i < left.length; i += 1) {
    if (left[i] !== right[i]) return left[i] - right[i];
  }
  return 0;
}

/* --- decoding ------------------------------------------------------------ */

/**
 * @param {Uint8Array} bytes
 * @returns {unknown}
 */
export function decodeCbor(bytes) {
  if (!(bytes instanceof Uint8Array)) {
    throw new TypeError('cbor: expected a Uint8Array');
  }
  const reader = { bytes, at: 0 };
  const value = decodeItem(reader);
  // Trailing bytes are not a partial read to shrug off. The payload is exactly
  // one item, and anything after it is a payload this code does not understand.
  if (reader.at !== bytes.length) {
    throw new Error(`cbor: ${bytes.length - reader.at} trailing byte(s) after the top-level item`);
  }
  return value;
}

function need(reader, count) {
  if (reader.at + count > reader.bytes.length) {
    throw new Error('cbor: input ended in the middle of an item');
  }
}

function decodeItem(reader, depth = 0) {
  // A nesting bound so a hostile blob cannot recurse this into a stack overflow.
  // Nothing legitimate is anywhere near it: a record is a map of scalars.
  if (depth > 8) throw new Error('cbor: nested too deeply');

  need(reader, 1);
  const initial = reader.bytes[reader.at];
  reader.at += 1;

  const major = initial >> 5;
  const minor = initial & 0x1f;

  if (major === MAJOR_SIMPLE) return decodeSimple(reader, minor);

  const argument = decodeArgument(reader, minor);

  switch (major) {
    case MAJOR_UINT:
      return fitNumber(argument);
    case MAJOR_NEGINT:
      return fitNumber(-1n - argument);
    case MAJOR_TEXT: {
      const length = boundedLength(reader, argument);
      const text = utf8String(reader.bytes.subarray(reader.at, reader.at + length));
      reader.at += length;
      return text;
    }
    case MAJOR_ARRAY: {
      const count = boundedLength(reader, argument);
      const items = [];
      for (let i = 0; i < count; i += 1) items.push(decodeItem(reader, depth + 1));
      return items;
    }
    case MAJOR_MAP: {
      const count = boundedLength(reader, argument);
      const map = {};
      for (let i = 0; i < count; i += 1) {
        const key = decodeItem(reader, depth + 1);
        if (typeof key !== 'string') {
          throw new Error('cbor: map keys must be text strings in this profile');
        }
        // Two entries claiming one key is ambiguous, and which one wins is a
        // property of the decoder rather than of the data. Refuse instead.
        if (Object.hasOwn(map, key)) throw new Error(`cbor: duplicate map key ${JSON.stringify(key)}`);
        map[key] = decodeItem(reader, depth + 1);
      }
      return map;
    }
    case MAJOR_BYTES:
      throw new Error('cbor: byte strings are not part of this profile');
    default:
      // Major 6 is tags. A tagged value is a semantic claim about the item
      // inside it, and honouring one is exactly the surface this profile exists
      // to not have.
      throw new Error(`cbor: unsupported major type ${major}`);
  }
}

function decodeArgument(reader, minor) {
  if (minor < 24) return BigInt(minor);

  if (minor === 24) {
    need(reader, 1);
    const value = BigInt(reader.bytes[reader.at]);
    reader.at += 1;
    return value;
  }
  if (minor === 25 || minor === 26 || minor === 27) {
    const width = minor === 25 ? 2 : minor === 26 ? 4 : 8;
    need(reader, width);
    let value = 0n;
    for (let i = 0; i < width; i += 1) value = (value << 8n) | BigInt(reader.bytes[reader.at + i]);
    reader.at += width;
    return value;
  }
  if (minor === 31) throw new Error('cbor: indefinite lengths are not part of this profile');
  throw new Error(`cbor: reserved additional information ${minor}`);
}

function decodeSimple(reader, minor) {
  switch (minor) {
    case 20:
      return false;
    case 21:
      return true;
    case 22:
      return null;
    case 25:
      return decodeFloat(reader, 2);
    case 26:
      return decodeFloat(reader, 4);
    case 27:
      return decodeFloat(reader, 8);
    case 23:
      throw new Error('cbor: `undefined` is not part of this profile');
    default:
      throw new Error(`cbor: unsupported simple value ${minor}`);
  }
}

function decodeFloat(reader, width) {
  need(reader, width);
  const view = new DataView(
    reader.bytes.buffer,
    reader.bytes.byteOffset + reader.at,
    width,
  );
  reader.at += width;

  if (width === 8) return view.getFloat64(0, false);
  if (width === 4) return view.getFloat32(0, false);

  // Half precision, which Web Crypto's world has no reader for and which a
  // constrained device is entirely likely to emit for a temperature.
  const bits = view.getUint16(0, false);
  const sign = bits & 0x8000 ? -1 : 1;
  const exponent = (bits >> 10) & 0x1f;
  const fraction = bits & 0x3ff;

  if (exponent === 0) return sign * fraction * 2 ** -24;
  if (exponent === 31) return fraction ? Number.NaN : sign * Number.POSITIVE_INFINITY;
  return sign * (fraction + 1024) * 2 ** (exponent - 25);
}

/**
 * Integers come back as `number` where that is exact and `bigint` where it is
 * not. Silently rounding a uint64 into a double is the same class of mistake as
 * parsing `seq` with `Number`, and a reading is allowed to be a counter.
 */
function fitNumber(value) {
  return value >= BigInt(Number.MIN_SAFE_INTEGER) && value <= BigInt(Number.MAX_SAFE_INTEGER)
    ? Number(value)
    : value;
}

/**
 * A declared length is a promise the input has to be able to keep. Checking it
 * against what is actually left stops a 2^32-element array header from
 * allocating anything at all.
 */
function boundedLength(reader, argument) {
  const remaining = reader.bytes.length - reader.at;
  if (argument > BigInt(remaining)) {
    throw new Error(`cbor: declared length ${argument} exceeds the ${remaining} bytes left`);
  }
  return Number(argument);
}
