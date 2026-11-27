/**
 * The shape of what is inside the vault (design Sections 5.2 and 5.5).
 *
 * `vault.js` seals and opens the blob; this module is what the blob *contains*.
 * It lives in `lib/crypto/` despite holding no cipher of its own, for the same
 * reason everything else here does: a device record is `DEVICE_SECRET` in the
 * clear, and code that handles it must not be importable from `backend/` even by
 * accident.
 *
 * **The device name lives here and nowhere else.** There is no `name` column on
 * `devices` and adding one would be the mistake the one rule exists to catch:
 * "bedroom motion sensor" next to the upload timestamps the server already holds
 * turns accepted metadata leakage into a labelled occupancy log. The consequence
 * is that a locked vault can show `DEVICE_ID`s and liveness but no names, which
 * is the honest rendering of what the client actually knows.
 *
 * **Roadmap 4.3 says "encrypt `DEVICE_SECRET` under `vault_key`", and this does
 * not do that a second time.** The whole document is already sealed under
 * `vault_key` by `encryptVault`; a nested AES-GCM layer under the identical key
 * would add a nonce to manage and no confidentiality at all. The secret is
 * encrypted in the vault, which is what design 5.2's table actually requires.
 * The place a separate wrapping *would* earn its keep is per-device granularity
 * (design 15.6), where a record could be handed out without the rest of the
 * document; v1 is one blob per user, so there is nothing to hand out yet.
 *
 * Every function here returns a new document rather than mutating one. That is
 * load-bearing, not style: `PUT /vault` can lose a compare-and-swap and 409, and
 * the caller then has to refetch and re-apply against the server's newer
 * document. An in-place edit would have already corrupted the copy it is
 * retrying from.
 */

import { toBase64Url, fromBase64Url } from './encoding.js';
import { DEVICE_ID_BYTES, DEVICE_SECRET_BYTES } from './device.js';
import { cleanDisplayText } from './display-text.js';
import { buildSchema, normaliseSchema } from './device-schema.js';

/**
 * Bumped only for a change old clients cannot read. Additive fields do not need
 * it: `normaliseVaultDocument` drops what it does not recognise on read, so a
 * newer client's extra keys are survivable rather than fatal.
 */
export const VAULT_DOCUMENT_VERSION = 1;

/**
 * Long enough for "Greenhouse humidity (north bench)", short enough that a
 * pathological value cannot be used to inflate the blob and study the length.
 */
export const DEVICE_NAME_MAX_LENGTH = 64;

/** The document an account has before it has ever written a vault. */
export function emptyVaultDocument() {
  return { v: VAULT_DOCUMENT_VERSION, devices: [] };
}

/**
 * Strips what must never reach a rendered name (see `display-text.js`).
 *
 * A device list is exactly where "this is the sensor you think it is" has to
 * hold. The vault is authenticated, so nothing hostile gets in here from the
 * server; a name is still typed by a person who may have pasted it from anywhere.
 *
 * @param {unknown} name
 * @returns {string}
 */
export function normaliseDeviceName(name) {
  if (typeof name !== 'string') {
    throw new TypeError('device name must be a string');
  }

  const cleaned = cleanDisplayText(name);

  if (cleaned.length === 0) {
    throw new TypeError('device name cannot be empty');
  }
  if (cleaned.length > DEVICE_NAME_MAX_LENGTH) {
    throw new TypeError(`device name cannot exceed ${DEVICE_NAME_MAX_LENGTH} characters`);
  }
  return cleaned;
}

/**
 * @param {unknown} value
 * @param {number} expectedBytes
 * @param {string} label
 * @returns {string} the value, confirmed to be base64url of exactly that length.
 */
function assertBase64UrlBytes(value, expectedBytes, label) {
  if (typeof value !== 'string') {
    throw new TypeError(`${label} must be a base64url string`);
  }
  const bytes = fromBase64Url(value);
  if (bytes.length !== expectedBytes) {
    throw new TypeError(`${label} must decode to ${expectedBytes} bytes, got ${bytes.length}`);
  }
  return value;
}

/**
 * Reads whatever came out of `decryptVault` into a document this code can rely
 * on, discarding entries it cannot make sense of.
 *
 * Dropping a malformed entry rather than throwing is deliberate. The blob is
 * authenticated, so a broken record means a bug in some version of this client,
 * not tampering, and one bad entry must not make the other devices unreachable.
 * It is not silent either: the dropped ids come back so a caller can say so.
 *
 * A schema field that will not parse is dropped from its device rather than
 * taking the device with it: the schema says how to show readings, the entry
 * holds the only key that opens them, and losing the second over the first
 * would be absurd. Counted separately for the same not-silent reason.
 *
 * @param {unknown} contents
 * @returns {{ document: ReturnType<typeof emptyVaultDocument>, dropped: number,
 *             schemaFieldsDropped: number }}
 */
export function normaliseVaultDocument(contents) {
  if (contents === null || contents === undefined) {
    return { document: emptyVaultDocument(), dropped: 0, schemaFieldsDropped: 0, retiredDropped: 0 };
  }
  if (typeof contents !== 'object' || Array.isArray(contents)) {
    throw new TypeError('vault contents must be an object');
  }

  const raw = Array.isArray(contents.devices) ? contents.devices : [];
  const devices = [];
  const seen = new Set();
  let dropped = 0;
  let schemaFieldsDropped = 0;
  let retiredDropped = 0;

  for (const entry of raw) {
    try {
      const { device, schemaDropped, retiredDropped: retiredBad } = normaliseDeviceEntry(entry);
      // `DEVICE_ID` is the key everywhere (design 5.5); two entries claiming one
      // is a bug that would otherwise silently shadow whichever came second.
      if (seen.has(device.id)) throw new Error('duplicate DEVICE_ID');
      seen.add(device.id);
      devices.push(device);
      schemaFieldsDropped += schemaDropped;
      retiredDropped += retiredBad;
    } catch {
      dropped += 1;
    }
  }

  return {
    document: { v: VAULT_DOCUMENT_VERSION, devices },
    dropped,
    schemaFieldsDropped,
    retiredDropped,
  };
}

/** The largest `seq` there is: it is a uint64 (design 7.3). */
const UINT64_MAX = (1n << 64n) - 1n;

/**
 * @param {unknown} value
 * @returns {string} the value, confirmed to be a canonical decimal uint64.
 */
function assertThroughSeq(value) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new TypeError('through_seq must be a decimal string');
  }
  if (BigInt(value) > UINT64_MAX) {
    throw new RangeError('through_seq exceeds uint64');
  }
  return value;
}

/**
 * Reads the retired-secret list, tolerant per item. A bad item is dropped and
 * counted rather than failing the entry, for the same reason a bad schema field
 * is: the current `secret` is the only key that opens new records and losing it
 * over a damaged history would be absurd. Sorted by boundary so `secretForSeq`
 * can take the first match without trusting stored order.
 *
 * @param {unknown} raw
 * @returns {{ retired: Array<{ secret: string, through_seq: string }>, dropped: number }}
 */
function normaliseRetired(raw) {
  if (raw === undefined) return { retired: [], dropped: 0 };
  if (!Array.isArray(raw)) return { retired: [], dropped: 1 };
  const retired = [];
  let dropped = 0;
  for (const item of raw) {
    try {
      if (typeof item !== 'object' || item === null) throw new TypeError('not an object');
      retired.push({
        secret: assertBase64UrlBytes(item.secret, DEVICE_SECRET_BYTES, 'retired DEVICE_SECRET'),
        through_seq: assertThroughSeq(item.through_seq),
      });
    } catch {
      dropped += 1;
    }
  }
  retired.sort((a, b) => {
    const x = BigInt(a.through_seq);
    const y = BigInt(b.through_seq);
    return x < y ? -1 : x > y ? 1 : 0;
  });
  return { retired, dropped };
}

/**
 * @param {unknown} entry
 * @returns {{ device: { id: string, secret: string, name: string, added_at: string,
 *             schema?: object, retired?: Array<{ secret: string, through_seq: string }>,
 *             pending?: string }, schemaDropped: number, retiredDropped: number }}
 */
function normaliseDeviceEntry(entry) {
  if (typeof entry !== 'object' || entry === null) {
    throw new TypeError('device entry must be an object');
  }
  const device = {
    id: assertBase64UrlBytes(entry.id, DEVICE_ID_BYTES, 'DEVICE_ID'),
    secret: assertBase64UrlBytes(entry.secret, DEVICE_SECRET_BYTES, 'DEVICE_SECRET'),
    name: normaliseDeviceName(entry.name),
    added_at: typeof entry.added_at === 'string' ? entry.added_at : new Date(0).toISOString(),
  };
  // Absent rather than null when there is none, so an entry written before
  // schemas existed reads back exactly as it was written.
  const { schema, dropped } = normaliseSchema(entry.schema);
  if (schema) device.schema = schema;

  // Absent rather than empty for the same reason: an entry that was never
  // rotated reads back exactly as it was written.
  const { retired, dropped: retiredDropped } = normaliseRetired(entry.retired);
  if (retired.length > 0) device.retired = retired;
  let pendingBad = 0;
  if (entry.pending !== undefined) {
    try {
      device.pending = assertBase64UrlBytes(entry.pending, DEVICE_SECRET_BYTES, 'pending DEVICE_SECRET');
    } catch {
      // A pending secret that will not parse was never usable; counted, not fatal.
      pendingBad = 1;
    }
  }
  // Roadmap 10.4: absent until something has been marked read, and a value that
  // will not parse is treated as absent, which errs towards showing a
  // notification as unread again rather than hiding one nobody saw.
  if (entry.notifications_seen_through !== undefined) {
    try {
      device.notifications_seen_through = assertThroughSeq(entry.notifications_seen_through);
    } catch {
      // Not counted: unlike a dropped secret, nothing is lost but a read mark.
    }
  }
  // Roadmap 11.2: starts at 1 because a fresh device's high-water mark is 0.
  device.nextCommandSeq =
    Number.isSafeInteger(entry.nextCommandSeq) && entry.nextCommandSeq >= 1 ? entry.nextCommandSeq : 1;
  return { device, schemaDropped: dropped, retiredDropped: retiredDropped + pendingBad };
}

/**
 * Hands out the next `command_seq` for a device and bumps the stored counter
 * (roadmap 11.2). The caller must `PUT /vault` the returned document *before*
 * posting the command: a 409 then means another tab took this number, and the
 * recovery is the usual one (refetch, re-apply). Posting first would let two tabs
 * send the same `command_seq`, and the device would run only one of them.
 *
 * A number reserved and then never sent is harmless: the device only needs
 * sequences to increase, not to be contiguous.
 *
 * @returns {{ document: { devices: Array }, commandSeq: number }}
 */
export function reserveCommandSeq(doc, deviceId) {
  const device = findDevice(doc, deviceId);
  if (!device) throw new Error('no such device in the vault');
  const commandSeq = device.nextCommandSeq ?? 1;
  if (!Number.isSafeInteger(commandSeq + 1)) throw new RangeError('command counter exhausted');
  return {
    commandSeq,
    document: {
      ...doc,
      v: VAULT_DOCUMENT_VERSION,
      devices: listDevices(doc).map((d) =>
        d.id === deviceId ? { ...d, nextCommandSeq: commandSeq + 1 } : d,
      ),
    },
  };
}

/**
 * Marks a device's notifications read up to and including `seq` (roadmap 10.4).
 *
 * Read state lives here, in the vault, and not on the server. "This account read
 * the smoke alarm alert at 03:12" is a fact about a person, and the server
 * already holds the arrival time of the alert; a read flag beside it would turn
 * the pair into a record of when someone was awake and looking. Here it is one
 * more opaque vault write, the same size class and the same route as a rename.
 *
 * A high-water `seq` rather than a set of read ids, because notifications and
 * readings share one sequence (10.2) and the mark is then one number per device
 * however many alerts arrive. It only moves forward: marking an older position
 * returns the document unchanged, so a stale tab cannot un-read something a
 * newer one already marked, and a caller can compare identity to skip the write.
 *
 * @param {{ devices: Array }} doc
 * @param {string} deviceId base64url
 * @param {string} seq uint64 as a decimal string
 */
export function markNotificationsSeen(doc, deviceId, seq) {
  const entry = findDevice(doc, deviceId);
  if (!entry) throw new Error('no such device in the vault');
  const mark = assertThroughSeq(seq);
  if (
    entry.notifications_seen_through !== undefined &&
    BigInt(mark) <= BigInt(entry.notifications_seen_through)
  ) {
    return doc;
  }
  return {
    ...doc,
    v: VAULT_DOCUMENT_VERSION,
    devices: listDevices(doc).map((device) =>
      device.id === deviceId ? { ...device, notifications_seen_through: mark } : device,
    ),
  };
}

/**
 * @param {{ devices: Array }} doc
 * @returns {Array<{ id: string, secret: string, name: string, added_at: string }>}
 */
export function listDevices(doc) {
  return doc?.devices ?? [];
}

/**
 * @param {{ devices: Array }} doc
 * @param {string} deviceId base64url
 */
export function findDevice(doc, deviceId) {
  return listDevices(doc).find((device) => device.id === deviceId) ?? null;
}

/**
 * Adds a freshly minted device.
 *
 * The name is required and comes in with the rest, because design 5.5 wants it
 * asked for *before* the device exists: there is no moment at which a device is
 * displayed as a bare `DEVICE_ID` waiting to be labelled.
 *
 * @param {{ devices: Array }} doc
 * @param {{ deviceId: Uint8Array, deviceSecret: Uint8Array, name: string, addedAt?: Date }} device
 */
export function addDevice(doc, { deviceId, deviceSecret, name, addedAt = new Date() }) {
  if (!(deviceId instanceof Uint8Array) || deviceId.length !== DEVICE_ID_BYTES) {
    throw new TypeError(`DEVICE_ID must be ${DEVICE_ID_BYTES} bytes`);
  }
  if (!(deviceSecret instanceof Uint8Array) || deviceSecret.length !== DEVICE_SECRET_BYTES) {
    throw new TypeError(`DEVICE_SECRET must be ${DEVICE_SECRET_BYTES} bytes`);
  }

  const id = toBase64Url(deviceId);
  if (findDevice(doc, id)) {
    throw new Error('a device with this DEVICE_ID is already in the vault');
  }

  return {
    ...doc,
    v: VAULT_DOCUMENT_VERSION,
    devices: [
      ...listDevices(doc),
      {
        id,
        secret: toBase64Url(deviceSecret),
        name: normaliseDeviceName(name),
        added_at: addedAt.toISOString(),
        nextCommandSeq: 1,
      },
    ],
  };
}

/**
 * Renaming is an ordinary vault write: same `PUT /vault`, same version bump, no
 * endpoint of its own. It has to survive a re-provisioning too (design 8.4), so
 * it touches nothing but the name.
 *
 * @param {{ devices: Array }} doc
 * @param {string} deviceId base64url
 * @param {string} name
 */
export function renameDevice(doc, deviceId, name) {
  if (!findDevice(doc, deviceId)) {
    throw new Error('no such device in the vault');
  }
  const nextName = normaliseDeviceName(name);

  return {
    ...doc,
    v: VAULT_DOCUMENT_VERSION,
    devices: listDevices(doc).map((device) =>
      device.id === deviceId ? { ...device, name: nextName } : device,
    ),
  };
}

/**
 * Declares, replaces or clears what a device's readings mean (roadmap 7.1). An
 * ordinary vault write like a rename, and like a rename it touches nothing else
 * on the entry, so it survives re-provisioning.
 *
 * Validated strictly here, at the last point before sealing, so a caller that
 * skipped `buildSchema` still cannot write a schema a reader would discard.
 *
 * @param {{ devices: Array }} doc
 * @param {string} deviceId base64url
 * @param {unknown[]} fields
 */
export function setDeviceSchema(doc, deviceId, fields) {
  if (!findDevice(doc, deviceId)) {
    throw new Error('no such device in the vault');
  }
  const schema = buildSchema(fields);

  return {
    ...doc,
    v: VAULT_DOCUMENT_VERSION,
    devices: listDevices(doc).map((device) => {
      if (device.id !== deviceId) return device;
      // eslint-disable-next-line no-unused-vars -- dropping the old schema is the point
      const { schema: _previous, ...rest } = device;
      return schema ? { ...rest, schema } : rest;
    }),
  };
}

/**
 * Step (a) of a secret rotation (design 9.3): park a freshly generated secret on
 * the entry as `pending`, leaving `secret` untouched. The old secret stays the
 * one that reads and (until the server rebinds) the one that is registered, so
 * a failure anywhere after this loses nothing.
 *
 * Calling it again with the *same* bytes is a no-op (a retry after a lost
 * response). Different bytes replace the pending secret: a caller that already
 * rebound the server must reuse the stored pending rather than mint again.
 * Setting it equal to the current secret is refused: that rotates nothing.
 *
 * @param {{ devices: Array }} doc
 * @param {string} deviceId base64url
 * @param {Uint8Array} secretBytes 32 bytes
 */
export function setPendingSecret(doc, deviceId, secretBytes) {
  const entry = findDevice(doc, deviceId);
  if (!entry) {
    throw new Error('no such device in the vault');
  }
  if (!(secretBytes instanceof Uint8Array) || secretBytes.length !== DEVICE_SECRET_BYTES) {
    throw new TypeError(`DEVICE_SECRET must be ${DEVICE_SECRET_BYTES} bytes`);
  }
  const pending = toBase64Url(secretBytes);
  if (pending === entry.secret) {
    throw new Error('the pending secret is the current secret');
  }
  if (entry.pending === pending) return doc;

  return {
    ...doc,
    v: VAULT_DOCUMENT_VERSION,
    devices: listDevices(doc).map((device) =>
      device.id === deviceId ? { ...device, pending } : device,
    ),
  };
}

/**
 * Step (c) of a rotation: the server has rebound the device and said every record
 * it accepted under the old key has `seq <= throughSeq`. The old secret moves to
 * `retired` with that boundary (old records stay readable forever), the pending
 * secret becomes `secret`, and `pending` goes away. Name, schema and `added_at`
 * ride through untouched.
 *
 * Idempotency: if `pending` already equals `secret` (a stale copy of the entry
 * re-applied after a promote landed) the marker is cleared and nothing is
 * appended, so a retry never creates a second retired entry. If the promote
 * already completed outright there is no `pending` and this throws; a caller
 * that lost the response reloads the vault and finds the work done.
 *
 * A boundary lower than the last retired one is a bug, not data: rotations
 * happen in order, so boundaries only move forward. An equal boundary is allowed
 * (a rotation with no uploads in between).
 *
 * @param {{ devices: Array }} doc
 * @param {string} deviceId base64url
 * @param {string} throughSeq uint64 as a decimal string
 */
export function promotePendingSecret(doc, deviceId, throughSeq) {
  const entry = findDevice(doc, deviceId);
  if (!entry) {
    throw new Error('no such device in the vault');
  }
  if (entry.pending === undefined) {
    throw new Error('no pending secret to promote');
  }
  const boundary = assertThroughSeq(throughSeq);

  if (entry.pending === entry.secret) {
    return {
      ...doc,
      v: VAULT_DOCUMENT_VERSION,
      devices: listDevices(doc).map((device) => {
        if (device.id !== deviceId) return device;
        // eslint-disable-next-line no-unused-vars -- dropping the marker is the point
        const { pending: _pending, ...rest } = device;
        return rest;
      }),
    };
  }

  const retired = entry.retired ?? [];
  const last = retired[retired.length - 1];
  if (last && BigInt(boundary) < BigInt(last.through_seq)) {
    throw new RangeError('through_seq is lower than the last retired boundary');
  }

  return {
    ...doc,
    v: VAULT_DOCUMENT_VERSION,
    devices: listDevices(doc).map((device) => {
      if (device.id !== deviceId) return device;
      const { pending, ...rest } = device;
      return {
        ...rest,
        secret: pending,
        retired: [...retired, { secret: device.secret, through_seq: boundary }],
      };
    }),
  };
}

/**
 * Which stored secret covers a record at `seq`: the first retired secret whose
 * boundary is at or above it, else the current one. Strings in and out;
 * comparison is BigInt because `seq` overflows a double.
 *
 * @param {{ secret: string, retired?: Array<{ secret: string, through_seq: string }> }} entry normalised
 * @param {string} seq uint64 as a decimal string
 * @returns {string} base64url secret as stored
 */
export function secretForSeq(entry, seq) {
  const target = BigInt(seq);
  for (const item of entry.retired ?? []) {
    if (target <= BigInt(item.through_seq)) return item.secret;
  }
  return entry.secret;
}

/**
 * Forgets a device locally. The server keeps the row (nothing here calls a
 * delete endpoint, and there is not one), so this is "stop tracking it", not
 * "destroy it": the `DEVICE_ID` stays registered and any board still holding the
 * secret can still upload. Removing the secret from the vault does mean those
 * uploads become permanently unreadable, which is the honest consequence and
 * belongs in the confirmation copy rather than in a comment.
 *
 * @param {{ devices: Array }} doc
 * @param {string} deviceId base64url
 */
export function removeDevice(doc, deviceId) {
  if (!findDevice(doc, deviceId)) {
    throw new Error('no such device in the vault');
  }
  return {
    ...doc,
    v: VAULT_DOCUMENT_VERSION,
    devices: listDevices(doc).filter((device) => device.id !== deviceId),
  };
}

/**
 * The bytes behind a stored entry, for deriving keys or for a 4.6 reveal.
 *
 * Returned as a fresh array the caller can zero. The string form stays in the
 * document either way, which is a limit of holding the vault as JSON rather than
 * something this can fix.
 *
 * @param {{ secret: string }} device
 * @returns {Uint8Array} 32 bytes.
 */
export function deviceSecretBytes(device) {
  const bytes = fromBase64Url(device.secret);
  if (bytes.length !== DEVICE_SECRET_BYTES) {
    throw new Error(`stored DEVICE_SECRET is ${bytes.length} bytes, expected 32`);
  }
  return bytes;
}

/**
 * @param {{ id: string }} device
 * @returns {Uint8Array} 16 bytes.
 */
export function deviceIdBytes(device) {
  return fromBase64Url(device.id);
}
