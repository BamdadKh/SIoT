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
 * Strips what must never reach a rendered name.
 *
 * React escapes markup, so this is not an XSS defence and should not be mistaken
 * for one. It is a *display integrity* one: control characters and the Unicode
 * bidi overrides can make a name render as something other than its own bytes,
 * and a device list is exactly where "this is the sensor you think it is" has to
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

  // C0/C1 controls, the bidi embedding and isolate overrides, and the
  // zero-width characters that make two different names look identical.
  const cleaned = name
    // eslint-disable-next-line no-control-regex -- stripping controls is the point
    .replace(/[\u0000-\u001F\u007F-\u009F\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/g, '')
    .replace(/\s+/g, ' ')
    .trim();

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
 * @param {unknown} contents
 * @returns {{ document: ReturnType<typeof emptyVaultDocument>, dropped: number }}
 */
export function normaliseVaultDocument(contents) {
  if (contents === null || contents === undefined) {
    return { document: emptyVaultDocument(), dropped: 0 };
  }
  if (typeof contents !== 'object' || Array.isArray(contents)) {
    throw new TypeError('vault contents must be an object');
  }

  const raw = Array.isArray(contents.devices) ? contents.devices : [];
  const devices = [];
  const seen = new Set();
  let dropped = 0;

  for (const entry of raw) {
    try {
      const device = normaliseDeviceEntry(entry);
      // `DEVICE_ID` is the key everywhere (design 5.5); two entries claiming one
      // is a bug that would otherwise silently shadow whichever came second.
      if (seen.has(device.id)) throw new Error('duplicate DEVICE_ID');
      seen.add(device.id);
      devices.push(device);
    } catch {
      dropped += 1;
    }
  }

  return { document: { v: VAULT_DOCUMENT_VERSION, devices }, dropped };
}

/**
 * @param {unknown} entry
 * @returns {{ id: string, secret: string, name: string, added_at: string }}
 */
function normaliseDeviceEntry(entry) {
  if (typeof entry !== 'object' || entry === null) {
    throw new TypeError('device entry must be an object');
  }
  return {
    id: assertBase64UrlBytes(entry.id, DEVICE_ID_BYTES, 'DEVICE_ID'),
    secret: assertBase64UrlBytes(entry.secret, DEVICE_SECRET_BYTES, 'DEVICE_SECRET'),
    name: normaliseDeviceName(entry.name),
    added_at: typeof entry.added_at === 'string' ? entry.added_at : new Date(0).toISOString(),
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
