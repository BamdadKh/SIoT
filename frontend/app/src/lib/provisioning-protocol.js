/**
 * The browser half of the provisioning serial protocol (roadmap 4.5).
 *
 * The other half is `firmware/esp32-provisioning/esp32-provisioning.ino`, and
 * its header is the specification. Both sides have to agree, so change them in
 * one commit or not at all.
 *
 * Pure string handling, no `navigator.serial` and no React: the transport lives
 * next door in `web-serial.js`, and everything worth being sure about is here
 * where `node --test` can reach it. Getting a length check or an overwrite rule
 * wrong is not the kind of thing to discover against a board.
 *
 * Line oriented ASCII. One command per line, one response line per command, and
 * anything not beginning with `SIOT ` is noise rather than an error: the port is
 * shared with ROM bootloader chatter, and the board applies the identical rule to
 * what it receives.
 */

/** The only protocol version this client speaks. */
export const PROTOCOL_BANNER = 'PROVISION/1';

const PREFIX = 'SIOT ';

/** No credentials on the board, in both directions on the wire. */
export const NO_ID = '-';

/* --- commands ------------------------------------------------------------ */

export function helloCommand() {
  return `${PREFIX}HELLO`;
}

export function readIdCommand() {
  return `${PREFIX}READ-ID`;
}

/**
 * The write, carrying the id this client believes is currently on the board.
 *
 * That first argument is what makes the overwrite decision below binding rather
 * than advisory. The board compares it against what it actually finds and
 * refuses if they differ, so a board swapped between the read and the write
 * cannot be provisioned against a check that was computed for a different one.
 * Same compare-and-swap shape as `vault_version` and `last_seq` on the server.
 *
 * @param {string|null} expectedId base64url, or null for "the board is blank"
 * @param {string} deviceId base64url
 * @param {string} deviceSecret base64url
 */
export function writeCommand(expectedId, deviceId, deviceSecret) {
  if (!deviceId || !deviceSecret) {
    throw new TypeError('a write needs both a DEVICE_ID and a DEVICE_SECRET');
  }
  return `${PREFIX}WRITE ${expectedId ?? NO_ID} ${deviceId} ${deviceSecret}`;
}

/**
 * Retires a board: both values removed, carrying the same compare-and-swap the
 * write does (roadmap 4.9).
 *
 * `WRITE` already reclaims a board for a new device, so this is for the board
 * going in a drawer rather than into another project: a retired board should not
 * stay a live `DEVICE_SECRET` in flash for a device that no longer exists.
 *
 * The expected id is required, and `-` is not a value it accepts. An erase with
 * no expectation is a command that wipes whichever board happens to be plugged
 * in, which is the exact shape the swap exists to refuse.
 *
 * @param {string} expectedId base64url, what `readId` just returned.
 */
export function eraseCommand(expectedId) {
  if (!expectedId || expectedId === NO_ID) {
    throw new TypeError('an erase needs the DEVICE_ID the board is expected to be holding');
  }
  return `${PREFIX}ERASE ${expectedId}`;
}

/* --- responses ----------------------------------------------------------- */

/**
 * @typedef {{ ok: true, value: string|null } | { ok: false, code: string, detail: string|null }}
 *   ProvisioningResponse
 */

/**
 * @param {string} line one line off the wire, without its terminator.
 * @returns {ProvisioningResponse|null} null when the line is not addressed to us.
 */
export function parseResponse(line) {
  const text = line.replace(/\r$/, '').trim();
  if (!text.startsWith(PREFIX)) return null;

  const body = text.slice(PREFIX.length);
  const space = body.indexOf(' ');
  const head = space === -1 ? body : body.slice(0, space);
  const rest = space === -1 ? '' : body.slice(space + 1);

  if (head === 'OK') {
    return { ok: true, value: rest === '' ? null : rest };
  }
  if (head === 'ERR') {
    const gap = rest.indexOf(' ');
    return gap === -1
      ? { ok: false, code: rest, detail: null }
      : { ok: false, code: rest.slice(0, gap), detail: rest.slice(gap + 1) };
  }

  // `SIOT READY PROVISION/1`, printed on boot for a human with a serial monitor,
  // lands here. Not a response to anything, so not one.
  return null;
}

/**
 * @param {ProvisioningResponse} response to `SIOT HELLO`
 * @returns {boolean} whether the far end is a listener this client can drive.
 */
export function isSupportedBanner(response) {
  return response.ok === true && response.value === PROTOCOL_BANNER;
}

/**
 * @param {ProvisioningResponse} response to `SIOT READ-ID`
 * @returns {string|null} the stored `DEVICE_ID`, or null for a blank board.
 */
export function storedIdFrom(response) {
  if (!response.ok) throw new Error(describeError(response));
  if (response.value === null || response.value === NO_ID) return null;
  return response.value;
}

/* --- the overwrite decision (design 5.4) --------------------------------- */

/** Nothing on the board. Provision normally. */
export const BLANK = 'blank';

/** The board already holds the id being written: a re-provision of one device. */
export const SAME = 'same';

/**
 * A different id. Writing would leave whatever device that is reporting under an
 * identity nothing in the vault can decrypt, with no way back.
 */
export const OCCUPIED = 'occupied';

/**
 * Design 5.4's three cases.
 *
 * The decision lives here rather than on the board because it needs the vault:
 * only this side can tell whether an id already on a board is one of the user's
 * own devices or a stranger's, and that difference is the whole content of the
 * warning. The board enforces the outcome (see `writeCommand`) without being
 * told the reasoning.
 *
 * `intendedId` is null when minting a new device, which is the ordinary add
 * flow. A freshly generated 128-bit id cannot match what is already on a board,
 * so `SAME` only ever arises from re-provisioning an existing one (roadmap 8.4).
 *
 * @param {string|null} storedId what the board reported.
 * @param {string|null} intendedId the id about to be written, if it already exists.
 * @param {Array<{ id: string, name: string }>} [vaultDevices] to name the occupant.
 * @returns {{ state: string, storedId: string|null, storedName: string|null }}
 */
export function classifyBoard(storedId, intendedId, vaultDevices = []) {
  if (storedId === null) {
    return { state: BLANK, storedId: null, storedName: null };
  }
  if (intendedId !== null && storedId === intendedId) {
    return { state: SAME, storedId, storedName: nameOf(storedId, vaultDevices) };
  }
  return { state: OCCUPIED, storedId, storedName: nameOf(storedId, vaultDevices) };
}

/**
 * A name only if the vault has one. An occupied board holding a device the vault
 * has never heard of is the worse case of the two, not the better one, so it must
 * not read as the unremarkable branch: it means the board belongs to some other
 * account, or to a vault entry that has been lost.
 */
function nameOf(deviceId, vaultDevices) {
  return vaultDevices.find((device) => device.id === deviceId)?.name ?? null;
}

/* --- wording ------------------------------------------------------------- */

/**
 * The board's error codes as something to put on screen. The detail the board
 * sends is written for a log, not for a person, so it is not passed through.
 *
 * @param {ProvisioningResponse} response
 * @returns {string}
 */
export function describeError(response) {
  if (response.ok) return '';
  switch (response.code) {
    case 'STALE':
      // The board found something other than what this client expected, which
      // after a successful read means the board changed underneath it. The
      // wording covers the erase too: "nothing was changed" is true of both,
      // and naming the specific command would need a second describe function
      // whose only difference is one verb.
      return 'The board is not the one that was checked a moment ago. Nothing on it was changed. Reconnect and try again.';
    case 'BAD-LENGTH':
    case 'BAD-ARGS':
    case 'BAD-COMMAND':
      // A disagreement between the two halves of the protocol: this client sent
      // something the sketch does not accept. Not something a user can fix by
      // retrying, so it does not suggest it.
      return 'The board rejected the command. Its provisioning sketch is probably a different version from this page.';
    case 'TOO-LONG':
      return 'The board rejected the command as too long. Its provisioning sketch is probably a different version from this page.';
    case 'NVS':
      return 'The board could not change its storage. Nothing on it was changed.';
    default:
      return 'The board refused the command for a reason this page does not recognise.';
  }
}
