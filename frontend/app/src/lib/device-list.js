/**
 * Joining what the vault knows against what the server knows (roadmap 4.8).
 *
 * Neither side is complete on its own, and that split is the design working
 * rather than a schema that needs fixing:
 *
 *   the vault    holds the name and `DEVICE_SECRET`, and the server has never
 *                seen either (design 5.5). It cannot know whether a device has
 *                ever reported.
 *   the server   holds `DEVICE_ID`, `last_seq` and when the newest record
 *                arrived (design 5.2). It has no name to give and never will.
 *
 * `DEVICE_ID` is the key on both sides, so the join is by id and nothing else.
 * Names are not identifiers, are not unique, and two devices called "sensor" are
 * the user's business rather than a constraint violation.
 *
 * Deliberately free of crypto and of React so `node --test` can cover it
 * directly: the mismatch cases below are exactly the ones that are tedious to
 * reproduce by hand and easy to get wrong.
 */

/** In the vault and registered. The ordinary case. */
export const PAIRED = 'paired';

/**
 * In the vault, unknown to the server. Registration never completed, or was
 * rolled back. Recoverable: the secret is safe and `POST /devices/register` can
 * be retried with the same id.
 */
export const UNREGISTERED = 'unregistered';

/**
 * Registered, with no vault record (design 5.4's orphan). The `DEVICE_SECRET`
 * is gone, so anything this device has uploaded or will upload is permanently
 * unreadable. Not recoverable, and the list has to say so rather than hide it.
 */
export const ORPHAN = 'orphan';

/**
 * @param {Array<{ id: string, name: string, added_at: string }>} vaultDevices
 * @param {Array<{ device_id: string, last_seq: string, last_seen_at: string|null }>} serverDevices
 * @returns {Array<{
 *   id: string,
 *   name: string|null,
 *   state: typeof PAIRED | typeof UNREGISTERED | typeof ORPHAN,
 *   lastSeq: string|null,
 *   lastSeenAt: string|null,
 * }>}
 */
export function joinDevices(vaultDevices, serverDevices) {
  const fromServer = new Map(serverDevices.map((device) => [device.device_id, device]));

  // Vault order first: it is the order the person added them in, and the server
  // has its own (creation time) that would silently disagree.
  const joined = vaultDevices.map((device) => {
    const known = fromServer.get(device.id);
    fromServer.delete(device.id);

    return {
      id: device.id,
      name: device.name,
      state: known ? PAIRED : UNREGISTERED,
      lastSeq: known ? known.last_seq : null,
      lastSeenAt: known ? known.last_seen_at : null,
    };
  });

  // Whatever is left has no vault record. Last, because an orphan is a problem
  // to resolve rather than a device to use, and because it has no name to sort by.
  for (const device of fromServer.values()) {
    joined.push({
      id: device.device_id,
      name: null,
      state: ORPHAN,
      lastSeq: device.last_seq,
      lastSeenAt: device.last_seen_at,
    });
  }

  return joined;
}

/**
 * The `DEVICE_ID` as it is shown: the first and last few characters of the
 * base64url, with the middle elided.
 *
 * A 128-bit id is 22 characters and none of them mean anything to a reader, so
 * the full string is noise on a list. Both ends are kept because a truncation
 * that only keeps the front makes two ids look identical exactly when telling
 * them apart matters. The full value stays in the element's `title`.
 *
 * @param {string} id base64url
 * @returns {string}
 */
export function shortDeviceId(id) {
  return id.length <= 14 ? id : `${id.slice(0, 6)}…${id.slice(-6)}`;
}
