/**
 * Notifications across every device an account holds (roadmap 10.3 and 10.4).
 *
 * The server cannot tell a notification from a reading (ROADMAP 10.0), so there
 * is no notifications endpoint to ask. This client fetches each device's newest
 * records, opens them, and keeps the ones that turned out to be notifications.
 * Everything here works on records that are already open; no React and no
 * crypto, so `node --test` reaches it directly.
 *
 * **Two orders, and they are not equally trustworthy.** Within one device the
 * order is `seq`, which the device signed and the server cannot reorder without
 * the signature failing. Across devices there is no shared sequence, so the only
 * common clock is the server's arrival time, which is exactly as trustworthy as
 * the server. The merge below keeps both: each device's notifications stay in
 * `seq` order whatever their timestamps say, and devices are interleaved by
 * arrival time. A server that lies about arrival times can shuffle *between*
 * devices and never *within* one, and the screen says which order is which.
 *
 * **Attribution comes from the vault.** The name a notification is shown under is
 * joined from the vault by `DEVICE_ID`, the same join `device-list.js` does; the
 * server has never been told it. A device with no name (the join produced none)
 * is attributed to its bare identifier rather than to a guess.
 *
 * **Unread is a lower bound on nothing and an upper bound on nothing.** It is a
 * count of notifications this browser has seen above the vault's read mark. A
 * withholding server makes it smaller and nothing here can tell, which is the
 * same asymmetry `last-seen.js` is built around; so a zero is phrased as "none
 * unread among what has arrived", never as "no alerts".
 */

/** How each fixed severity reads, in sentence case like every other label. */
export const SEVERITY_LABELS = Object.freeze({
  info: 'Info',
  warning: 'Warning',
  alert: 'Alert',
  critical: 'Critical',
});

/**
 * How often an open Devices screen asks again (roadmap 10.4: poll on open, and
 * poll while open). A minute is the same order as the intervals sketches report
 * on; faster would mostly re-open records already held.
 */
export const NOTIFICATION_POLL_MS = 60_000;

/**
 * The notifications in one device's opened records, newest `seq` first.
 *
 * A record that opened under the notify key and failed validation is kept, with
 * `notification: null`, for the reason 6.3 keeps unopened records: dropping it
 * reports fewer alerts than the device sent.
 *
 * @param {Array<{ seq: string, receivedAt: string, kind?: string|null,
 *                 notification?: object|null, error: string|null }>} records ascending.
 * @returns {Array<{ seq: string, receivedAt: string, notification: object|null }>}
 */
export function notificationsIn(records) {
  const found = [];
  for (let index = records.length - 1; index >= 0; index -= 1) {
    const record = records[index];
    if (record.error) continue;
    if (record.kind !== 'notification' && record.kind !== 'malformed-notification') continue;
    found.push({
      seq: record.seq,
      receivedAt: record.receivedAt,
      notification: record.kind === 'notification' ? (record.notification ?? null) : null,
    });
  }
  return found;
}

/** Arrival time as a number for comparison; an unreadable one sorts last. */
function arrival(receivedAt) {
  const ms = new Date(receivedAt).getTime();
  return Number.isFinite(ms) ? ms : -Infinity;
}

/**
 * Merges every device's notifications into one list, newest first.
 *
 * A k-way merge rather than a sort on arrival time, because a sort would let the
 * server's timestamps reorder one device's notifications against its own signed
 * sequence. Here each device's list is consumed strictly in `seq` order and only
 * the choice of *which device goes next* looks at arrival time.
 *
 * @param {Array<{ deviceId: string, name: string|null, seenThrough: string|null,
 *                 notifications: ReturnType<typeof notificationsIn> }>} devices
 * @returns {Array<{ deviceId: string, name: string|null, seq: string, receivedAt: string,
 *                   notification: object|null, unread: boolean }>}
 */
export function mergeNotifications(devices) {
  const cursors = devices.map(() => 0);
  const merged = [];

  for (;;) {
    let pick = -1;
    for (let d = 0; d < devices.length; d += 1) {
      const next = devices[d].notifications[cursors[d]];
      if (!next) continue;
      if (pick === -1) {
        pick = d;
        continue;
      }
      const best = devices[pick].notifications[cursors[pick]];
      if (arrival(next.receivedAt) > arrival(best.receivedAt)) pick = d;
    }
    if (pick === -1) return merged;

    const device = devices[pick];
    const item = device.notifications[cursors[pick]];
    cursors[pick] += 1;
    merged.push({
      deviceId: device.deviceId,
      name: device.name,
      seq: item.seq,
      receivedAt: item.receivedAt,
      notification: item.notification,
      unread: isUnread(item.seq, device.seenThrough),
    });
  }
}

/**
 * @param {string} seq
 * @param {string|null|undefined} seenThrough the vault's read mark for the device.
 */
export function isUnread(seq, seenThrough) {
  if (seenThrough === null || seenThrough === undefined) return true;
  return BigInt(seq) > BigInt(seenThrough);
}

/**
 * The read mark each device should advance to when everything shown is marked
 * read: its highest notification `seq` that is still unread. Devices with
 * nothing unread are left out, so marking read writes nothing it need not.
 *
 * @param {ReturnType<typeof mergeNotifications>} merged
 * @returns {Map<string, string>} device id to `seq`.
 */
export function readMarks(merged) {
  const marks = new Map();
  for (const item of merged) {
    if (!item.unread) continue;
    const current = marks.get(item.deviceId);
    if (current === undefined || BigInt(item.seq) > BigInt(current)) {
      marks.set(item.deviceId, item.seq);
    }
  }
  return marks;
}

/**
 * The count as a sentence, never claiming silence.
 *
 * @param {number} unread
 * @param {number} shown how many notifications this browser holds.
 */
export function describeUnread(unread, shown) {
  if (shown === 0) {
    return 'None have arrived among the recent records this browser has opened.';
  }
  if (unread === 0) return 'None unread among those that have arrived.';
  return unread === 1 ? '1 unread.' : `${unread} unread.`;
}
