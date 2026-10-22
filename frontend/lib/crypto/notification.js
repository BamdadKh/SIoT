/**
 * Device notifications (roadmap Phase 10).
 *
 * A notification is an ordinary record (ROADMAP 10.0): same `POST /records`, same
 * signature, same `seq`, same AAD with the same constant record-type byte. What
 * makes it a notification is *inside the ciphertext*, and which key it opens
 * under. The server therefore cannot tell an alert from a temperature reading,
 * which is the point and also the cost: it cannot notify anyone, so delivery is
 * polled (10.4).
 *
 * Payload, beside the reading shape `{ t, r }`:
 *
 *   { t: <device seconds, 0 = no clock>, type: "notification",
 *     severity: "info" | "warning" | "alert" | "critical", message: <text> }
 *
 * The reader tries `device_data_key` first and `device_notify_key` second. A
 * record that opens under neither is reported as unopened, the same signal 6.3
 * uses for a gap, not as an error.
 *
 * `validateNotification` is the allowlist the dashboard renders through. The
 * record is authenticated, so this is not about tampering: a device is a program
 * somebody wrote, and the dashboard shows whatever it says. It rebuilds the
 * object from checked members and copies nothing through.
 */

import { decryptRecord } from './record.js';
import { utf8Bytes } from './encoding.js';

export const NOTIFICATION_TYPE = 'notification';
export const SEVERITIES = Object.freeze(['info', 'warning', 'alert', 'critical']);

/**
 * Bytes, not characters, and enforced by the firmware too (10.2): a device that
 * can emit an arbitrarily long ciphertext lets the payload *size* leak what it is
 * saying. Bounding is not padding; a fixed-size payload is a separate decision.
 */
export const NOTIFICATION_MESSAGE_MAX_BYTES = 120;

/**
 * @param {{ t?: number, severity: string, message: string }} notification
 * @returns {object} the payload to hand to `encryptRecord` under the notify key.
 */
export function buildNotificationPayload({ t = 0, severity, message }) {
  if (!SEVERITIES.includes(severity)) throw new TypeError('severity is not in the fixed set');
  if (typeof message !== 'string' || message.length === 0) {
    throw new TypeError('message must be non-empty text');
  }
  if (utf8Bytes(message).length > NOTIFICATION_MESSAGE_MAX_BYTES) {
    throw new RangeError(`message exceeds ${NOTIFICATION_MESSAGE_MAX_BYTES} bytes`);
  }
  return { t, type: NOTIFICATION_TYPE, severity, message };
}

/**
 * @param {unknown} payload a decoded plaintext.
 * @returns {{ deviceTime: number|null, severity: string, message: string } | null}
 *   null when it is not a well-formed notification; the caller shows it as
 *   unreadable rather than rendering any part of it.
 */
export function validateNotification(payload) {
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) return null;
  const own = (name) =>
    Object.prototype.hasOwnProperty.call(payload, name) ? payload[name] : undefined;

  if (own('type') !== NOTIFICATION_TYPE) return null;

  const severity = own('severity');
  if (typeof severity !== 'string' || !SEVERITIES.includes(severity)) return null;

  const raw = own('message');
  if (typeof raw !== 'string' || utf8Bytes(raw).length > NOTIFICATION_MESSAGE_MAX_BYTES) {
    return null;
  }
  // Same display-integrity strip as device names and schema labels.
  const message = raw
    // eslint-disable-next-line no-control-regex -- stripping controls is the point
    .replace(/[\u0000-\u001F\u007F-\u009F​-‏‪-‮⁦-⁩﻿]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
  if (message.length === 0) return null;

  let deviceTime = null;
  const t = own('t');
  if (t !== undefined) {
    if (typeof t !== 'number' && typeof t !== 'bigint') return null;
    const seconds = Number(t);
    if (!Number.isFinite(seconds) || seconds < 0) return null;
    deviceTime = seconds === 0 ? null : seconds;
  }

  return { deviceTime, severity, message };
}

/**
 * Opens one record under whichever of the device's two keys fits.
 *
 * @returns {Promise<{ kind: 'reading', payload: object }
 *   | { kind: 'notification', notification: object }
 *   | { kind: 'malformed-notification' }>}
 * @throws when it opens under neither key (wrong device, tampered, or a nonce
 *   that disagrees with `seq`); the caller counts it as unopened.
 */
export async function openAnyRecord({ dataKey, notifyKey, deviceId, seq, nonce, ciphertext }) {
  try {
    const payload = await decryptRecord({ dataKey, deviceId, seq, nonce, ciphertext });
    return { kind: 'reading', payload };
  } catch (dataFailure) {
    let payload;
    try {
      payload = await decryptRecord({ dataKey: notifyKey, deviceId, seq, nonce, ciphertext });
    } catch {
      // Report the first failure: it is the one a reader of a plain device sees.
      throw dataFailure;
    }
    const notification = validateNotification(payload);
    return notification ? { kind: 'notification', notification } : { kind: 'malformed-notification' };
  }
}
