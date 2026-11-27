import { SEVERITY_LABELS } from '../lib/notifications.js';

/**
 * What a notification said, inside a `.record` row (roadmap 10.3).
 *
 * Used by the Readings list on a device's page and by the cross-device list on
 * Devices, so a notification looks the same wherever it turns up. Everything
 * rendered here has already been through `validateNotification`: the severity is
 * one of four fixed words and the message is stripped of controls and bidi
 * overrides, because a device is a program somebody else wrote.
 *
 * Severity is a word, not a colour. `--alarm` is for something the person did or
 * can retry and `--rust` for what the client cannot read; a device saying
 * "critical" is neither, and a fifth colour for it would be the palette growing
 * a token for one screen. The word is set in ink at the label size, and the two
 * louder severities in the heavier weight, which is as loud as the page gets
 * about anything.
 *
 * @param {{ notification: { severity: string, message: string } | null }} props
 *        null for one that opened under the notify key and failed validation.
 */
export function NotificationBody({ notification }) {
  if (!notification) {
    return (
      <p className="record-problem">
        A notification this version does not render. It opened under the notification key, so
        the device sent it, but its contents are not the shape a notification is allowed to take.
      </p>
    );
  }

  const loud = notification.severity === 'alert' || notification.severity === 'critical';
  return (
    <p className="notification-body">
      <span className={`notification-severity${loud ? ' notification-loud' : ''}`}>
        {SEVERITY_LABELS[notification.severity]}
      </span>{' '}
      <span className="notification-message">{notification.message}</span>
    </p>
  );
}
