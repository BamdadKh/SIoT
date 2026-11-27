import { useState } from 'react';
import { markNotificationsSeen } from '@siot/crypto';
import { ApiError } from '../lib/api.js';
import { Link } from '../lib/router.jsx';
import { describeSequence } from '../lib/sequence.js';
import { shortDeviceId } from '../lib/device-list.js';
import { describeUnread, readMarks } from '../lib/notifications.js';
import { loadVault, storeVault, VaultRollbackError } from '../lib/vault-store.js';
import { NotificationBody } from './NotificationBody.jsx';

/**
 * What the account's devices have said that was not a reading (roadmap 10.3,
 * 10.4), on the Devices screen.
 *
 * The same register as the device list above it and the Readings list on a
 * device's page: one strong border, light rules between rows. A row is a
 * `.record`, headed by where it came from and when it arrived, so a notification
 * looks the same here as in its device's own sequence.
 *
 * **The lede says which order is which**, because the two are not equally
 * trustworthy: within a device the order is the device's signed `seq`; across
 * devices it is the server's arrival time. And the count is worded over what has
 * arrived, never as "no alerts", for the reason `last-seen.js` never says
 * "offline".
 *
 * **Marking read is a vault write** (`markNotificationsSeen`), not a request to
 * the server, so the server learns that the vault changed and nothing about why.
 * It re-reads the vault before writing, like every other vault write here.
 */
export function Notifications({ username, notifications, onMarked }) {
  const { status, merged, failed } = notifications;
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  if (status === 'idle') return null;

  const unread = merged.filter((item) => item.unread).length;

  async function handleMarkRead() {
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      const marks = readMarks(merged);
      const { version, document } = await loadVault(username);
      let next = document;
      for (const [deviceId, seq] of marks) {
        // A device deleted in another tab since this list was fetched has no
        // entry to mark; skipping it is the goal state, not a failure.
        try {
          next = markNotificationsSeen(next, deviceId, seq);
        } catch {
          // no such device any more
        }
      }
      if (next !== document) await storeVault(username, version, next);
      await onMarked();
    } catch (failure) {
      setError(describeFailure(failure));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="notifications" aria-labelledby="notifications-heading">
      <h2 className="h3" id="notifications-heading">
        Notifications
        {unread > 0 ? <span className="notifications-count">{unread} unread</span> : null}
      </h2>
      <p className="prose section-lede">
        Opened in this browser from each device&rsquo;s recent records; the server stores them as
        ciphertext and cannot tell them from readings. One device&rsquo;s notifications are in the
        order it sent them. Between devices they are ordered by when they reached the server, which
        is only as reliable as the server.
      </p>

      <div className="stack stack-4">
        {status === 'loading' ? (
          <p className="board-note" role="status">
            Opening recent records&hellip;
          </p>
        ) : null}

        {failed.length > 0 ? (
          <p className="alarm" role="alert">
            {failed.length === 1
              ? 'One device could not be checked, so anything it sent is missing from this list.'
              : `${failed.length} devices could not be checked, so anything they sent is missing from this list.`}{' '}
            It is asked again on the next check, every minute while this page is open.
          </p>
        ) : null}

        {status === 'ok' && merged.length === 0 ? (
          <p className="board-note">{describeUnread(0, 0)}</p>
        ) : null}

        {status === 'ok' && merged.length > 0 ? (
          <ol className="record-list">
            {merged.map((item) => (
              <li
                className={`record${item.unread ? ' notification-unread' : ''}`}
                key={`${item.deviceId}-${item.seq}`}
              >
                <div className="record-head">
                  <span className="notification-source">
                    <Link to={`/device/${item.deviceId}`}>
                      {item.name ?? shortDeviceId(item.deviceId)}
                    </Link>
                    <span className="record-seq mono">
                      {' '}
                      {describeSequence(item.seq) ?? item.seq}
                    </span>
                  </span>
                  <span className="record-when" title={item.receivedAt}>
                    {formatArrival(item.receivedAt)}
                  </span>
                </div>
                <NotificationBody notification={item.notification} />
              </li>
            ))}
          </ol>
        ) : null}

        {error ? (
          <p className="alarm" role="alert">
            {error}
          </p>
        ) : null}

        {status === 'ok' && merged.length > 0 ? (
          <p className="small">
            {unread > 0 ? (
              <>
                {describeUnread(unread, merged.length)}{' '}
                <button
                  className="button button-link"
                  type="button"
                  onClick={handleMarkRead}
                  disabled={busy}
                >
                  {busy ? 'Saving' : 'Mark as read'}
                </button>
              </>
            ) : (
              <span className="ink-faint">{describeUnread(0, merged.length)}</span>
            )}
          </p>
        ) : null}
      </div>
    </section>
  );
}

function formatArrival(receivedAt) {
  const when = new Date(receivedAt);
  if (!Number.isFinite(when.getTime())) return 'At an unreadable time';
  return when.toLocaleString();
}

function describeFailure(failure) {
  if (failure instanceof VaultRollbackError) {
    return (
      `The server returned vault version ${failure.serverVersion} when this browser has already ` +
      `seen ${failure.cachedVersion}, so nothing was marked read.`
    );
  }
  if (failure instanceof ApiError) {
    if (failure.status === 401) return 'Your session ended. Sign in again; nothing was marked read.';
    if (failure.status === 409) {
      return 'Your vault changed in another tab, so this write was refused. Try again.';
    }
    if (failure.status === 0) return 'Could not reach the server. Nothing was marked read.';
    return `${failure.message}. Nothing was marked read.`;
  }
  return failure?.message ?? 'Could not mark these read.';
}
