/**
 * Notifications for every paired device, fetched on open and polled while open
 * (roadmap 10.3 and 10.4).
 *
 * **Poll, never push.** The server cannot tell a notification from a reading
 * (ROADMAP 10.0), so it has nothing to push on. This asks for each paired
 * device's newest page of records, opens each record under both of the device's
 * keys (`openRawRecord`), and keeps the notifications. It does so for every
 * paired device alike, whether or not that device has ever sent one, so the
 * fetch pattern says nothing about which devices are the alerting kind: the
 * server sees the same requests from an account with a smoke alarm as from one
 * with three thermometers.
 *
 * **Polling pauses while the tab is hidden** and resumes, with an immediate
 * fetch, when it is shown again. A background tab decrypting fifty records per
 * device per minute is a cost to the battery and no use to anyone who is not
 * looking; nothing is lost by it, since the records wait on the server.
 *
 * **Only the newest page per device.** This is a recent list, not a history: the
 * device's own page has the full sequence and "Load older". A notification older
 * than its device's last `RECORDS_PAGE_SIZE` records is not counted as unread
 * here, and the section says the count is over what it has opened.
 *
 * Keys are derived per poll and zeroed after, the same derive-use-zero shape as
 * `use-device-records.js`.
 *
 * Untested as a hook, like every other hook here; `notifications.js` holds the
 * claims and is covered by `node --test`.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { deviceIdBytes, findDevice } from '@siot/crypto';
import { fetchRecords } from './api.js';
import { PAIRED } from './device-list.js';
import { openKeyRing, openRawRecord } from './record-keys.js';
import { RECORDS_PAGE_SIZE } from './records.js';
import { NOTIFICATION_POLL_MS, mergeNotifications, notificationsIn } from './notifications.js';

/**
 * @param {{ status: string, devices?: Array, document?: object }} vaultState
 *        what `useVaultDevices` returned.
 * @returns {{ status: 'idle' | 'loading' | 'ok', merged: Array, failed: string[],
 *             checkedAt: Date | null, refresh: () => Promise<void> }}
 */
export function useNotifications(vaultState) {
  // device id -> its notifications, newest seq first.
  const [byDevice, setByDevice] = useState(null);
  const [failed, setFailed] = useState([]);
  const [checkedAt, setCheckedAt] = useState(null);

  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const ready = vaultState.status === 'ok';
  const paired = useMemo(() => {
    if (!ready) return [];
    return vaultState.devices
      .filter((device) => device.state === PAIRED)
      .map((device) => ({ device, entry: findDevice(vaultState.document, device.id) }))
      .filter(({ entry }) => entry);
  }, [ready, vaultState.devices, vaultState.document]);

  // The secrets that open each device's records, serialised so a re-render with
  // the same vault contents does not restart polling.
  const pairedKey = JSON.stringify(
    paired.map(({ entry }) => [entry.id, entry.secret, entry.retired ?? []]),
  );

  const inFlight = useRef(false);
  const refresh = useCallback(async () => {
    if (inFlight.current) return;
    inFlight.current = true;
    try {
      const entries = JSON.parse(pairedKey).map(([id, secret, retired]) => ({ id, secret, retired }));
      const results = await Promise.all(entries.map((entry) => newestNotifications(entry)));
      if (!mounted.current) return;

      const next = new Map();
      const failures = [];
      for (const [index, result] of results.entries()) {
        if (result.ok) next.set(entries[index].id, result.notifications);
        else failures.push(entries[index].id);
      }
      setByDevice(next);
      setFailed(failures);
      setCheckedAt(new Date());
    } finally {
      inFlight.current = false;
    }
  }, [pairedKey]);

  useEffect(() => {
    if (!ready) return undefined;
    refresh();

    let timer = null;
    const start = () => {
      if (timer === null) timer = setInterval(refresh, NOTIFICATION_POLL_MS);
    };
    const stop = () => {
      if (timer !== null) clearInterval(timer);
      timer = null;
    };
    const onVisibility = () => {
      if (document.visibilityState === 'visible') {
        refresh();
        start();
      } else {
        stop();
      }
    };

    if (document.visibilityState === 'visible') start();
    document.addEventListener('visibilitychange', onVisibility);
    return () => {
      stop();
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, [ready, refresh]);

  // The read marks come from the vault and the names from the join, both of
  // which can change (a "mark read" reloads the vault) without a refetch.
  const merged = useMemo(() => {
    if (!byDevice) return [];
    return mergeNotifications(
      paired
        .filter(({ device }) => byDevice.has(device.id))
        .map(({ device, entry }) => ({
          deviceId: device.id,
          name: device.name ?? null,
          seenThrough: entry.notifications_seen_through ?? null,
          notifications: byDevice.get(device.id),
        })),
    );
  }, [byDevice, paired]);

  return {
    status: !ready ? 'idle' : byDevice === null ? 'loading' : 'ok',
    merged,
    failed,
    checkedAt,
    refresh,
  };
}

/**
 * One device's newest page, opened, reduced to its notifications.
 *
 * @param {{ id: string, secret: string, retired: Array }} entry
 */
async function newestNotifications(entry) {
  const ring = openKeyRing(entry);
  try {
    const { records: raw } = await fetchRecords(entry.id, { order: 'desc', limit: RECORDS_PAGE_SIZE });
    const idBytes = deviceIdBytes({ id: entry.id });
    const ascending = [];
    for (const record of [...raw].reverse()) {
      ascending.push(await openRawRecord(ring, idBytes, record));
    }
    return { ok: true, notifications: notificationsIn(ascending) };
  } catch {
    // One device failing to answer is not a reason to hide the others'. The
    // section names how many could not be checked.
    return { ok: false };
  } finally {
    ring.zero();
  }
}
