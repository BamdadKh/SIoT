/**
 * One device's records, fetched and opened in this browser (roadmap 6.3).
 *
 * The whole of the product's claim runs through this file. The server hands back
 * ciphertext it has never been able to read, and the key that opens it comes out
 * of the vault entry the same browser sealed at provisioning time. Nothing here
 * asks the server for anything but blobs, and nothing here sends it anything.
 *
 * **Keys are derived once per page and zeroed when the page is done.**
 * `device_data_key` is HKDF over a `DEVICE_SECRET` the vault holds, and a rotated
 * device holds several: each record opens under the secret `secretForSeq` picks
 * for its `seq` (design 9.3), each distinct secret derived at most once. They are
 * not kept between pages: a key that lives as long as the screen does is a key
 * sitting in memory through every idle minute someone leaves this tab open.
 * Zeroing it is best effort in a garbage-collected runtime, the same caveat
 * `deriveAccountKeys` states, and it costs a line.
 *
 * **A record that will not open stays in the list.** `decryptRecord` refuses a
 * wrong key, a tampered blob, a record moved to another device and a nonce that
 * disagrees with its `seq`, all as one failure, because they mean the same thing
 * to a reader: this is not a record this device wrote at this position. Dropping
 * those would report a shorter history than the device has, which is the same
 * mistake `vault-document.js` refuses to make with entries it cannot parse. They
 * are counted and rendered in place instead.
 *
 * **Newest first, and that is why the route grew a direction.** `GET
 * /devices/:id/records` paged ascending only, so reaching the newest record meant
 * paging through every record before it. The page walks backwards with
 * `before_seq`; the export in 6.4 is the same walk forwards.
 *
 * Untested, like every other hook here: it is React plus crypto, and the halves
 * worth testing are already covered separately (`records.js` by `node --test`,
 * `decryptRecord` by `test/record.test.js` and the published vectors).
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import { decryptRecord, deviceIdBytes, fromBase64Url } from '@siot/crypto';
import { fetchRecords } from './api.js';
import { openKeyRing } from './record-keys.js';
import { RECORDS_PAGE_SIZE } from './records.js';

/**
 * @param {{ id: string, secret: string }} entry the vault's half of this device.
 *        Required: without a `DEVICE_SECRET` there is no key, and an orphan is
 *        excluded by the screen rather than handled with an empty state here.
 * @returns {[
 *   { status: 'loading' }
 *   | { status: 'error', message: string }
 *   | { status: 'ok', records: Array, unopened: number, exhausted: boolean,
 *       loadingMore: boolean, moreError?: string },
 *   () => Promise<void>,
 *   () => Promise<void>,
 * ]} the state, a reload, and a request for the next older page.
 */
export function useDeviceRecords(entry) {
  const [state, setState] = useState({ status: 'loading' });

  // Handlers outlive the effect that first ran them (loading an older page is a
  // click), so the mounted flag is a ref, same as `use-vault-devices.js`.
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const deviceId = entry.id;
  // Retired secrets change what opens a record, so they are part of the identity
  // of this effect; serialised so a re-render with equal contents does not refetch.
  const secretsKey = JSON.stringify([entry.secret, entry.retired ?? []]);

  /**
   * Fetches one page and opens it. Ascending `seq` within the page, whichever
   * direction it was fetched in, because that is the order gaps are read in.
   */
  const openPage = useCallback(
    async (beforeSeq) => {
      const idBytes = deviceIdBytes({ id: deviceId });
      const [secret, retired] = JSON.parse(secretsKey);
      const ring = openKeyRing({ secret, retired });

      try {
        const { records: raw } = await fetchRecords(deviceId, {
          order: 'desc',
          limit: RECORDS_PAGE_SIZE,
          ...(beforeSeq === undefined ? {} : { beforeSeq }),
        });

        const ascending = [...raw].reverse();
        const opened = [];
        for (const record of ascending) {
          const seq = BigInt(record.seq);
          try {
            const payload = await decryptRecord({
              dataKey: await ring.keyFor(record.seq),
              deviceId: idBytes,
              seq,
              nonce: fromBase64Url(record.nonce),
              ciphertext: fromBase64Url(record.ciphertext),
            });
            opened.push({ seq: record.seq, receivedAt: record.created_at, payload, error: null });
          } catch (failure) {
            opened.push({
              seq: record.seq,
              receivedAt: record.created_at,
              payload: null,
              error: failure.message,
            });
          }
        }

        // A short page means the server had nothing more before the cursor.
        return { opened, exhausted: raw.length < RECORDS_PAGE_SIZE };
      } finally {
        ring.zero();
      }
    },
    [deviceId, secretsKey],
  );

  const reload = useCallback(async () => {
    setState({ status: 'loading' });
    try {
      const { opened, exhausted } = await openPage(undefined);
      if (!mounted.current) return;
      setState({
        status: 'ok',
        records: opened,
        unopened: opened.filter((record) => record.error).length,
        exhausted,
        loadingMore: false,
      });
    } catch (failure) {
      if (!mounted.current) return;
      setState({ status: 'error', message: failure.message });
    }
  }, [deviceId, secretsKey, openPage]);

  /*
   * Reads `state` directly rather than through a `setState` updater. An updater
   * is not a place to take a value out of: React is free to run it twice, and it
   * would then be a second fetch of the same page. The callback is rebuilt on
   * every render as a result, which costs nothing for something only an onClick
   * reads.
   */
  const loadOlder = useCallback(async () => {
    if (state.status !== 'ok' || state.loadingMore || state.exhausted) return;
    const cursor = state.records[0]?.seq;
    if (cursor === undefined) return;

    setState({ ...state, loadingMore: true, moreError: null });

    try {
      const { opened, exhausted } = await openPage(cursor);
      if (!mounted.current) return;
      setState((current) => {
        if (current.status !== 'ok') return current;
        // Prepended, because the page just fetched is older than everything
        // already held and the list is kept ascending.
        const records = [...opened, ...current.records];
        return {
          ...current,
          records,
          unopened: records.filter((record) => record.error).length,
          exhausted,
          loadingMore: false,
        };
      });
    } catch (failure) {
      if (!mounted.current) return;
      // A failed older page is not a reason to throw away the records already on
      // screen: what is held is still true, there is just no more of it yet.
      setState((current) =>
        current.status === 'ok'
          ? { ...current, loadingMore: false, moreError: failure.message }
          : current,
      );
    }
  }, [state, openPage]);

  useEffect(() => {
    reload();
  }, [reload]);

  return [state, reload, loadOlder];
}
