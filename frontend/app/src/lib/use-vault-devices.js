/**
 * The one load every signed-in, unlocked screen starts from: the vault joined
 * against the server's device metadata.
 *
 * It is a hook rather than a helper because two screens now need it (`Devices`
 * and `DeviceDetail`) and the second copy is the one that would forget the
 * rollback branch. `loadVault` already makes a rollback impossible to ignore by
 * throwing, and this makes the *handling* of it impossible to write twice.
 *
 * `version` is carried out with the document, not discarded. Every vault edit is
 * a compare-and-swap against the version it was read at, so a screen that can
 * write needs the number it read.
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import { listDevices } from '@siot/crypto';
import { fetchDevices } from './api.js';
import { loadVault, VaultRollbackError } from './vault-store.js';
import { joinDevices } from './device-list.js';

/**
 * @param {string} username
 * @returns {[
 *   { status: 'checking' }
 *   | { status: 'ok', version: number, document: object, dropped: number, devices: Array }
 *   | { status: 'rollback', serverVersion: number, cached: number }
 *   | { status: 'error', message: string },
 *   () => Promise<void>,
 * ]}
 */
export function useVaultDevices(username) {
  const [state, setState] = useState({ status: 'checking' });

  // `reload` is called from event handlers that outlive the effect which first
  // ran it (a rename, a registration), so the mounted flag is a ref rather than
  // the usual effect-local variable.
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const reload = useCallback(async () => {
    try {
      const [{ version, document, dropped }, { devices: registered }] = await Promise.all([
        loadVault(username),
        fetchDevices(),
      ]);
      if (!mounted.current) return;

      setState({
        status: 'ok',
        version,
        document,
        dropped,
        devices: joinDevices(listDevices(document), registered),
      });
    } catch (err) {
      if (!mounted.current) return;
      if (err instanceof VaultRollbackError) {
        setState({ status: 'rollback', serverVersion: err.serverVersion, cached: err.cachedVersion });
        return;
      }
      setState({ status: 'error', message: err.message });
    }
  }, [username]);

  useEffect(() => {
    reload();
  }, [reload]);

  return [state, reload];
}
