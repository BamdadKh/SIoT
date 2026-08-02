import { useCallback, useEffect, useRef, useState } from 'react';
import {
  deriveDeviceKeys,
  deviceSecretBytes,
  listDevices,
  toBase64Url,
} from '@siot/crypto';
import { ApiError, fetchDevices, registerDevice } from '../lib/api.js';
import { loadVault, VaultRollbackError } from '../lib/vault-store.js';
import { joinDevices, shortDeviceId, ORPHAN, UNREGISTERED } from '../lib/device-list.js';
import { describeLastSeen, exactLastSeen } from '../lib/last-seen.js';
import { Link } from '../lib/router.jsx';
import { TopBar } from '../components/TopBar.jsx';

/**
 * The signed-in, unlocked home: every device, named from the vault and dated
 * from the server (roadmap 4.8).
 *
 * Two fetches that neither side could do alone. The vault has names and secrets
 * the server has never seen; the server has arrival times the vault cannot know.
 * `joinDevices` puts them together by `DEVICE_ID` and surfaces the two ways they
 * can disagree, both of which are real states rather than error handling.
 *
 * On mount it still does the roadmap 3.2 rollback check, now inside `loadVault`
 * rather than inline here, since `AddDevice` needs the identical check and the
 * one that gets written second is the one that forgets it.
 */
export function Devices({ username, onSignOut, signingOut }) {
  const [state, setState] = useState({ status: 'checking' });

  // `load` is called both on mount and again after a device is registered from
  // the list, so the mounted check is a ref rather than the usual effect-local
  // flag: the second caller outlives the effect that created it.
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const load = useCallback(async () => {
    try {
      const [{ document, dropped }, { devices: registered }] = await Promise.all([
        loadVault(username),
        fetchDevices(),
      ]);
      if (!mounted.current) return;

      setState({
        status: 'ok',
        devices: joinDevices(listDevices(document), registered),
        vaultDocument: document,
        dropped,
      });
    } catch (err) {
      if (!mounted.current) return;
      if (err instanceof VaultRollbackError) {
        setState({
          status: 'rollback',
          serverVersion: err.serverVersion,
          cached: err.cachedVersion,
        });
        return;
      }
      setState({ status: 'error', message: err.message });
    }
  }, [username]);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <>
      <TopBar username={username} onSignOut={onSignOut} signingOut={signingOut} />
      <main className="page">
        {/*
          The whole head waits for the fetches, rather than the heading landing
          first and the link arriving with the list. A heading that is alone for
          one paint and then gains a control reads as the page still assembling
          itself; nothing below it can be shown yet anyway.
        */}
        {state.status !== 'checking' ? (
          <div className="page-head">
            <h1 className="h2">Devices</h1>
            {state.status === 'ok' ? (
              <Link to="/add-device" className="button button-inline">
                Add device
              </Link>
            ) : null}
          </div>
        ) : null}

        {state.status === 'rollback' ? (
          <section className="rollback-warning">
            <span className="tick tick-tl" />
            <span className="tick tick-tr" />
            <span className="tick tick-bl" />
            <span className="tick tick-br" />
            <h2 className="h3">This vault went backwards</h2>
            <p className="prose" style={{ marginTop: 'var(--sp-3)' }}>
              The server just returned vault version{' '}
              <span className="mono">{state.serverVersion}</span>, but this browser has already
              seen version <span className="mono">{state.cached}</span>. That can only happen if
              the server served an old copy of your vault, either by mistake or on purpose.
              Nothing has been decrypted or trusted.
            </p>
            <p className="prose" style={{ marginTop: 'var(--sp-3)' }}>
              Do not make changes to devices or credentials from this browser until this is
              resolved.
            </p>
          </section>
        ) : null}

        {state.status === 'error' ? (
          <p className="alarm" role="alert">
            Could not check the vault: {state.message}
          </p>
        ) : null}

        {state.status === 'ok' && state.dropped > 0 ? (
          <p className="alarm" style={{ marginBottom: 'var(--sp-4)' }} role="alert">
            {state.dropped} {state.dropped === 1 ? 'entry' : 'entries'} in your vault could not be
            read and {state.dropped === 1 ? 'was' : 'were'} skipped. The vault itself is intact and
            authentic, so this is a fault in the client that wrote {state.dropped === 1 ? 'it' : 'them'},
            not tampering.
          </p>
        ) : null}

        {state.status === 'ok' && state.devices.length === 0 ? (
          <section className="slot">
            <span className="tick tick-tl" />
            <span className="tick tick-tr" />
            <span className="tick tick-bl" />
            <span className="tick tick-br" />
            <h2 className="h3">No devices yet</h2>
            <p className="prose">Name one and this browser will mint its keys locally.</p>
          </section>
        ) : null}

        {state.status === 'ok' && state.devices.length > 0 ? (
          <ul className="device-list">
            {state.devices.map((device) => (
              <DeviceRow
                key={device.id}
                device={device}
                vaultDocument={state.vaultDocument}
                onRegistered={load}
              />
            ))}
          </ul>
        ) : null}
      </main>
    </>
  );
}

/**
 * One device.
 *
 * The liveness line never says "offline". The client knows it has not received a
 * record, not why: a withholding server and a flat battery look identical from
 * here, and the server cannot forge a newer record at a higher `seq` but can
 * always withhold one. So the honest claim is when something last arrived.
 */
function DeviceRow({ device, vaultDocument, onRegistered }) {
  return (
    <li className={`device${device.state === ORPHAN ? ' device-orphan' : ''}`}>
      <div className="device-identity">
        {device.name ? (
          <h2 className="h3">{device.name}</h2>
        ) : (
          <h2 className="h3 device-nameless">Unnamed device</h2>
        )}
        <span className="mono" title={device.id}>
          {shortDeviceId(device.id)}
        </span>
      </div>

      <div className="device-liveness">
        <span className="small" title={exactLastSeen(device.lastSeenAt)}>
          {device.state === UNREGISTERED ? 'Not registered' : describeLastSeen(device.lastSeenAt)}
        </span>
      </div>

      {device.state === UNREGISTERED ? (
        <UnregisteredNote device={device} vaultDocument={vaultDocument} onRegistered={onRegistered} />
      ) : null}

      {device.state === ORPHAN ? (
        <p className="device-note">
          The server has this device registered, but your vault has no record of it, so its{' '}
          <span className="mono">DEVICE_SECRET</span> is gone. Nothing it has uploaded or will
          upload can be decrypted. Set up a replacement and stop using this one.
        </p>
      ) : null}
    </li>
  );
}

/**
 * The recoverable half of a half-finished add: the vault has the secret, the
 * server never got the public key. Registering again with the same `DEVICE_ID`
 * is all that is missing, and the public key is re-derived here rather than
 * stored, because it always was derived rather than stored.
 */
function UnregisteredNote({ device, vaultDocument, onRegistered }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  async function handleRegister() {
    setBusy(true);
    setError(null);

    let secret = null;
    try {
      const entry = listDevices(vaultDocument).find((candidate) => candidate.id === device.id);
      if (!entry) throw new Error('this device is no longer in the vault');

      secret = deviceSecretBytes(entry);
      const { dataKey, signPub } = await deriveDeviceKeys(secret);
      dataKey.fill(0);

      await registerDevice({ device_id: device.id, sign_pub: toBase64Url(signPub) });
      await onRegistered();
    } catch (failure) {
      setError(
        failure instanceof ApiError && failure.status === 409
          ? 'That identifier is registered to a different account. Set up a replacement device.'
          : (failure?.message ?? 'Could not register the device.'),
      );
      setBusy(false);
    } finally {
      secret?.fill(0);
    }
  }

  return (
    <div className="device-note">
      <p style={{ margin: 0 }}>
        This device is in your vault but the server has never heard of it, so it cannot upload
        anything. Its secret is safe: registering again is all that is missing.
      </p>
      <div className="row" style={{ gap: 'var(--sp-4)', marginTop: 'var(--sp-3)' }}>
        <button className="button button-inline" type="button" onClick={handleRegister} disabled={busy}>
          {busy ? 'Registering' : 'Finish registering'}
        </button>
        {error ? <span className="small device-note-error">{error}</span> : null}
      </div>
    </div>
  );
}
