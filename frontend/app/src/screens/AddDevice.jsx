import { useState } from 'react';
import { addDevice, generateDevice, listDevices, toBase64Url } from '@siot/crypto';
import { ApiError, registerDevice } from '../lib/api.js';
import { loadVault, storeVault, VaultRollbackError } from '../lib/vault-store.js';
import { Link } from '../lib/router.jsx';
import { Plate } from '../components/Plate.jsx';
import { Field } from '../components/Field.jsx';
import { SubmitButton } from '../components/SubmitButton.jsx';

/**
 * Minting a device (design Section 5.3, roadmap 4.4).
 *
 * A `Plate` rather than the `TopBar` shell, matching `ChangePassword`: one
 * focused action reached from `Devices`, with the way back in a footer row.
 *
 * The name is asked for first and is not optional, which is design 5.5 taken
 * literally: there is no moment at which a device exists as a bare `DEVICE_ID`
 * waiting to be labelled. `addDevice` in the crypto layer enforces the same
 * thing, so this is a friendlier place to say it and not the only place it holds.
 *
 * **This screen does not write to a board yet.** Design 5.3's steps 1 to 3
 * (mint, register, vault) are here; step 4, the Web Serial write to NVS, is
 * roadmap 4.5 and needs the provisioning sketch to exist before any of it can be
 * exercised. So the completion state says plainly that the credentials have not
 * reached hardware rather than implying a device is ready. When 4.5 lands, the
 * "Connect device" step follows the one below and this note comes out.
 */
export function AddDevice({ username, onSignOut, signingOut }) {
  const [name, setName] = useState('');
  const [busy, setBusy] = useState(null);
  const [error, setError] = useState(null);
  const [added, setAdded] = useState(null);

  async function handleSubmit(event) {
    event.preventDefault();
    if (!name.trim()) {
      setError('Give the device a name first.');
      return;
    }
    setError(null);
    setAdded(null);

    let device = null;
    let stored = null;

    try {
      setBusy('Generating keys');
      device = await generateDevice();

      // Re-read rather than trusting whatever the list already had. The vault
      // may have moved under this tab, and a write built on a stale version is
      // a 409 that costs a freshly minted DEVICE_SECRET to recover from.
      setBusy('Reading your vault');
      const { version, document } = await loadVault(username);

      const next = addDevice(document, {
        deviceId: device.deviceId,
        deviceSecret: device.deviceSecret,
        name,
      });

      /*
       * The vault write goes first, and design 5.3 lists registration as step 2.
       * The deviation is deliberate, and it is about which half-completed state
       * a person can be left holding.
       *
       * Register first and let the vault write fail: the server has a DEVICE_ID
       * and a signing key, and the DEVICE_SECRET that only ever existed in this
       * tab's memory is gone. That id is burned permanently and shows as an
       * orphan (design 5.4) forever.
       *
       * Vault first and let registration fail: the secret is safely stored and
       * registering again with the same id works. The device list offers exactly
       * that. One order is recoverable and the other is not.
       */
      setBusy('Saving to your vault');
      await storeVault(username, version, next);

      // Read the name back out rather than echoing the input: the crypto layer
      // normalises it, and the confirmation should say what was actually stored.
      const entries = listDevices(next);
      stored = entries[entries.length - 1].name;

      setBusy('Registering with the server');
      await registerDevice({
        device_id: toBase64Url(device.deviceId),
        sign_pub: toBase64Url(device.signPub),
      });

      setAdded({ name: stored, registered: true });
      setName('');
    } catch (failure) {
      if (stored !== null) {
        // The vault write landed and only registration failed. Saying nothing
        // happened would be false, and the device really is recoverable.
        setAdded({ name: stored, registered: false });
        setName('');
      }
      setError(describe(failure, stored !== null));
    } finally {
      setBusy(null);
      // The secret's home is the vault from here on. Best effort, the same
      // caveat the keyring carries: JS cannot promise a byte is gone.
      device?.deviceSecret.fill(0);
      device?.dataKey.fill(0);
    }
  }

  return (
    <Plate>
      <div className="wordmark" style={{ marginBottom: 'var(--sp-5)' }}>
        SIoT
      </div>
      <h1 className="h1">Add a device</h1>
      <p className="prose" style={{ marginTop: 'var(--sp-3)' }}>
        The name is stored in your vault, encrypted, and never reaches the server. Neither does
        the device&rsquo;s secret. The server is told an identifier and a public key, which is all
        it needs to tell a genuine upload from a forged one.
      </p>

      <form onSubmit={handleSubmit}>
        <div style={{ marginTop: 'var(--sp-5)' }}>
          <Field
            label="Device name"
            value={name}
            onChange={(value) => {
              setName(value);
              setAdded(null);
            }}
            disabled={Boolean(busy)}
            placeholder="Greenhouse humidity"
            maxLength={64}
            autoFocus
          />
        </div>

        {error ? (
          <p className="alarm" style={{ marginTop: 'var(--sp-4)' }} role="alert">
            {error}
          </p>
        ) : null}

        {added?.registered ? (
          <div className="success" style={{ marginTop: 'var(--sp-4)' }} role="status">
            <strong>{added.name}</strong> is in your vault and registered. Its credentials have
            not reached any hardware yet: writing them to a board over USB is the next part being
            built.
          </div>
        ) : null}

        <div style={{ marginTop: 'var(--sp-5)' }}>
          <SubmitButton busy={Boolean(busy)} busyLabel={busy} disabled={!name.trim()}>
            Add device
          </SubmitButton>
        </div>
      </form>

      <hr className="rule" style={{ margin: 'var(--sp-6) 0 18px' }} />
      <div className="row spread">
        <span className="small">
          Signed in as <span className="mono">{username}</span>
        </span>
        <div className="row" style={{ gap: 'var(--sp-4)' }}>
          <Link to="/" className="button button-link">
            Devices
          </Link>
          <button
            className="button button-link"
            type="button"
            onClick={onSignOut}
            disabled={signingOut}
          >
            {signingOut ? 'Signing out' : 'Sign out'}
          </button>
        </div>
      </div>
    </Plate>
  );
}

function describe(failure, savedToVault) {
  const tail = savedToVault
    ? ' The device is saved in your vault; finish registering it from Devices.'
    : ' Nothing was changed.';

  if (failure instanceof VaultRollbackError) {
    return (
      `The server returned vault version ${failure.serverVersion} when this browser has already ` +
      `seen ${failure.cachedVersion}. Nothing was added. Open Devices to see the warning in full.`
    );
  }
  if (failure instanceof ApiError) {
    if (failure.status === 401) return `Your session ended. Sign in again.${tail}`;
    if (failure.status === 0) return `Could not reach the server.${tail}`;
    // A 409 is either the vault losing a race with another tab (nothing saved)
    // or a DEVICE_ID collision, which at 128 bits means something is very wrong.
    return `${failure.message}.${tail}`;
  }
  return `${failure?.message ?? 'Could not add the device.'}${tail}`;
}
