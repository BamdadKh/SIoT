import { useState } from 'react';
import { deriveDeviceKeys, deviceSecretBytes, listDevices, toBase64Url } from '@siot/crypto';
import { ApiError, registerDevice } from '../lib/api.js';

/**
 * The two ways the vault and the server disagree about a device (roadmap 4.8),
 * worded once and rendered wherever a device is shown.
 *
 * The wrapper class is a prop rather than fixed, because the same words sit in
 * two different grounds: inside the device list a note is `.device-note`, set
 * into the ruled block it hangs from, and on a screen of its own it is a member
 * of the `.alarm` / `.success` / `.board-note` status family. What must not
 * differ between the two is the copy, which is the whole reason this is shared.
 */

/**
 * The recoverable half of a half-finished add: the vault has the secret, the
 * server never got the public key. Registering again with the same `DEVICE_ID`
 * is all that is missing, and `sign_pub` is re-derived here rather than stored,
 * because it always was derived rather than stored.
 */
export function UnregisteredNote({ device, vaultDocument, onRegistered, className = 'device-note' }) {
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
    <div className={`${className} stack stack-3`}>
      <p>
        This device is in your vault but the server has never heard of it, so it cannot upload
        anything. Its secret is safe: registering again is all that is missing.
      </p>
      <div className="row row-links">
        <button className="button button-inline" type="button" onClick={handleRegister} disabled={busy}>
          {busy ? 'Registering' : 'Finish registering'}
        </button>
        {error ? <span className="small device-note-error">{error}</span> : null}
      </div>
    </div>
  );
}

/**
 * Design 5.4's orphan: registered, with no vault record, so the `DEVICE_SECRET`
 * is gone. Nothing it has uploaded or will upload can be decrypted, by anyone,
 * ever. Not recoverable and not phrased as though it might be.
 */
export function OrphanNote({ className = 'device-note' }) {
  return (
    <p className={className}>
      The server has this device registered, but your vault has no record of it, so its{' '}
      <span className="mono">DEVICE_SECRET</span> is gone. Nothing it has uploaded or will upload
      can be decrypted. Set up a replacement and stop using this one.
    </p>
  );
}
