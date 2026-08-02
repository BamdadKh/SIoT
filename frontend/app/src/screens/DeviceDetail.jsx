import { useState } from 'react';
import { renameDevice, DEVICE_NAME_MAX_LENGTH } from '@siot/crypto';
import { ApiError } from '../lib/api.js';
import { loadVault, storeVault, VaultRollbackError } from '../lib/vault-store.js';
import { useVaultDevices } from '../lib/use-vault-devices.js';
import { ORPHAN, UNREGISTERED } from '../lib/device-list.js';
import { describeLastSeen, exactLastSeen } from '../lib/last-seen.js';
import { describeSequence } from '../lib/sequence.js';
import { Link } from '../lib/router.jsx';
import { TopBar } from '../components/TopBar.jsx';
import { Field } from '../components/Field.jsx';
import { RollbackWarning } from '../components/RollbackWarning.jsx';
import { OrphanNote, UnregisteredNote } from '../components/DeviceStateNote.jsx';

/**
 * One device (roadmap 4.9).
 *
 * The home the list did not have. Rename lives here, and 4.6's reveal and 4.9's
 * delete will land beside it, for the reason that item gives: three
 * destructive-or-sensitive controls crowded onto a list row is how a stray click
 * lands on the wrong one. Same reasoning that moved sign-out into `AccountMenu`.
 *
 * The `TopBar` shell rather than a `Plate`, unlike `ChangePassword` and
 * `AddDevice`. Those are one focused action each, reached and left; this is the
 * app's view of a thing that exists, with several actions on it, and it is where
 * a per-device dashboard would eventually hang. It reads its own data rather
 * than being handed it, so the URL survives a reload.
 *
 * Everything above the rule is the union of what two parties know and neither
 * knows alone: the name and the date added come from the vault, which the server
 * has never seen; the sequence and the arrival time come from the server, which
 * has no name to give.
 */
export function DeviceDetail({ username, deviceId, onSignOut, signingOut }) {
  const [state, reload] = useVaultDevices(username);

  return (
    <>
      <TopBar username={username} onSignOut={onSignOut} signingOut={signingOut} />
      <main className="page">
        <div className="page-column">
          <Link to="/" className="page-back">
            Devices
          </Link>

          {state.status === 'rollback' ? (
            <RollbackWarning serverVersion={state.serverVersion} cached={state.cached} />
          ) : null}

          {state.status === 'error' ? (
            <p className="alarm" role="alert">
              Could not check the vault: {state.message}
            </p>
          ) : null}

          {state.status === 'ok' ? (
            <Found
              username={username}
              deviceId={deviceId}
              state={state}
              reload={reload}
            />
          ) : null}
        </div>
      </main>
    </>
  );
}

/** The vault opened and the server answered; now, is this device in either. */
function Found({ username, deviceId, state, reload }) {
  const device = state.devices.find((candidate) => candidate.id === deviceId);

  if (!device) {
    return (
      <section className="slot">
        <span className="tick tick-tl" />
        <span className="tick tick-tr" />
        <span className="tick tick-bl" />
        <span className="tick tick-br" />
        <h2 className="h3">No such device</h2>
        <p className="prose">
          Neither your vault nor the server has a device with this identifier. It may have been
          deleted, or the link may be from another account.
        </p>
      </section>
    );
  }

  return (
    <>
      {device.name ? (
        <h1 className="h2 device-title">{device.name}</h1>
      ) : (
        <h1 className="h2 device-title device-nameless">Unnamed device</h1>
      )}

      <Specification device={device} vaultDocument={state.document} />

      {device.state === UNREGISTERED ? (
        <UnregisteredNote
          device={device}
          vaultDocument={state.document}
          onRegistered={reload}
          className="board-note device-section"
        />
      ) : null}

      {device.state === ORPHAN ? <OrphanNote className="unreadable device-section" /> : null}

      {device.state !== ORPHAN ? (
        <RenameSection username={username} device={device} reload={reload} />
      ) : null}
    </>
  );
}

/**
 * What is known about the device, labelled in the same mono the form fields use
 * for exactly this: values the machine owns rather than words a person chose.
 *
 * The full `DEVICE_ID` is shown here rather than the elided form the list uses.
 * On a list the middle of a 22-character identifier is noise; on the device's
 * own page it is the thing someone came to copy.
 */
function Specification({ device, vaultDocument }) {
  const entry = vaultDocument.devices.find((candidate) => candidate.id === device.id) ?? null;
  const sequence = describeSequence(device.lastSeq);

  return (
    <dl className="spec">
      <dt>Device ID</dt>
      <dd className="mono spec-id">{device.id}</dd>

      {entry ? (
        <>
          <dt>Added</dt>
          <dd>{formatAdded(entry.added_at)}</dd>
        </>
      ) : null}

      <dt>Last record</dt>
      <dd>
        {device.state === UNREGISTERED ? (
          <span className="ink-faint">Not registered with the server</span>
        ) : (
          <span title={exactLastSeen(device.lastSeenAt)}>{describeLastSeen(device.lastSeenAt)}</span>
        )}
      </dd>

      {device.state !== UNREGISTERED ? (
        <>
          <dt>Sequence</dt>
          <dd>
            {sequence ? (
              <>
                <span className="mono">{device.lastSeq}</span>
                <span className="small spec-gloss">{sequence}</span>
              </>
            ) : (
              <span className="ink-faint">Nothing accepted yet</span>
            )}
          </dd>
        </>
      ) : null}
    </dl>
  );
}

/**
 * Renaming is an ordinary vault write: the same `PUT /vault` and the same
 * version bump as adding a device, with no endpoint of its own, because the name
 * has never been anywhere but the vault (design 5.5).
 *
 * The vault is re-read here rather than written from the copy this screen
 * loaded. The document may have moved under this tab, and a write built on a
 * stale version is a 409 the person would have to understand to recover from.
 */
function RenameSection({ username, device, reload }) {
  const [draft, setDraft] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [saved, setSaved] = useState(false);

  const stored = device.name ?? '';
  const value = draft ?? stored;
  const changed = value.trim() !== stored;

  function handleChange(next) {
    setDraft(next);
    setSaved(false);
    setError(null);
  }

  async function handleSubmit(event) {
    event.preventDefault();
    if (busy || !changed) return;

    setBusy(true);
    setError(null);
    try {
      const { version: current, document } = await loadVault(username);
      await storeVault(username, current, renameDevice(document, device.id, value));
      // Back to reading the stored name, so the field shows what the crypto
      // layer normalised rather than what was typed.
      setDraft(null);
      setSaved(true);
      await reload();
    } catch (failure) {
      setError(describe(failure));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="device-section">
      <h2 className="h3">Name</h2>
      <p className="prose" style={{ margin: 'var(--sp-3) 0 var(--sp-4)' }}>
        Stored in your vault, encrypted, and never sent to the server. Renaming rewrites the vault
        and nothing else, so it survives re-provisioning the hardware.
      </p>

      <form onSubmit={handleSubmit}>
        <Field
          label="Device name"
          value={value}
          onChange={handleChange}
          disabled={busy}
          maxLength={DEVICE_NAME_MAX_LENGTH}
        />

        {error ? (
          <p className="alarm" style={{ marginTop: 'var(--sp-4)' }} role="alert">
            {error}
          </p>
        ) : null}

        {saved && !changed ? (
          <p className="success" style={{ marginTop: 'var(--sp-4)' }} role="status">
            Saved. The new name is in your vault.
          </p>
        ) : null}

        <div style={{ marginTop: 'var(--sp-4)' }}>
          <button className="button button-inline" type="submit" disabled={busy || !changed}>
            {busy ? 'Saving' : 'Save name'}
          </button>
        </div>
      </form>
    </section>
  );
}

/** The date the vault recorded, not a relative phrase: it never changes. */
function formatAdded(addedAt) {
  const when = new Date(addedAt);
  if (!Number.isFinite(when.getTime())) return 'At an unreadable time';
  return when.toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric' });
}

function describe(failure) {
  if (failure instanceof VaultRollbackError) {
    return (
      `The server returned vault version ${failure.serverVersion} when this browser has already ` +
      `seen ${failure.cachedVersion}. The name was not changed. Open Devices to see the warning ` +
      `in full.`
    );
  }
  if (failure instanceof ApiError) {
    if (failure.status === 401) return 'Your session ended. Sign in again; the name was not changed.';
    if (failure.status === 409) {
      return 'Your vault changed in another tab, so this write was refused. Reload and try again.';
    }
    if (failure.status === 0) return 'Could not reach the server. The name was not changed.';
    return `${failure.message}. The name was not changed.`;
  }
  return failure?.message ?? 'Could not save the name.';
}
