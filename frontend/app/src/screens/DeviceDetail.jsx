import { useEffect, useState } from 'react';
import { findDevice, removeDevice, renameDevice, DEVICE_NAME_MAX_LENGTH } from '@siot/crypto';
import { ApiError, deleteDevice } from '../lib/api.js';
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
import { RevealCredentials } from '../components/RevealCredentials.jsx';
import { EraseBoard } from '../components/EraseBoard.jsx';

/**
 * One device (roadmap 4.9).
 *
 * The home the list did not have. Rename, reveal (4.6) and delete all live here,
 * for the reason 4.9 gives: three destructive-or-sensitive controls crowded onto
 * a list row is how a stray click lands on the wrong one. Same reasoning that
 * moved sign-out into `AccountMenu`.
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

  // A terminal state rather than a redirect to the list. The device really is
  // gone, so re-reading would render "No such device", which is true and tells
  // the person nothing about what they just did; and a row silently vanishing
  // from a list is not a confirmation. Held here rather than in the section that
  // performs it, because everything below it is about a device that no longer
  // exists.
  const [deleted, setDeleted] = useState(null);

  return (
    <>
      <TopBar username={username} onSignOut={onSignOut} signingOut={signingOut} />
      <main className="page">
        <div className="page-column">
          <Link to="/" className="page-back">
            Devices
          </Link>

          {deleted ? <Deleted deleted={deleted} /> : null}

          {!deleted && state.status === 'rollback' ? (
            <RollbackWarning serverVersion={state.serverVersion} cached={state.cached} />
          ) : null}

          {!deleted && state.status === 'error' ? (
            <p className="alarm" role="alert">
              Could not check the vault: {state.message}
            </p>
          ) : null}

          {!deleted && state.status === 'ok' ? (
            <Found
              username={username}
              deviceId={deviceId}
              state={state}
              reload={reload}
              onDeleted={setDeleted}
            />
          ) : null}
        </div>
      </main>
    </>
  );
}

/** The vault opened and the server answered; now, is this device in either. */
function Found({ username, deviceId, state, reload, onDeleted }) {
  const device = state.devices.find((candidate) => candidate.id === deviceId);
  // The vault's half of this device, and the reason an orphan gets neither a
  // rename nor a reveal: there is no entry, so there is no name to change and no
  // `DEVICE_SECRET` left to show.
  const entry = device ? (findDevice(state.document, device.id) ?? null) : null;

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

      <Specification device={device} entry={entry} />

      {device.state === UNREGISTERED ? (
        <UnregisteredNote
          device={device}
          vaultDocument={state.document}
          onRegistered={reload}
          className="board-note device-section"
        />
      ) : null}

      {device.state === ORPHAN ? <OrphanNote className="unreadable device-section" /> : null}

      {/* An orphan has no vault entry, so there is no name to change, nothing to
          derive keys from, and no secret to reveal. Roadmap 4.9 is explicit that
          delete is the only action it gets. */}
      {entry ? (
        <>
          <RenameSection username={username} device={device} reload={reload} />
          <RevealCredentials device={device} entry={entry} />
        </>
      ) : null}

      <DeleteSection
        username={username}
        device={device}
        reload={reload}
        onDeleted={onDeleted}
      />
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
function Specification({ device, entry }) {
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
      <p className="prose section-lede">
        Stored in your vault, encrypted, and never sent to the server. Renaming rewrites the vault
        and nothing else, so it survives re-provisioning the hardware.
      </p>

      <form className="stack stack-4" onSubmit={handleSubmit}>
        <Field
          label="Device name"
          value={value}
          onChange={handleChange}
          disabled={busy}
          maxLength={DEVICE_NAME_MAX_LENGTH}
        />

        {error ? (
          <p className="alarm" role="alert">
            {error}
          </p>
        ) : null}

        {saved && !changed ? (
          <p className="success" role="status">
            Saved. The new name is in your vault.
          </p>
        ) : null}

        <div>
          <button className="button button-inline" type="submit" disabled={busy || !changed}>
            {busy ? 'Saving' : 'Save name'}
          </button>
        </div>
      </form>
    </section>
  );
}

/**
 * Deleting a device (roadmap 4.9).
 *
 * **A delete is two deletes and nothing can make them one transaction.** The
 * server row goes by `DELETE /devices/:id` and the vault entry by an ordinary
 * `PUT /vault`, so the order is chosen the way 4.4 chose the provisioning
 * order: by which half-finished state a person can be left holding. The server
 * row goes first. A vault write that then fails leaves the device
 * `UNREGISTERED`, a state the list already renders and which costs nothing to
 * finish from. The other order manufactures an `ORPHAN`: records nothing can
 * ever decrypt, storage nothing can reclaim, and a `DEVICE_ID` that can never be
 * registered again because the row still holds the primary key. One order is
 * recoverable and the other creates exactly the state delete exists to escape.
 *
 * The two mismatch states each collapse to one of those steps: an orphan has no
 * vault entry to remove, and an unregistered device has no server row to delete.
 *
 * The confirmation is shaped like the occupied-board override in `AddDevice`,
 * because it is the same species of thing: not armed by default, armed only by a
 * second deliberate click on a control that says what it does, and it does not
 * stay armed. It names what is being destroyed at the moment of destroying it
 * rather than in documentation nobody opens.
 */
function DeleteSection({ username, device, reload, onDeleted }) {
  const [armed, setArmed] = useState(false);
  const [busy, setBusy] = useState(null);
  const [error, setError] = useState(null);

  const onServer = device.state !== UNREGISTERED;
  const inVault = device.state !== ORPHAN;

  /*
   * Arming is a judgement about this device as it stands right now, the same way
   * arming the board override is a judgement about the board currently plugged
   * in. If the state moves underneath (a reload finds the server row already
   * gone), what was confirmed is no longer what would happen, so the refusal
   * goes back up rather than carrying over to a different act.
   */
  useEffect(() => {
    setArmed(false);
  }, [device.state]);

  async function handleDelete() {
    setError(null);

    let serverGone = false;
    try {
      if (onServer) {
        setBusy('Deleting the server record');
        await deleteDevice(device.id);
        serverGone = true;
      }

      if (inVault) {
        setBusy('Rewriting your vault');
        // Re-read rather than writing from what this screen loaded: the same
        // discipline every other vault write here uses, since a write built on
        // a stale version is a 409.
        const { version, document } = await loadVault(username);
        // Already absent is the goal state, not a failure. A retry after a
        // vault write whose response was lost must not report an error for
        // something that has in fact been achieved; same rule as the 404
        // `deleteDevice` folds into success.
        if (findDevice(document, device.id)) {
          await storeVault(username, version, removeDevice(document, device.id));
        }
      }

      setBusy(null);
      // The id travels with it: the device is gone from both places by now, so
      // the completed state has nothing left to look it up from, and erasing the
      // board needs exactly that value to hand the board's compare-and-swap.
      onDeleted({ id: device.id, name: device.name, fromServer: onServer, fromVault: inVault });
    } catch (failure) {
      setBusy(null);
      setError(describeDelete(failure, serverGone && inVault));
      // The server row went and the vault entry did not. That is the
      // recoverable half the order above was chosen for, and it is now an
      // `UNREGISTERED` device: show it as what it has become, so the section
      // re-renders offering the one step that is left.
      if (serverGone && inVault) await reload();
    }
  }

  return (
    <section className="device-section">
      <h2 className="h3">Delete</h2>

      <p className="prose section-lede">
        {onServer && inVault ? (
          <>
            Removes this device from the server and from your vault, together with every reading it
            has uploaded. There is no undo and no copy held anywhere else.
          </>
        ) : null}
        {onServer && !inVault ? (
          <>
            Its <span className="mono">DEVICE_SECRET</span> is already gone, so nothing this device
            uploaded can be read by anyone. Deleting clears those records from the server and frees
            the identifier to be registered again.
          </>
        ) : null}
        {!onServer && inVault ? (
          <>
            Removes this device&rsquo;s entry from your vault. The server has no record of it, so
            there is nothing to delete there.
          </>
        ) : null}
      </p>

      <div className="stack stack-4">
        {error ? (
          <p className="alarm" role="alert">
            {error}
          </p>
        ) : null}

        {armed ? (
          <div className="alarm" role="alert">
            <strong>
              {onServer && inVault ? (
                <>This erases every reading {device.name ?? 'this device'} has uploaded.</>
              ) : null}
              {onServer && !inVault ? <>This erases records nothing can open.</> : null}
              {!onServer && inVault ? (
                <>
                  This erases the only copy of {device.name ?? 'this device'}&rsquo;s{' '}
                  <span className="mono">DEVICE_SECRET</span>.
                </>
              ) : null}
            </strong>
            <p>
              {onServer && inVault ? (
                <>
                  The server holds those readings as ciphertext and the only key that opens them is
                  the <span className="mono">DEVICE_SECRET</span> in the vault entry being erased
                  alongside them. Neither half survives, and nothing you still hold can put either
                  back.
                </>
              ) : null}
              {onServer && !inVault ? (
                <>
                  The only key that opened them was a{' '}
                  <span className="mono">DEVICE_SECRET</span> your vault no longer holds, so this
                  destroys nothing that was still readable. It is permanent all the same: the
                  records go, and the identifier becomes free for a different device to claim.
                </>
              ) : null}
              {!onServer && inVault ? (
                <>
                  The secret exists in your vault and, if it was ever provisioned, on the board
                  itself. Erasing the vault entry leaves the board as the only place it exists, and
                  this browser has no way to read it back.
                </>
              ) : null}
            </p>
            {/* The boundary this stops at, said plainly. A confirmation that let
                someone believe the hardware had been dealt with would be lying
                about where the guarantees end: nothing here reaches NVS. */}
            <p>
              The board keeps running. Deleting here does not touch its storage, so firmware still
              holding these credentials will go on uploading into refusals until it is provisioned
              for another device or erased.
            </p>
          </div>
        ) : null}

        {armed ? (
          <div>
            <button
              className="button button-inline"
              type="button"
              onClick={handleDelete}
              disabled={Boolean(busy)}
            >
              {busy ?? 'Delete permanently'}
            </button>
          </div>
        ) : null}

        {/* The ordinary way out sits below the destructive control in both
            states, in the same place, so the eye lands on it in the same
            position whether the section is armed or not. */}
        <p className="small">
          {armed ? (
            <>
              Changed your mind?{' '}
              <button
                className="button button-link"
                type="button"
                onClick={() => setArmed(false)}
                disabled={Boolean(busy)}
              >
                Keep it
              </button>
            </>
          ) : (
            <>
              Finished with this device?{' '}
              <button className="button button-link" type="button" onClick={() => setArmed(true)}>
                Delete it
              </button>
            </>
          )}
        </p>
      </div>
    </section>
  );
}

/**
 * What is left of the page once the device is not there any more.
 *
 * The heading, the specification and every control above have been removed
 * rather than left showing values for something that no longer exists.
 */
function Deleted({ deleted }) {
  return (
    <div className="stack stack-4">
      <div className="success" role="status">
        <strong>{deleted.name ?? 'The device'}</strong> has been deleted.{' '}
        {deleted.fromServer && deleted.fromVault ? (
          <>
            Its records are gone from the server and its{' '}
            <span className="mono">DEVICE_SECRET</span> is gone from your vault. Nothing it uploaded
            can be recovered, by you or by anyone else.
          </>
        ) : null}
        {deleted.fromServer && !deleted.fromVault ? (
          <>
            Its records are gone from the server and its identifier is free to be registered again.
          </>
        ) : null}
        {!deleted.fromServer && deleted.fromVault ? (
          <>Its vault entry is gone. The server had no record of it to remove.</>
        ) : null}
      </div>

      <p className="board-note">
        If a board is still running with these credentials, it still holds them: nothing here
        reached its storage. Provision it for another device, or erase it, to stop it reporting.
      </p>

      {/* The sentence above is only actionable if something acts on it. Offered
          here and nowhere else: a board carrying a device that still exists is
          reclaimed by provisioning over it, and this is for the one going in a
          drawer. Renders nothing at all without Web Serial. */}
      <EraseBoard deviceId={deleted.id} deviceName={deleted.name} />

      <p className="small">
        <Link to="/">Back to Devices</Link>
      </p>
    </div>
  );
}

/** The date the vault recorded, not a relative phrase: it never changes. */
function formatAdded(addedAt) {
  const when = new Date(addedAt);
  if (!Number.isFinite(when.getTime())) return 'At an unreadable time';
  return when.toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric' });
}

/**
 * @param {unknown} failure
 * @param {boolean} halfDone the server row went and the vault write did not.
 */
function describeDelete(failure, halfDone) {
  // The tail is the whole point of this message. "It failed" is not actionable
  // when the server half succeeded, because the device is in a different state
  // than it was and the remaining step is a different one.
  const tail = halfDone
    ? ' The server record is already gone, so this device is now unregistered. Delete it again to' +
      ' remove the vault entry; the first step will not be repeated.'
    : ' Nothing was deleted.';

  if (failure instanceof VaultRollbackError) {
    return (
      `The server returned vault version ${failure.serverVersion} when this browser has already ` +
      `seen ${failure.cachedVersion}, so the vault was not rewritten.${tail}`
    );
  }
  if (failure instanceof ApiError) {
    if (failure.status === 401) return `Your session ended. Sign in again.${tail}`;
    if (failure.status === 409) {
      return `Your vault changed in another tab, so this write was refused. Reload and try again.${tail}`;
    }
    if (failure.status === 0) return `Could not reach the server.${tail}`;
    return `${failure.message}.${tail}`;
  }
  return `${failure?.message ?? 'Could not delete the device.'}${tail}`;
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
