import { useCallback, useEffect, useRef, useState } from 'react';
import { addDevice, generateDevice, listDevices, toBase64Url } from '@siot/crypto';
import { ApiError, registerDevice } from '../lib/api.js';
import { loadVault, storeVault, VaultRollbackError } from '../lib/vault-store.js';
import { isWebSerialSupported, requestPort, ProvisioningSession } from '../lib/web-serial.js';
import { classifyBoard, BLANK, SAME, OCCUPIED } from '../lib/provisioning-protocol.js';
import { shortDeviceId } from '../lib/device-list.js';
import { Link } from '../lib/router.jsx';
import { Plate } from '../components/Plate.jsx';
import { Field } from '../components/Field.jsx';
import { SubmitButton } from '../components/SubmitButton.jsx';

/**
 * Minting a device and putting it on a board (design 5.3, roadmap 4.4 and 4.5).
 *
 * A `Plate` rather than the `TopBar` shell, matching `ChangePassword`: one
 * focused action reached from `Devices`, with the way back in a footer row.
 *
 * Three stages, in the order design 5.3 asks for: name it, connect to the board
 * and see what is already on it, then write. The board is checked *before*
 * anything is minted, so a board that already belongs to another device costs
 * nothing to discover: no vault entry, no registration, no wasted `DEVICE_ID`.
 *
 * The name is asked for first and is not optional, which is design 5.5 taken
 * literally: there is no moment at which a device exists as a bare `DEVICE_ID`
 * waiting to be labelled. `addDevice` in the crypto layer enforces the same
 * thing, so this is a friendlier place to say it and not the only place it holds.
 */
export function AddDevice({ username, onSignOut, signingOut }) {
  const [name, setName] = useState('');
  const [stage, setStage] = useState('naming');
  const [board, setBoard] = useState(null);
  const [busy, setBusy] = useState(null);
  const [error, setError] = useState(null);
  const [done, setDone] = useState(null);

  // The occupied-board refusal, deliberately stood down. Never survives a
  // reconnect or a disconnect: arming it is a statement about the board that is
  // in front of the person right now, and a different board is a fresh decision.
  const [overriding, setOverriding] = useState(false);

  const session = useRef(null);

  // Constant for the life of the tab, so it is read once rather than per render.
  const [serialSupported] = useState(isWebSerialSupported);

  const release = useCallback(async () => {
    const open = session.current;
    session.current = null;
    await open?.close();
  }, []);

  // A port stays open for the life of the tab. Leaving one behind means the next
  // attempt fails on a port already in use, with nothing on screen saying why.
  useEffect(() => () => void release(), [release]);

  async function handleConnect() {
    setError(null);
    setOverriding(false);

    let port;
    try {
      port = await requestPort();
    } catch {
      // The chooser was dismissed without picking anything. A deliberate cancel
      // is not a failure and gets no error message.
      return;
    }

    setBusy('Connecting to the board');
    try {
      const opened = new ProvisioningSession(port);
      await opened.open();
      session.current = opened;

      const storedId = await opened.readId();

      /*
       * The vault is read here, before anything is written anywhere, for two
       * reasons. It names an occupied board's device where the vault knows it,
       * which is the whole content of the warning below. And a rollback surfaces
       * now rather than three steps later with a board half-provisioned.
       */
      const { document } = await loadVault(username);
      // `null` because the device does not exist yet: an id that has not been
      // generated cannot match what is on a board, so any occupant is OCCUPIED.
      setBoard(classifyBoard(storedId, null, listDevices(document)));
      setStage('board');
    } catch (failure) {
      await release();
      setError(failure instanceof VaultRollbackError ? describeRollback(failure) : failure.message);
    } finally {
      setBusy(null);
    }
  }

  async function handleAdd({ writeToBoard }) {
    setError(null);

    let device = null;
    let stored = null;

    try {
      setBusy('Generating keys');
      device = await generateDevice();

      // Re-read rather than trusting what the connect step saw. The vault may
      // have moved under this tab, and a write built on a stale version is a 409
      // that costs a freshly minted DEVICE_SECRET to recover from.
      setBusy('Reading your vault');
      const { version, document } = await loadVault(username);

      const next = addDevice(document, {
        deviceId: device.deviceId,
        deviceSecret: device.deviceSecret,
        name,
      });

      /*
       * The vault write goes first, and design 5.3 lists registration as step 2
       * and the board write as step 4. Both deviations are about which
       * half-completed state a person can be left holding.
       *
       * The vault is the only durable home this secret has. Write the board
       * first and lose the tab and the secret exists on a board and nowhere
       * else: it will happily encrypt records that nothing in the world can
       * open. Register first and lose the vault write and the id is burned
       * permanently and shows as an orphan (design 5.4) forever.
       *
       * Vault first, and every later failure is recoverable: the secret is
       * stored, the same id registers again, and the same board takes the same
       * credentials on a second run.
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

      if (writeToBoard) {
        setBusy('Writing to the board');
        // `board.storedId` is what the board reported a moment ago, and the
        // board checks it again before writing. If someone swapped the cable in
        // between, this refuses rather than overwriting the new board.
        await session.current.write(
          board.storedId,
          toBase64Url(device.deviceId),
          toBase64Url(device.deviceSecret),
        );
      }

      // What the write destroyed, if anything, so the confirmation can say so.
      // Read off the classification rather than `overriding`, because only an
      // OCCUPIED board had something on it to lose.
      const replaced = writeToBoard && board?.state === OCCUPIED ? board : null;

      setDone({ name: stored, wroteToBoard: writeToBoard, replaced });
      setStage('done');
    } catch (failure) {
      if (stored !== null) {
        // The vault write landed. Saying nothing happened would be false, and
        // the device really is recoverable from the list.
        setDone({ name: stored, wroteToBoard: false, replaced: null });
        setStage('done');
      }
      setError(describe(failure, stored !== null));
    } finally {
      setBusy(null);
      // The secret's home is the vault and the board from here on. Best effort,
      // the same caveat the keyring carries: JS cannot promise a byte is gone.
      device?.deviceSecret.fill(0);
      device?.dataKey.fill(0);
      await release();
    }
  }

  const named = name.trim().length > 0;

  /*
   * One form, and the primary action is whatever the current stage's next step
   * is. Keeping it a real submit rather than a set of onClick buttons is what
   * makes Enter in the name field do the obvious thing, and a submit fired by
   * Enter still counts as the user gesture `requestPort` requires.
   */
  function handleSubmit(event) {
    event.preventDefault();
    if (busy) return;

    if (stage === 'naming') {
      if (!named) {
        setError('Give the device a name first.');
        return;
      }
      return void (serialSupported ? handleConnect() : handleAdd({ writeToBoard: false }));
    }
    // An occupied board has no submit at all until the refusal has been stood
    // down, so Enter cannot overwrite one either: arming it is a click on a
    // control that says what it does, and nothing else reaches this branch.
    if (stage === 'board' && (board.state !== OCCUPIED || overriding)) {
      return void handleAdd({ writeToBoard: true });
    }
  }

  async function handleDisconnect() {
    await release();
    setBoard(null);
    setError(null);
    setOverriding(false);
    setStage('naming');
  }

  return (
    <Plate>
      <div className="wordmark" style={{ marginBottom: 'var(--sp-5)' }}>
        SIoT
      </div>
      <h1 className="h1">Add a device</h1>
      <p className="prose" style={{ marginTop: 'var(--sp-3)' }}>
        The name is stored in your vault, encrypted, and never reaches the server. Neither does
        the device&rsquo;s secret: it goes from this page straight to the board over USB. The
        server is told an identifier and a public key, which is all it needs to tell a genuine
        upload from a forged one.
      </p>

      <form onSubmit={handleSubmit}>
        {stage !== 'done' ? (
          <div style={{ marginTop: 'var(--sp-5)' }}>
            <Field
              label="Device name"
              value={name}
              onChange={setName}
              disabled={Boolean(busy) || stage === 'board'}
              placeholder="Greenhouse humidity"
              maxLength={64}
              autoFocus
            />
          </div>
        ) : null}

        {error ? (
          <p className="alarm" style={{ marginTop: 'var(--sp-4)' }} role="alert">
            {error}
          </p>
        ) : null}

        {stage === 'naming' ? (
          <NamingStage
            named={named}
            busy={busy}
            serialSupported={serialSupported}
            onSkip={() => handleAdd({ writeToBoard: false })}
          />
        ) : null}

        {stage === 'board' ? (
          <BoardStage
            board={board}
            busy={busy}
            overriding={overriding}
            onOverride={() => setOverriding(true)}
            onDisconnect={handleDisconnect}
          />
        ) : null}

        {stage === 'done' ? <DoneStage done={done} /> : null}
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

/**
 * Name it, then reach for the board.
 *
 * Connecting is the primary action even though it is not the last one, because
 * it is the next thing to do and the guided path is the supported path (design
 * 5.3). Adding without a board is a link rather than a button: it is a real
 * thing to want on a browser that cannot do Web Serial, and it leaves a device
 * half-set-up, so it should not sit where a stray click lands.
 */
function NamingStage({ named, busy, serialSupported, onSkip }) {
  return (
    <>
      {!serialSupported ? (
        <p className="board-note" style={{ marginTop: 'var(--sp-4)' }}>
          This browser cannot talk to a board. Writing credentials over USB needs Web Serial,
          which today means a Chromium browser: Chrome, Edge or Opera on desktop. You can still
          add the device here and provision it from a Chromium browser later, or with the
          credentials themselves once revealing them is built.
        </p>
      ) : null}

      <div style={{ marginTop: 'var(--sp-5)' }}>
        <SubmitButton busy={Boolean(busy)} busyLabel={busy} disabled={!named}>
          {serialSupported ? 'Connect board' : 'Add device'}
        </SubmitButton>
      </div>

      {serialSupported ? (
        <p className="small" style={{ margin: 'var(--sp-4) 0 0' }}>
          Not an ESP32, or no board to hand?{' '}
          <button
            className="button button-link"
            type="button"
            onClick={onSkip}
            disabled={!named || Boolean(busy)}
          >
            Add it without one
          </button>
        </p>
      ) : null}
    </>
  );
}

/**
 * What is already on the board, and design 5.4's decision about it.
 *
 * An occupied board is refused, not warned about: the default state offers no
 * submit at all, because overwriting leaves whatever device that is with no
 * hardware carrying its identity and, when the vault has never heard of it, no
 * way back at all.
 *
 * The override is an escape hatch and is shaped like one, the same way revealing
 * credentials is (design 5.3.1): it is a second deliberate action, it states its
 * cost at the moment of arming rather than in documentation, and it does not
 * stay armed. Reconnecting or disconnecting puts the refusal back, because the
 * judgement being made is about the board currently plugged in and the next
 * board is a fresh one. What it is not is a path: nothing in the ordinary flow
 * routes through here, and the recommendation above it does not change.
 */
function BoardStage({ board, busy, overriding, onOverride, onDisconnect }) {
  if (board.state === OCCUPIED) {
    return (
      <>
        <div className="alarm" style={{ marginTop: 'var(--sp-4)' }} role="alert">
          <strong>This board already belongs to another device.</strong>
          <p style={{ margin: 'var(--sp-2) 0 0' }}>
            It is holding{' '}
            {board.storedName ? (
              <>
                <strong>{board.storedName}</strong> (
                <span className="mono" title={board.storedId}>
                  {shortDeviceId(board.storedId)}
                </span>
                )
              </>
            ) : (
              <>
                <span className="mono" title={board.storedId}>
                  {shortDeviceId(board.storedId)}
                </span>
                , which is not in your vault
              </>
            )}
            . Writing over it would leave that device reporting under credentials nothing can
            decrypt, permanently.{' '}
            {overriding
              ? 'Nothing has been changed yet.'
              : 'Nothing has been changed. Use a different board, or re-provision that device from its own entry in Devices.'}
          </p>
        </div>

        {overriding ? (
          <>
            {/* Olive like every other action, not rust: the accent rule is not
                negotiable and rust is the mark, not a danger colour. What makes
                this read as the heavier choice is the label and the fact that
                a deliberate action was needed to make it appear at all. */}
            <div style={{ marginTop: 'var(--sp-5)' }}>
              <SubmitButton busy={Boolean(busy)} busyLabel={busy}>
                Overwrite the board
              </SubmitButton>
            </div>
            <p className="small" style={{ margin: 'var(--sp-4) 0 0' }}>
              Leave it as it is?{' '}
              <button
                className="button button-link"
                type="button"
                onClick={onDisconnect}
                disabled={Boolean(busy)}
              >
                Disconnect
              </button>
            </p>
          </>
        ) : (
          <>
            {/* The ordinary way out first, the hatch last. Someone scanning for
                the way forward should reach "Disconnect" before they reach the
                thing that destroys a device. */}
            <p className="small" style={{ margin: 'var(--sp-4) 0 0' }}>
              Finished with this board?{' '}
              <button
                className="button button-link"
                type="button"
                onClick={onDisconnect}
                disabled={Boolean(busy)}
              >
                Disconnect
              </button>
            </p>
            <p className="small" style={{ margin: 'var(--sp-3) 0 0' }}>
              Retiring that device?{' '}
              <button
                className="button button-link"
                type="button"
                onClick={onOverride}
                disabled={Boolean(busy)}
              >
                Overwrite it anyway
              </button>
            </p>
          </>
        )}
      </>
    );
  }

  return (
    <>
      <p className="board-note" style={{ marginTop: 'var(--sp-4)' }}>
        {board.state === BLANK
          ? 'This board has no credentials on it. Ready to provision.'
          : 'This board already holds this device. Writing again will refresh its credentials.'}
      </p>

      <div style={{ marginTop: 'var(--sp-5)' }}>
        <SubmitButton busy={Boolean(busy)} busyLabel={busy}>
          Write to board
        </SubmitButton>
      </div>

      <p className="small" style={{ margin: 'var(--sp-4) 0 0' }}>
        Wrong board?{' '}
        <button
          className="button button-link"
          type="button"
          onClick={onDisconnect}
          disabled={Boolean(busy)}
        >
          Disconnect
        </button>
      </p>
    </>
  );
}

/** Says which of the two endings happened, because they are not the same state. */
function DoneStage({ done }) {
  return done.wroteToBoard ? (
    <div className="success" style={{ marginTop: 'var(--sp-5)' }} role="status">
      <strong>{done.name}</strong> is in your vault, registered, and written to the board. It
      will start reporting once it is running firmware that uses those credentials.
      {/* An override destroyed something. Naming it here is the point: the
          decision was taken two screens ago and the confirmation is the last
          place it can be recorded for the person who took it. */}
      {done.replaced ? (
        <>
          {' '}
          It replaced{' '}
          {done.replaced.storedName ? (
            <strong>{done.replaced.storedName}</strong>
          ) : (
            <span className="mono" title={done.replaced.storedId}>
              {shortDeviceId(done.replaced.storedId)}
            </span>
          )}
          , which is no longer on any hardware and will not report again.
        </>
      ) : null}
    </div>
  ) : (
    <div className="board-note" style={{ marginTop: 'var(--sp-5)' }} role="status">
      <strong>{done.name}</strong> is in your vault and registered. Its credentials have not
      reached any hardware yet, so it will show in Devices as never having reported. Provision an
      ESP32 from this page when you have one to hand, or, for other hardware, read the
      credentials out once revealing them is built.
    </div>
  );
}

function describeRollback(failure) {
  return (
    `The server returned vault version ${failure.serverVersion} when this browser has already ` +
    `seen ${failure.cachedVersion}. Nothing was added. Open Devices to see the warning in full.`
  );
}

function describe(failure, savedToVault) {
  const tail = savedToVault
    ? ' The device is saved in your vault; finish setting it up from Devices.'
    : ' Nothing was changed.';

  if (failure instanceof VaultRollbackError) return describeRollback(failure);

  if (failure instanceof ApiError) {
    if (failure.status === 401) return `Your session ended. Sign in again.${tail}`;
    if (failure.status === 0) return `Could not reach the server.${tail}`;
    // A 409 is either the vault losing a race with another tab (nothing saved)
    // or a DEVICE_ID collision, which at 128 bits means something is very wrong.
    return `${failure.message}.${tail}`;
  }
  return `${failure?.message ?? 'Could not add the device.'}${tail}`;
}
