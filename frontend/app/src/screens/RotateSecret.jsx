import { useCallback, useEffect, useRef, useState } from 'react';
import {
  deriveAccountKeys,
  deriveDeviceKeys,
  findDevice,
  fromBase64Url,
  generateDeviceSecret,
  promotePendingSecret,
  setPendingSecret,
  toBase64Url,
} from '@siot/crypto';
import { ApiError, fetchSalt, rotateDeviceKey } from '../lib/api.js';
import { loadVault, storeVault, VaultRollbackError } from '../lib/vault-store.js';
import { useVaultDevices } from '../lib/use-vault-devices.js';
import { findReaders } from '../lib/grant-access.js';
import { isWebSerialSupported, requestPort, ProvisioningSession } from '../lib/web-serial.js';
import { classifyBoard, BLANK, SAME } from '../lib/provisioning-protocol.js';
import { PAIRED, shortDeviceId } from '../lib/device-list.js';
import { describeSequence } from '../lib/sequence.js';
import { Link } from '../lib/router.jsx';
import { Plate } from '../components/Plate.jsx';
import { PlateHead } from '../components/PlateHead.jsx';
import { SessionFooter } from '../components/PlateFoot.jsx';
import { Field } from '../components/Field.jsx';
import { SubmitButton } from '../components/SubmitButton.jsx';
import { RollbackWarning } from '../components/RollbackWarning.jsx';

/**
 * Giving a device a new `DEVICE_SECRET` (design 9.3, roadmap 8.4).
 *
 * This is what "revoke a grant" means, and the only thing it can mean: a device
 * holding a grant already has this device's data key, and nothing can take a key
 * back. A new secret means a new data key, so a grantee keeps everything up to
 * the rotation and nothing after it. The screen says that in those words before
 * anything happens, because the person most likely to be here is the one who
 * believed "revoke" meant something stronger.
 *
 * The device keeps its `DEVICE_ID`, its name and its fields: it is the same
 * physical thing in the same place. Its earlier readings stay readable here,
 * because the vault keeps each retired secret beside the last `seq` it covers.
 *
 * **Four steps, ordered by what each failure leaves behind**, the same reasoning
 * `AddDevice` uses:
 *
 *   1. The new secret goes into the vault as *pending*, beside the current one.
 *      The vault is the only durable home it has; minting it anywhere first
 *      risks a secret that exists on a board and nowhere else.
 *   2. The server rebinds the device to the new public key and answers with the
 *      `seq` boundary. From here the old key's uploads are refused, which is the
 *      revocation actually happening. Requires the account password: a session
 *      alone must not be able to hand the signing slot to whoever holds a copy
 *      of the data key.
 *   3. The vault promotes the pending secret and retires the old one at that
 *      boundary.
 *   4. The board is written.
 *
 * A failure at 1, 2 or 3 leaves a pending secret that the next attempt reuses
 * rather than replaces, so a retry after a lost response converges instead of
 * minting a second secret. A failure at 4 leaves a board running on credentials
 * the server now refuses, and the cure is writing again, which is offered.
 *
 * **One hardware path: the board this device is already on.** A blank board or
 * one holding another device is refused, with no override. Rotation is not how
 * a device moves boards, and a different board starts its sequence from scratch
 * where the server has already accepted higher numbers.
 */
export function RotateSecret({ username, deviceId, onSignOut, signingOut }) {
  const [state] = useVaultDevices(username);

  const device = state.status === 'ok' ? state.devices.find((d) => d.id === deviceId) : null;
  const entry = state.status === 'ok' ? (findDevice(state.document, deviceId) ?? null) : null;
  const backTo = `/device/${deviceId}`;

  return (
    <Plate>
      <PlateHead title="Rotate secret">
        Gives this device a new <span className="mono">DEVICE_SECRET</span>, on the board and in
        your vault. It keeps its identifier, its name and its fields.
      </PlateHead>

      {state.status === 'rollback' ? (
        <RollbackWarning serverVersion={state.serverVersion} cached={state.cached} />
      ) : null}

      {state.status === 'error' ? (
        <p className="alarm" role="alert">
          Could not check the vault: {state.message}
        </p>
      ) : null}

      {state.status === 'ok' && (!device || !entry || device.state !== PAIRED) ? (
        <p className="board-note">
          <strong>Nothing to rotate.</strong> A secret can be rotated only for a device that is both
          in your vault and registered with the server.
        </p>
      ) : null}

      {state.status === 'ok' && device && entry && device.state === PAIRED ? (
        <Rotation username={username} device={device} entry={entry} devices={state.devices} />
      ) : null}

      <p className="small">
        Back to{' '}
        <Link to={backTo} className="button button-link">
          {device?.name ?? 'the device'}
        </Link>
      </p>

      <SessionFooter username={username} onSignOut={onSignOut} signingOut={signingOut} />
    </Plate>
  );
}

function Rotation({ username, device, entry, devices }) {
  const name = device.name ?? 'This device';
  const [password, setPassword] = useState('');
  const [stage, setStage] = useState('intro');
  const [board, setBoard] = useState(null);
  const [busy, setBusy] = useState(null);
  const [error, setError] = useState(null);
  const [done, setDone] = useState(null);
  // `undefined` while asking, `null` if the server could not be asked. Neither
  // may read as "no grants": that would be a claim made out of an absence.
  const [readers, setReaders] = useState(undefined);
  // The new secret is on the server and in the vault and the board write did not
  // land. The board still holds the old one, which the server now refuses.
  const [writePending, setWritePending] = useState(false);

  const session = useRef(null);
  const [serialSupported] = useState(isWebSerialSupported);

  const release = useCallback(async () => {
    const open = session.current;
    session.current = null;
    await open?.close();
  }, []);
  useEffect(() => () => void release(), [release]);

  // Who currently holds this device's key, so the cost below names them.
  const others = devices
    .filter((other) => other.id !== device.id && other.state === PAIRED)
    .map((other) => other.id)
    .join(',');
  useEffect(() => {
    let live = true;
    findReaders(device.id, others ? others.split(',') : [])
      .then((found) => live && setReaders(found))
      .catch(() => live && setReaders(null));
    return () => {
      live = false;
    };
  }, [device.id, others]);
  const readerNames = (readers ?? []).map(
    ({ id }) => devices.find((other) => other.id === id)?.name ?? shortDeviceId(id),
  );

  async function handleConnect() {
    setError(null);
    let port;
    try {
      port = await requestPort();
    } catch {
      return;
    }

    setBusy('Connecting to the board');
    try {
      const opened = new ProvisioningSession(port);
      await opened.open();
      session.current = opened;
      const storedId = await opened.readId();
      setBoard(classifyBoard(storedId, device.id, devices));
      setStage('board');
    } catch (failure) {
      await release();
      setError(failure.message);
    } finally {
      setBusy(null);
    }
  }

  async function handleRotate() {
    setError(null);
    let loginKey = null;
    let kek = null;
    let fresh = null;
    let through = null;
    // Which step failed decides what is true afterwards, so it is tracked here
    // rather than read back from state the closure cannot see change.
    let step = 'vault';

    try {
      // Step 1, or its resumption. A pending secret left by an attempt that did
      // not finish is reused: the server may already be bound to it.
      setBusy('Reading your vault');
      let { version, document } = await loadVault(username);
      let pending = findDevice(document, device.id)?.pending ?? null;
      if (!pending) {
        setBusy('Generating a new secret');
        fresh = generateDeviceSecret();
        const next = setPendingSecret(document, device.id, fresh);
        setBusy('Saving it to your vault');
        await storeVault(username, version, next);
        pending = toBase64Url(fresh);
      }

      // Step 2. The password is proved to the server, not checked here.
      step = 'rebind';
      setBusy('Checking your password');
      const { salt } = await fetchSalt(username);
      ({ loginKey, kek } = await deriveAccountKeys(password, fromBase64Url(salt)));
      kek.fill(0);
      kek = null;

      const pendingBytes = fromBase64Url(pending);
      const { dataKey, signPub } = await deriveDeviceKeys(pendingBytes);
      dataKey.fill(0);

      setBusy('Rebinding the device on the server');
      const answer = await rotateDeviceKey(device.id, {
        signPub: toBase64Url(signPub),
        currentLoginKey: toBase64Url(loginKey),
      });
      through = answer.through_seq;

      // Step 3. Re-read: the first write moved the version.
      step = 'promote';
      setBusy('Retiring the old secret');
      ({ version, document } = await loadVault(username));
      await storeVault(username, version, promotePendingSecret(document, device.id, through));

      // Step 4.
      step = 'board';
      setDone({ through });
      await writeBoard(pending);
      pendingBytes.fill(0);
      setPassword('');
      setStage('done');
      await release();
    } catch (failure) {
      setError(describe(failure, step));
    } finally {
      setBusy(null);
      loginKey?.fill(0);
      kek?.fill(0);
      fresh?.fill(0);
    }
  }

  async function writeBoard(secret) {
    setWritePending(true);
    setBusy('Writing to the board');
    // The board checks the id again before writing, so a board swapped since the
    // check refuses rather than taking this device's credentials.
    await session.current.write(device.id, device.id, secret);
    setWritePending(false);
  }

  async function handleWriteAgain() {
    setError(null);
    try {
      const { document } = await loadVault(username);
      const secret = findDevice(document, device.id)?.secret;
      await writeBoard(secret);
      setPassword('');
      setStage('done');
      await release();
    } catch (failure) {
      setError(describe(failure, 'board'));
    } finally {
      setBusy(null);
    }
  }

  async function handleDisconnect() {
    await release();
    setBoard(null);
    setError(null);
    setStage('intro');
  }

  function handleSubmit(event) {
    event.preventDefault();
    if (busy) return;
    if (stage === 'intro') return void handleConnect();
    if (stage === 'board' && board.state === SAME) {
      return void (writePending ? handleWriteAgain() : handleRotate());
    }
  }

  if (!serialSupported) {
    return (
      <p className="board-note">
        This browser cannot talk to a board. Rotating a secret writes the new one to the board over
        USB, which needs Web Serial: Chrome, Edge or Opera on desktop.
      </p>
    );
  }

  if (stage === 'done' && !writePending) {
    return (
      <div className="success" role="status">
        <strong>{name}</strong> has a new secret, on the board and in your vault. Readings up to{' '}
        {describeBoundary(done.through)} were sealed under the old one and still open here.
        {readerNames.length > 0 ? (
          <>
            {' '}
            {joinNames(readerNames)} can still read everything up to that point and nothing after
            it. Grant again from the device&rsquo;s page to restore any of them.
          </>
        ) : null}
      </div>
    );
  }

  return (
    <form className="stack stack-5" onSubmit={handleSubmit}>
      <div className="stack stack-4">
        <div className="board-note">
          <strong>What this changes, and what it cannot.</strong>
          {!readers ? (
            <p>
              {readers === null ? 'Could not check' : 'Checking'} which devices hold a grant on{' '}
              {name}. Any that do keep everything it sent before this, permanently, and read nothing
              it sends after.
            </p>
          ) : readerNames.length > 0 ? (
            <p>
              {joinNames(readerNames)} {readerNames.length === 1 ? 'holds' : 'hold'} a grant on{' '}
              {name}. After this, {readerNames.length === 1 ? 'it reads' : 'they read'} nothing{' '}
              {name} sends, and keep everything it sent before, permanently. A key that has been
              handed over cannot be taken back.
            </p>
          ) : (
            <p>
              No device holds a grant on {name}. Rotating still replaces the secret everywhere it
              lives, which is the remedy if it may have been copied.
            </p>
          )}
          <p>
            Its earlier readings stay readable to you: the old secret stays in your vault, retired,
            for exactly the records it sealed.
          </p>
          <p>
            Have the board plugged in over USB and running the provisioning listener, as when it was
            added. From the moment the server is rebound until the board is written, the
            board&rsquo;s uploads are refused.
          </p>
        </div>

        {entry.pending ? (
          <p className="board-note">
            A rotation for this device was started and not finished. Continuing uses the same new
            secret rather than making another.
          </p>
        ) : null}

        <Field
          label="Your password"
          type="password"
          value={password}
          onChange={setPassword}
          disabled={Boolean(busy) || writePending}
          autoComplete="current-password"
          autoFocus
        />
      </div>

      {error ? (
        <p className="alarm" role="alert">
          {error}
        </p>
      ) : null}

      {stage === 'intro' ? (
        <SubmitButton busy={Boolean(busy)} busyLabel={busy} disabled={!password}>
          Connect board
        </SubmitButton>
      ) : null}

      {stage === 'board' ? (
        <BoardStage
          board={board}
          name={name}
          busy={busy}
          writePending={writePending}
          canSubmit={Boolean(password) || writePending}
          onDisconnect={handleDisconnect}
        />
      ) : null}
    </form>
  );
}

/**
 * Only the board this device is already on. A refusal here offers no override:
 * unlike Add device, nothing a person could want is behind it.
 */
function BoardStage({ board, name, busy, writePending, canSubmit, onDisconnect }) {
  const disconnect = (
    <button
      className="button button-link"
      type="button"
      onClick={onDisconnect}
      disabled={Boolean(busy)}
    >
      Disconnect
    </button>
  );

  if (board.state !== SAME) {
    return (
      <div className="stack stack-4">
        <div className="alarm" role="alert">
          <strong>
            {board.state === BLANK
              ? 'This board holds no credentials.'
              : 'This board belongs to a different device.'}
          </strong>
          <p>A secret is rotated on the board {name} already runs on. Nothing has been changed.</p>
        </div>
        <p className="small">Wrong board? {disconnect}</p>
      </div>
    );
  }

  return (
    <div className="stack stack-4">
      <p className="board-note">
        {writePending
          ? 'The server and your vault have the new secret. This board still has the old one.'
          : `This board holds ${name}. Ready to rotate.`}
      </p>
      <SubmitButton busy={Boolean(busy)} busyLabel={busy} disabled={!canSubmit}>
        {writePending ? 'Write to board again' : 'Rotate and write'}
      </SubmitButton>
      <p className="small">Wrong board? {disconnect}</p>
    </div>
  );
}

const WRITE_AGAIN =
  'The server and your vault already have the new secret; the board does not, so its uploads ' +
  'are refused until it is written.';

function describeBoundary(through) {
  if (through === '0') return 'now (it had sent none)';
  return describeSequence(through)?.toLowerCase() ?? `sequence ${through}`;
}

function joinNames(names) {
  if (names.length <= 1) return names.join('');
  return `${names.slice(0, -1).join(', ')} and ${names.at(-1)}`;
}

/**
 * What failed, followed by what is now true, which depends on how far it got.
 * Before the rebind nothing has changed anywhere that matters (a pending secret
 * waits in the vault to be reused). After it, the server refuses the old key,
 * so saying "nothing was rotated" would be false in the way that costs the most.
 */
function describe(failure, step) {
  const reason = reasonFor(failure);
  if (step === 'vault' || step === 'rebind') return `${reason} Nothing was rotated.`;
  if (step === 'promote') {
    return (
      `${reason} The server already expects the new secret, and your vault has not retired the ` +
      'old one yet. Try again: it continues from here with the same new secret.'
    );
  }
  return `${reason} ${WRITE_AGAIN}`;
}

function reasonFor(failure) {
  if (failure instanceof VaultRollbackError) {
    return (
      `The server returned vault version ${failure.serverVersion} when this browser has already ` +
      `seen ${failure.cachedVersion}. Open Devices to see the warning in full.`
    );
  }
  if (failure instanceof ApiError) {
    if (failure.status === 403) return 'That password is incorrect.';
    if (failure.status === 0) return 'Could not reach the server.';
    return `${failure.message}.`;
  }
  return `${failure?.message ?? 'Something went wrong'}.`;
}
