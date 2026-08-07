import { useCallback, useEffect, useRef, useState } from 'react';
import { isWebSerialSupported, requestPort, ProvisioningSession } from '../lib/web-serial.js';
import { classifyBoard, BLANK, SAME } from '../lib/provisioning-protocol.js';
import { shortDeviceId } from '../lib/device-list.js';

/**
 * Clearing a retired board's credentials (roadmap 4.9, `SIOT ERASE`).
 *
 * **Only offered after a delete, and that is the whole of its scope.** Deleting a
 * device does not touch NVS: the firmware still holds `DEVICE_SECRET` and goes on
 * uploading into 404s until someone provisions it for another device or erases
 * it. The completed-delete state has always said so; this is what lets someone
 * act on the sentence instead of reading it.
 *
 * It is not a fourth control on the device page. A board carrying a device that
 * still exists is reclaimed by provisioning over it, which `AddDevice` already
 * does properly, with the vault available to name what is being replaced. This
 * is for the board going in a drawer, which is a case that only arises once the
 * device is gone.
 *
 * The three cases are `classifyBoard`'s, the same function the write path uses,
 * against the id of the device that was just deleted:
 *
 *   SAME      this is the board. Offer the erase.
 *   BLANK     nothing on it. Say so; there is nothing to do.
 *   OCCUPIED  a different device's board. Refuse, and offer no override: the
 *             way to erase that one is from its own page, after deleting it,
 *             where the confirmation can name what is being destroyed.
 *
 * The board runs the same compare-and-swap it runs for a write, so the check
 * above is what decides which button appears and never what the board accepts.
 * A cable swapped between the read and the erase is refused by the board itself.
 */
export function EraseBoard({ deviceId, deviceName }) {
  const [supported] = useState(isWebSerialSupported);
  const [busy, setBusy] = useState(null);
  const [board, setBoard] = useState(null);
  const [error, setError] = useState(null);
  const [erased, setErased] = useState(false);

  const session = useRef(null);

  const release = useCallback(async () => {
    const open = session.current;
    session.current = null;
    await open?.close();
  }, []);

  // A port left open stays open for the life of the tab, and the next attempt
  // then fails on a port already in use with nothing on screen saying why.
  useEffect(() => () => void release(), [release]);

  if (!supported) return null;

  async function handleConnect() {
    setError(null);
    setErased(false);

    let port;
    try {
      port = await requestPort();
    } catch {
      // The chooser was dismissed. A deliberate cancel is not a failure.
      return;
    }

    setBusy('Connecting to the board');
    try {
      const opened = new ProvisioningSession(port);
      await opened.open();
      session.current = opened;
      const storedId = await opened.readId();
      setBoard(classifyBoard(storedId, deviceId));
    } catch (failure) {
      await release();
      setError(failure.message);
    } finally {
      setBusy(null);
    }
  }

  async function handleErase() {
    setError(null);
    setBusy('Erasing the board');
    try {
      await session.current.erase(board.storedId);
      setErased(true);
      setBoard(null);
    } catch (failure) {
      setError(failure.message);
    } finally {
      setBusy(null);
      await release();
    }
  }

  async function handleDisconnect() {
    await release();
    setBoard(null);
    setError(null);
  }

  if (erased) {
    return (
      <p className="success" role="status">
        The board has been erased. It is holding no credentials and will not report again until
        it is provisioned for another device.
      </p>
    );
  }

  return (
    <div className="stack stack-4">
      {error ? (
        <p className="alarm" role="alert">
          {error}
        </p>
      ) : null}

      {board?.state === SAME ? (
        <>
          <p className="board-note">
            This is {deviceName ? <strong>{deviceName}</strong> : 'that device'}&rsquo;s board.
            Erasing removes both credentials from its storage; the sketch on it is untouched and
            can be provisioned for another device at any time.
          </p>
          <div>
            <button
              className="button button-inline"
              type="button"
              onClick={handleErase}
              disabled={Boolean(busy)}
            >
              {busy ?? 'Erase the board'}
            </button>
          </div>
          <p className="small">
            Wrong board?{' '}
            <button
              className="button button-link"
              type="button"
              onClick={handleDisconnect}
              disabled={Boolean(busy)}
            >
              Disconnect
            </button>
          </p>
        </>
      ) : null}

      {board?.state === BLANK ? (
        <>
          <p className="board-note">
            This board is holding no credentials, so there is nothing to erase.
          </p>
          <p className="small">
            <button
              className="button button-link"
              type="button"
              onClick={handleDisconnect}
              disabled={Boolean(busy)}
            >
              Disconnect
            </button>
          </p>
        </>
      ) : null}

      {board && board.state !== SAME && board.state !== BLANK ? (
        <>
          <div className="alarm" role="alert">
            <strong>This board belongs to a different device.</strong>
            <p>
              It is holding{' '}
              <span className="mono" title={board.storedId}>
                {shortDeviceId(board.storedId)}
              </span>
              , not the device that was just deleted. Erasing it would leave that device with no
              hardware carrying its identity, so nothing was changed. Erase it from its own page
              once you have deleted it there.
            </p>
          </div>
          <p className="small">
            <button
              className="button button-link"
              type="button"
              onClick={handleDisconnect}
              disabled={Boolean(busy)}
            >
              Disconnect
            </button>
          </p>
        </>
      ) : null}

      {!board ? (
        <p className="small">
          Still have the board?{' '}
          <button
            className="button button-link"
            type="button"
            onClick={handleConnect}
            disabled={Boolean(busy)}
          >
            {busy ?? 'Erase its credentials'}
          </button>
        </p>
      ) : null}
    </div>
  );
}
