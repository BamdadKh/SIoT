import { useCallback, useEffect, useState } from 'react';
import { ApiError } from '../lib/api.js';
import { findReaders, grantReadAccess } from '../lib/grant-access.js';
import { PAIRED } from '../lib/device-list.js';
import { Choice } from './Choice.jsx';
import { Link } from '../lib/router.jsx';

/**
 * Letting another device read this one (design Section 9, roadmap 8.1).
 *
 * A grant hands device A this device's `device_data_key`, wrapped under A's own,
 * so A can fetch and open this device's records with no browser in the loop.
 * It is the one action on this page whose cost outlives every other control
 * here, and the section is shaped for that:
 *
 *   - **The costs come before the decision, and name both devices.** Design 9.2
 *     and 9.3 are explicit that a grant covers everything this device has ever
 *     sent, not a live feed, and that "revoke" means re-provisioning this board
 *     with a new `DEVICE_SECRET`, which protects only what comes after. A person
 *     who believes otherwise is wrong in a way that matters, so it is said at
 *     the moment of granting rather than in a help page.
 *   - **Not armed by default, armed by a deliberate second click, disarmed when
 *     what was confirmed changes.** The same shape as Delete below and the
 *     occupied-board override: picking a different recipient is a different
 *     grant and so a fresh decision.
 *   - **What it does not grant is said too.** A receives the data key and never
 *     the signing key (design 5.1), so it can read as this device and cannot
 *     write as it. That is the property the key split exists for, and the
 *     reason a grant is survivable at all.
 *
 * Only paired devices on both sides: the server checks that the account owns
 * both rows, and the wrapping needs both `DEVICE_SECRET`s from the vault.
 *
 * @param {{ device: object, entry: { id: string, secret: string },
 *           devices: Array<object>, findEntry: (id: string) => object|null }} props
 *        `devices` is the joined list `useVaultDevices` produced.
 */
export function GrantAccess({ device, entry, devices, findEntry }) {
  const candidates = devices.filter(
    (other) => other.id !== device.id && other.state === PAIRED && findEntry(other.id),
  );
  const nameOf = (id) => devices.find((other) => other.id === id)?.name ?? null;
  const thisName = device.name ?? 'this device';

  const [recipientId, setRecipientId] = useState('');
  const [armed, setArmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [granted, setGranted] = useState(null);
  const [readers, setReaders] = useState({ status: 'loading' });

  const candidateIds = candidates.map((other) => other.id).join(',');
  const loadReaders = useCallback(async () => {
    try {
      const found = await findReaders(device.id, candidateIds ? candidateIds.split(',') : []);
      setReaders({ status: 'ok', readers: found });
    } catch (failure) {
      setReaders({ status: 'error', message: failure?.message ?? 'unknown error' });
    }
  }, [device.id, candidateIds]);

  useEffect(() => {
    loadReaders();
  }, [loadReaders]);

  // A different recipient is a different grant, so a confirmation given for one
  // must not carry over to the other.
  useEffect(() => {
    setArmed(false);
  }, [recipientId]);

  const recipient = candidates.find((other) => other.id === recipientId) ?? null;
  const recipientName = recipient ? (recipient.name ?? 'the unnamed device') : null;

  async function handleGrant() {
    if (!recipient || busy) return;
    const recipientEntry = findEntry(recipient.id);
    if (!recipientEntry) return;

    setBusy(true);
    setError(null);
    try {
      await grantReadAccess({ source: entry, recipient: recipientEntry });
      setGranted({ id: recipient.id, name: recipientName });
      setRecipientId('');
      setArmed(false);
      await loadReaders();
    } catch (failure) {
      setError(describeGrant(failure));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="device-section">
      <h2 className="h3">Grants</h2>
      <p className="prose section-lede">
        Let another of your devices read this one directly, with no browser in between. It is sent
        this device&rsquo;s data key, sealed so that only it can open it; the server stores the
        sealed key and cannot.
      </p>

      <div className="stack stack-4">
        <Readers readers={readers} nameOf={nameOf} />

        {/* Revoking is rotation (design 9.3), and it has its own screen because
            it needs the board. Offered here whatever the readers, since rotating
            is also the remedy for a secret that may have been copied. */}
        {readers.status === 'ok' ? (
          <p className="small">
            {readers.readers.length > 0 ? (
              <>
                A grant cannot be withdrawn, only outrun: to stop{' '}
                {readers.readers.length === 1 ? 'that device' : 'them'} reading what this one sends
                next,{' '}
              </>
            ) : (
              <>If this device&rsquo;s secret may have been copied, </>
            )}
            <Link to={`/device/${device.id}/rotate`} className="button button-link">
              rotate its secret
            </Link>
          </p>
        ) : null}

        {granted ? (
          <p className="success" role="status">
            {granted.name ?? 'The device'} can now read {thisName}, including everything already
            uploaded.
          </p>
        ) : null}

        {error ? (
          <p className="alarm" role="alert">
            {error}
          </p>
        ) : null}

        {candidates.length === 0 ? (
          <p className="board-note">
            <strong>No other device to grant to.</strong> A grant needs a second device that is in
            your vault and registered with the server.
          </p>
        ) : (
          <>
            <Choice
              label="Device that will read this one"
              value={recipientId}
              onChange={setRecipientId}
              disabled={busy}
              options={[
                ['', 'Choose a device'],
                ...candidates.map((other) => [other.id, other.name ?? `Unnamed (${other.id})`]),
              ]}
            />

            {armed && recipient ? (
              <div className="alarm" role="alert">
                <strong>
                  {recipientName} will be able to read everything {thisName} has sent, and
                  everything it sends from now on.
                </strong>
                <p>
                  Not just new readings: the grant opens this device&rsquo;s whole history on the
                  server, back to its first record.
                </p>
                <p>
                  There is no revoking it. The only way to stop {recipientName} reading what comes
                  next is to provision this board again with a new{' '}
                  <span className="mono">DEVICE_SECRET</span>, and everything before that stays
                  readable to it permanently. If {recipientName} is ever compromised, so is all of
                  this.
                </p>
                <p>
                  It is read access only. {recipientName} never receives this device&rsquo;s signing
                  key, so it cannot upload anything that passes as {thisName}.
                </p>
              </div>
            ) : null}

            {armed && recipient ? (
              <div>
                <button
                  className="button button-inline"
                  type="button"
                  onClick={handleGrant}
                  disabled={busy}
                >
                  {busy ? 'Sealing and sending' : `Grant ${recipientName} read access`}
                </button>
              </div>
            ) : null}

            {/* The way out sits where the way in was, as Delete does it. */}
            {recipient ? (
              <p className="small">
                {armed ? (
                  <>
                    Changed your mind?{' '}
                    <button
                      className="button button-link"
                      type="button"
                      onClick={() => setArmed(false)}
                      disabled={busy}
                    >
                      Keep it private
                    </button>
                  </>
                ) : (
                  <>
                    Read what this grants before it is sent.{' '}
                    <button
                      className="button button-link"
                      type="button"
                      onClick={() => setArmed(true)}
                      disabled={busy}
                    >
                      Review the grant
                    </button>
                  </>
                )}
              </p>
            ) : null}
          </>
        )}
      </div>
    </section>
  );
}

/**
 * Which devices already hold this one's key. Asked of the server device by
 * device, since a grant is filed under its recipient: the same public route a
 * device's own firmware polls (design 9.3). Nothing here is secret from the
 * server, which already knows who holds grants on whom (design 13.1).
 */
function Readers({ readers, nameOf }) {
  if (readers.status === 'loading') return null;
  if (readers.status === 'error') {
    return <p className="small ink-faint">Could not check which devices can read this one.</p>;
  }
  if (readers.readers.length === 0) {
    return <p className="small">No device can read this one yet.</p>;
  }
  return (
    <p className="small">
      Can already read it:{' '}
      {readers.readers.map(({ id, since }, index) => (
        <span key={id}>
          {index > 0 ? ', ' : null}
          {nameOf(id) ?? <span className="mono">{id}</span>}{' '}
          <span className="ink-faint">(since {formatDate(since)})</span>
        </span>
      ))}
      .
    </p>
  );
}

function formatDate(iso) {
  const when = new Date(iso);
  return Number.isFinite(when.getTime()) ? when.toLocaleDateString() : 'an unreadable date';
}

function describeGrant(failure) {
  if (failure instanceof ApiError) {
    if (failure.status === 0) return 'Could not reach the server. Nothing was granted.';
    if (failure.status === 403) {
      return 'The server does not list both devices under this account. Nothing was granted.';
    }
    return `${failure.message}. Nothing was granted.`;
  }
  return failure?.message ?? 'Could not create the grant.';
}
