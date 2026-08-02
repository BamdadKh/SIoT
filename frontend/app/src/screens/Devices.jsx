import { ORPHAN, UNREGISTERED, shortDeviceId } from '../lib/device-list.js';
import { describeLastSeen, exactLastSeen } from '../lib/last-seen.js';
import { useVaultDevices } from '../lib/use-vault-devices.js';
import { Link } from '../lib/router.jsx';
import { TopBar } from '../components/TopBar.jsx';
import { RollbackWarning } from '../components/RollbackWarning.jsx';
import { OrphanNote, UnregisteredNote } from '../components/DeviceStateNote.jsx';

/**
 * The signed-in, unlocked home: every device, named from the vault and dated
 * from the server (roadmap 4.8).
 *
 * Two fetches that neither side could do alone. The vault has names and secrets
 * the server has never seen; the server has arrival times the vault cannot know.
 * `joinDevices` puts them together by `DEVICE_ID` and surfaces the two ways they
 * can disagree, both of which are real states rather than error handling.
 *
 * The load, the rollback check from roadmap 3.2 and the join all live in
 * `useVaultDevices` now, because `DeviceDetail` needs the identical three and
 * the copy written second is the one that forgets the rollback branch.
 */
export function Devices({ username, onSignOut, signingOut }) {
  const [state, reload] = useVaultDevices(username);

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
          <RollbackWarning serverVersion={state.serverVersion} cached={state.cached} />
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
                vaultDocument={state.document}
                onRegistered={reload}
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
 * The name is the link to its own page, and it is an ordinary link: olive, 600,
 * underlined on hover, like every other link in the app. A device name is the
 * one thing on the row a person came looking for, so it is the thing to press;
 * putting a separate control beside it would be a second appearance for the
 * same navigation.
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
        <h2 className="h3">
          <Link to={`/device/${device.id}`}>{device.name ?? 'Unnamed device'}</Link>
        </h2>
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
        <UnregisteredNote
          device={device}
          vaultDocument={vaultDocument}
          onRegistered={onRegistered}
        />
      ) : null}

      {device.state === ORPHAN ? <OrphanNote /> : null}
    </li>
  );
}
