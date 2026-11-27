import { ORPHAN, UNREGISTERED, shortDeviceId } from '../lib/device-list.js';
import { describeLastSeen, exactLastSeen } from '../lib/last-seen.js';
import { useVaultDevices } from '../lib/use-vault-devices.js';
import { Link } from '../lib/router.jsx';
import { TopBar } from '../components/TopBar.jsx';
import { RollbackWarning } from '../components/RollbackWarning.jsx';
import { OrphanNote, UnregisteredNote } from '../components/DeviceStateNote.jsx';
import { Notifications } from '../components/Notifications.jsx';
import { useNotifications } from '../lib/use-notifications.js';

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
  // Roadmap 10.4: fetched on open and polled while open, from the same vault
  // load the list uses, so the names and read marks cannot disagree with it.
  const notifications = useNotifications(state);
  const unreadBy = unreadByDevice(notifications.merged);

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

        {/* One stack, so a warning appearing above the list moves it down by the
            same step everywhere in the app rather than by a margin written on
            whichever panel happened to need one. */}
        <div className="stack stack-4">
          {state.status === 'rollback' ? (
            <RollbackWarning serverVersion={state.serverVersion} cached={state.cached} />
          ) : null}

          {state.status === 'error' ? (
            <p className="alarm" role="alert">
              Could not check the vault: {state.message}
            </p>
          ) : null}

          {state.status === 'ok' && state.dropped > 0 ? (
            <p className="alarm" role="alert">
              {state.dropped} {state.dropped === 1 ? 'entry' : 'entries'} in your vault could not be
              read and {state.dropped === 1 ? 'was' : 'were'} skipped. The vault itself is intact
              and authentic, so this is a fault in the client that wrote{' '}
              {state.dropped === 1 ? 'it' : 'them'}, not tampering.
            </p>
          ) : null}

          {state.status === 'ok' && state.schemaFieldsDropped > 0 ? (
            <p className="alarm" role="alert">
              {state.schemaFieldsDropped} declared{' '}
              {state.schemaFieldsDropped === 1 ? 'field' : 'fields'} in your vault could not be read
              and {state.schemaFieldsDropped === 1 ? 'was' : 'were'} skipped. The devices they
              belong to are unaffected; their readings show under the names the device sends until
              the fields are declared again.
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
                  unread={unreadBy.get(device.id) ?? 0}
                  vaultDocument={state.document}
                  onRegistered={reload}
                />
              ))}
            </ul>
          ) : null}

          {state.status === 'ok' && state.devices.length > 0 ? (
            <Notifications username={username} notifications={notifications} onMarked={reload} />
          ) : null}
        </div>
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
function DeviceRow({ device, unread, vaultDocument, onRegistered }) {
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
        {/* Only when there is something to say: a row reading "0 unread" on every
            quiet device would be the list claiming each one has no alerts. */}
        {unread > 0 ? (
          <span className="small device-unread">
            {unread === 1 ? '1 unread notification' : `${unread} unread notifications`}
          </span>
        ) : null}
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

/** @param {Array<{ deviceId: string, unread: boolean }>} merged */
function unreadByDevice(merged) {
  const counts = new Map();
  for (const item of merged) {
    if (item.unread) counts.set(item.deviceId, (counts.get(item.deviceId) ?? 0) + 1);
  }
  return counts;
}
