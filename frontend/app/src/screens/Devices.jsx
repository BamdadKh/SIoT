import { TopBar } from '../components/TopBar.jsx';

/**
 * The signed-in, unlocked home.
 *
 * There is no "Add device" control yet on purpose: pairing is Phase 4 and a
 * button that leads nowhere is worse than none. The empty state says what the
 * next step will be, and the control lands beside the heading when it works.
 *
 * The copy names the one supported flow (design 5.3): plug an ESP32 in and the
 * browser writes its credentials over Web Serial. It deliberately does not
 * mention revealing credentials for other hardware — that is an escape hatch
 * reached from a device that already exists (5.3.1), and an empty state is
 * exactly where it would get mistaken for a second way to start.
 *
 * Once 4.8 lands this stops being the only thing on the screen: devices appear
 * here with the name their owner gave them (which lives in the vault, never on
 * the server) and when each was last heard from.
 */
export function Devices({ username, onSignOut, signingOut }) {
  return (
    <>
      <TopBar username={username} onSignOut={onSignOut} signingOut={signingOut} />
      <main className="page">
        <div className="page-head">
          <h1 className="h2">Devices</h1>
        </div>

        <section className="slot">
          <span className="tick tick-tl" />
          <span className="tick tick-tr" />
          <span className="tick tick-bl" />
          <span className="tick tick-br" />
          <h2 className="h3">No devices yet</h2>
          <p className="prose">Plug an ESP32 in over USB to set one up.</p>
        </section>
      </main>
    </>
  );
}
