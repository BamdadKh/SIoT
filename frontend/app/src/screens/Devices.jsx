import { TopBar } from '../components/TopBar.jsx';

/**
 * The signed-in, unlocked home.
 *
 * There is no "Add device" control yet on purpose: pairing is Phase 4 and a
 * button that leads nowhere is worse than none. The empty state says what the
 * next step will be, and the control lands beside the heading when it works.
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
          <p className="prose">Pair a board over USB to add one.</p>
        </section>
      </main>
    </>
  );
}
