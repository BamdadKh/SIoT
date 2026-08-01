import { Link } from '../lib/router.jsx';

/**
 * The signed-in header. The username is set in mono because it is the value the
 * server stores, normalised to lowercase, rather than a display name the person
 * chose.
 *
 * Only `Devices` renders this: `ChangePassword` is a focused, single-purpose
 * screen and uses `Plate` instead, with its own way back in a footer row.
 */
export function TopBar({ username, onSignOut, signingOut }) {
  return (
    <header className="topbar">
      <span className="wordmark">SIoT</span>
      <div className="row" style={{ gap: 'var(--sp-4)' }}>
        <span className="mono">{username}</span>
        <Link to="/password" className="button button-quiet">
          Change password
        </Link>
        <button className="button button-quiet" type="button" onClick={onSignOut} disabled={signingOut}>
          {signingOut ? 'Signing out' : 'Sign out'}
        </button>
      </div>
    </header>
  );
}
