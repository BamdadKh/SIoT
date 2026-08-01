import { AccountMenu } from './AccountMenu.jsx';

/**
 * The signed-in header: the mark on one side, the account on the other.
 *
 * The account actions are not laid out here as loose buttons. Change password
 * and sign out are rare and one of them is destructive to the session, so they
 * sit under the username rather than beside it, where a stray click cannot
 * reach them and where they do not compete with whatever the page is for.
 *
 * Only `Devices` renders this: `ChangePassword` is a focused, single-purpose
 * screen and uses `Plate` instead, with its own way back in a footer row.
 */
export function TopBar({ username, onSignOut, signingOut }) {
  return (
    <header className="topbar">
      <span className="wordmark">SIoT</span>
      <AccountMenu username={username} onSignOut={onSignOut} signingOut={signingOut} />
    </header>
  );
}
