import { Link } from '../lib/router.jsx';

/**
 * The way out of a plate: a rule, and below it whatever this screen offers next.
 *
 * A rule with 18px under it and `--sp-6` over it, written once. Every plate drew
 * its own `<hr className="rule" style={{ margin: ... }}>` before this, with the
 * same numbers copied by hand, which is a rule that stays identical only for as
 * long as nobody edits one of them.
 */
export function PlateFoot({ children }) {
  return <div className="plate-foot">{children}</div>;
}

/**
 * The footer the three authenticated plates share: who is signed in on the left,
 * the way onwards on the right.
 *
 * `Unlock` passes `home={false}`, and that is not a styling preference: the vault
 * is sealed on that screen, so Devices has nothing to show and linking to it
 * would send someone to a page that bounces them straight back here.
 *
 * The controls are link-shaped rather than buttons, per the note in CLAUDE.md:
 * one link appearance everywhere, whether the element is a `<Link>` or a
 * `<button className="button button-link">`.
 */
export function SessionFooter({ username, onSignOut, signingOut, home = true }) {
  return (
    <PlateFoot>
      <div className="row spread">
        <span className="small">
          Signed in as <span className="mono">{username}</span>
        </span>
        <div className="row row-links">
          {home ? (
            <Link to="/" className="button button-link">
              Devices
            </Link>
          ) : null}
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
    </PlateFoot>
  );
}
