import { useEffect, useId, useRef, useState } from 'react';
import { Link } from '../lib/router.jsx';

/**
 * Pointer grace period. The panel is flush under the trigger, so there is no gap
 * to fall through on the way down, but a diagonal move towards a panel wider
 * than the trigger can clip the corner, and a menu that shuts on a 20px
 * overshoot reads as broken rather than as strict.
 */
const CLOSE_DELAY_MS = 120;

/**
 * The account control in the top bar: the username is the button, and the two
 * account actions live under it.
 *
 * It opens on hover, which is what earns the username its olive, but hover is
 * never the only way in. It is a disclosure button, so a click opens it, Tab
 * walks the items, and Escape closes it and hands focus back to the trigger. A
 * menu only a mouse can reach would put sign out behind a gesture a keyboard
 * cannot make.
 *
 * Deliberately not `role="menu"`. That pattern owes the reader roving tabindex
 * and full arrow-key ownership; this is two controls in a box, and disclosure
 * is the pattern that matches what it actually is. ArrowDown from the trigger
 * still works, because reaching for it costs nothing and some people will.
 */
export function AccountMenu({ username, onSignOut, signingOut }) {
  const [open, setOpen] = useState(false);
  const wrapper = useRef(null);
  const trigger = useRef(null);
  const panel = useRef(null);
  const closeTimer = useRef(0);
  const wantsFocus = useRef(false);
  const panelId = useId();

  useEffect(() => () => clearTimeout(closeTimer.current), []);

  // Anything outside closes it. `pointerdown` rather than `click`, so the menu
  // is already gone by the time whatever is underneath reacts to the press.
  useEffect(() => {
    if (!open) return undefined;
    const handle = (event) => {
      if (!wrapper.current?.contains(event.target)) setOpen(false);
    };
    document.addEventListener('pointerdown', handle);
    return () => document.removeEventListener('pointerdown', handle);
  }, [open]);

  // ArrowDown asked for the first item on a panel that was not mounted yet.
  useEffect(() => {
    if (open && wantsFocus.current) {
      wantsFocus.current = false;
      focusFirstItem();
    }
  }, [open]);

  function focusFirstItem() {
    panel.current?.querySelector('.account-item:not(:disabled)')?.focus();
  }

  function cancelClose() {
    clearTimeout(closeTimer.current);
    closeTimer.current = 0;
  }

  function handlePointerEnter() {
    cancelClose();
    setOpen(true);
  }

  function handlePointerLeave() {
    cancelClose();
    closeTimer.current = setTimeout(() => {
      // A keyboard user with a mouse resting somewhere: if focus is still in
      // here the menu is in use, and the pointer leaving says nothing about it.
      if (!wrapper.current?.contains(document.activeElement)) setOpen(false);
    }, CLOSE_DELAY_MS);
  }

  function handleClick(event) {
    // Enter and Space arrive as a click with no pointer behind them, and those
    // toggle. A real click must not close a menu the hover just opened, or the
    // two halves of the same gesture fight each other.
    setOpen(event.detail === 0 ? !open : true);
  }

  function handleKeyDown(event) {
    if (event.key === 'Escape' && open) {
      cancelClose();
      setOpen(false);
      trigger.current?.focus();
      return;
    }
    if (event.key === 'ArrowDown' && event.target === trigger.current) {
      event.preventDefault();
      cancelClose();
      if (open) focusFirstItem();
      else {
        wantsFocus.current = true;
        setOpen(true);
      }
    }
  }

  return (
    <div
      className="account"
      ref={wrapper}
      onPointerEnter={handlePointerEnter}
      onPointerLeave={handlePointerLeave}
      onKeyDown={handleKeyDown}
      onBlur={(event) => {
        if (!wrapper.current?.contains(event.relatedTarget)) setOpen(false);
      }}
    >
      <button
        type="button"
        className="account-trigger"
        ref={trigger}
        onClick={handleClick}
        aria-expanded={open}
        aria-controls={panelId}
        aria-haspopup="true"
      >
        {/* Still mono: this is the name the server stores, normalised to
            lowercase, not a display name anyone chose. The colour is the
            exception, and it is the point of this control (tokens.css: olive is
            every action the user can take). `.mono`'s muted ink would read as a
            label sitting next to a control that was not there. */}
        <span className="mono">{username}</span>
        <span className="account-caret" aria-hidden="true" />
      </button>

      {open ? (
        <div className="account-menu" id={panelId} ref={panel}>
          <Link to="/password" className="account-item">
            Change password
          </Link>
          <button
            type="button"
            className="account-item"
            onClick={onSignOut}
            disabled={signingOut}
          >
            {signingOut ? 'Signing out' : 'Sign out'}
          </button>
        </div>
      ) : null}
    </div>
  );
}
