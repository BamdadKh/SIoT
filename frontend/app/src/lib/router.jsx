/**
 * A router, in about forty lines.
 *
 * The app has four screens and no server rendering, no data loaders and no
 * nested layouts, so react-router would be a large dependency doing very little
 * — and every release in range currently carries open advisories that would sit
 * in `npm audit` forever, drowning out one that mattered. Same reasoning as the
 * hand-rolled Redis throttle on the server: the general tool is the wrong shape.
 *
 * Revisit if Phase 7 needs nested routes for per-device dashboards.
 */

import { useSyncExternalStore } from 'react';

const subscribers = new Set();

function announce() {
  for (const notify of subscribers) notify();
}

window.addEventListener('popstate', announce);

/**
 * @param {string} to absolute path, e.g. '/sign-in'
 * @param {{ replace?: boolean }} [options]
 */
export function navigate(to, { replace = false } = {}) {
  if (to === window.location.pathname) return;
  window.history[replace ? 'replaceState' : 'pushState'](null, '', to);
  announce();
}

export function usePath() {
  return useSyncExternalStore(
    (notify) => {
      subscribers.add(notify);
      return () => subscribers.delete(notify);
    },
    () => window.location.pathname,
  );
}

/** An anchor that stays an anchor: real href, middle-click and ctrl-click work. */
export function Link({ to, children, ...rest }) {
  function handleClick(event) {
    if (event.defaultPrevented || event.button !== 0) return;
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    event.preventDefault();
    navigate(to);
  }

  return (
    <a href={to} onClick={handleClick} {...rest}>
      {children}
    </a>
  );
}
