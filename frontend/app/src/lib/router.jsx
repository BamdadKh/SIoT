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
 * Everything this app owns lives under `/siot` (the domain root is reserved
 * for a future cross-project overview, not this app). This is the one place
 * that fact is spelled out: every screen still writes and compares plain
 * paths like `/sign-in`, and this strips/prepends the mount point so nothing
 * else has to know it exists. Matches `base: '/siot/'` in vite.config.js.
 */
const BASE = '/siot';

function stripBase(pathname) {
  if (pathname === BASE) return '/';
  if (pathname.startsWith(`${BASE}/`)) return pathname.slice(BASE.length);
  return pathname;
}

function withBase(to) {
  return to === '/' ? BASE : BASE + to;
}

/**
 * @param {string} to absolute path, e.g. '/sign-in'
 * @param {{ replace?: boolean }} [options]
 */
export function navigate(to, { replace = false } = {}) {
  const target = withBase(to);
  if (target === window.location.pathname) return;
  window.history[replace ? 'replaceState' : 'pushState'](null, '', target);
  announce();
}

export function usePath() {
  return useSyncExternalStore(
    (notify) => {
      subscribers.add(notify);
      return () => subscribers.delete(notify);
    },
    () => stripBase(window.location.pathname),
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
    <a href={withBase(to)} onClick={handleClick} {...rest}>
      {children}
    </a>
  );
}
