/**
 * How a device's liveness is worded (design Section 5.6, roadmap 4.8).
 *
 * Two rules, both load-bearing enough to live in one place rather than being
 * retyped per screen.
 *
 * **Never assert "offline".** The client knows it has not received a record. It
 * does not know why. A withholding server and a flat battery are indistinguishable
 * from here, and every freshness signal in this system fails in that direction:
 * the server cannot forge a *newer* record at a higher `seq` (it has no signing
 * key), so it can never make a dead device look alive, but it can always withhold
 * and make a live one look dead. So this says when something was last heard from
 * and stops there.
 *
 * **No fixed threshold.** Devices report on wildly different schedules. A sensor
 * that wakes hourly is healthy at 59 minutes and a doorbell is not; picking any
 * one number would call one of them dead. A timestamp lets the person who chose
 * the reporting interval be the one who decides.
 */

const relative = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });

/** Descending, so the first unit the gap clears is the coarsest that fits. */
const UNITS = [
  ['year', 365 * 24 * 60 * 60 * 1000],
  ['month', 30 * 24 * 60 * 60 * 1000],
  ['day', 24 * 60 * 60 * 1000],
  ['hour', 60 * 60 * 1000],
  ['minute', 60 * 1000],
];

/**
 * @param {string|null} lastSeenAt ISO timestamp, or null if no record has arrived.
 * @param {Date} [now]
 * @returns {string}
 */
export function describeLastSeen(lastSeenAt, now = new Date()) {
  if (!lastSeenAt) return 'No records yet';

  const then = Date.parse(lastSeenAt);
  if (!Number.isFinite(then)) return 'Last record at an unreadable time';

  const elapsed = now.getTime() - then;

  // A server clock running ahead puts the newest record in the future. Say so
  // plainly rather than rendering "in 3 minutes", which reads like a schedule.
  if (elapsed < 0) return 'Last record is timestamped in the future';
  if (elapsed < 60 * 1000) return 'Last record just now';

  for (const [unit, ms] of UNITS) {
    if (elapsed >= ms) {
      return `Last record ${relative.format(-Math.floor(elapsed / ms), unit)}`;
    }
  }
  return 'Last record just now';
}

/**
 * The exact timestamp, for the `title` on the relative phrasing above. Relative
 * time is easier to read and worse to reason about; both belong on the page, one
 * of them on demand.
 *
 * @param {string|null} lastSeenAt
 * @returns {string|undefined}
 */
export function exactLastSeen(lastSeenAt) {
  if (!lastSeenAt) return undefined;
  const then = new Date(lastSeenAt);
  return Number.isFinite(then.getTime()) ? then.toLocaleString() : undefined;
}
