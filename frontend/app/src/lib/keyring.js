/**
 * The two keys the browser holds, and the only place they live.
 *
 * Module scope, in memory, for the lifetime of one page. Never localStorage,
 * never sessionStorage, never IndexedDB, never a cookie. A reload is *supposed*
 * to lose these — that is why there is an unlock screen, and it is the property
 * that makes the server's copy of the vault useless to the server.
 *
 * Zeroing on clear is best effort. JavaScript gives no way to guarantee a byte
 * is gone once a copying collector has moved it, so this shortens the window
 * rather than closing it. Worth the two lines; not worth mistaking for real
 * memory hygiene.
 */

let kek = null;
let vaultKey = null;

const subscribers = new Set();

function announce() {
  for (const notify of subscribers) notify();
}

/** @param {() => void} notify @returns {() => void} unsubscribe */
export function subscribe(notify) {
  subscribers.add(notify);
  return () => subscribers.delete(notify);
}

/** True once the vault is open, i.e. this tab derived and unwrapped its keys. */
export function isUnlocked() {
  return vaultKey !== null;
}

export function getVaultKey() {
  return vaultKey;
}

/**
 * @param {Uint8Array} nextKek 32 bytes
 * @param {Uint8Array} nextVaultKey 32 bytes
 */
export function unlock(nextKek, nextVaultKey) {
  kek?.fill(0);
  vaultKey?.fill(0);
  kek = nextKek;
  vaultKey = nextVaultKey;
  announce();
}

export function clear() {
  kek?.fill(0);
  vaultKey?.fill(0);
  kek = null;
  vaultKey = null;
  announce();
}
