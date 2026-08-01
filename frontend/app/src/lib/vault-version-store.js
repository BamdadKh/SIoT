/**
 * The high-water mark for `vault_version` (roadmap 3.2, design Section 8).
 *
 * Every check inside the vault blob (the AAD binding, the plaintext envelope
 * copy) is satisfied by a blob that is old but *honestly labelled*: version 3,
 * sealed and served as version 3. Catching that needs a number that survives
 * outside the blob, and outside the page, which is what this is for. A
 * module-scoped variable would reset on every reload, exactly when a rollback
 * is most worth catching.
 *
 * IndexedDB per design Section 8's own wording, not localStorage: it is not
 * about capacity (this is one integer) but about being the store `structured
 * clone` handles natively, so a version bump to something other than a plain
 * number is not a silent `String(value)` coercion away from being wrong.
 *
 * Keyed by username, not one global number. This origin outlives any one
 * account. Signing out and into a second account on the same browser is
 * ordinary use, not a rollback, and the two vaults' version counters have
 * nothing to do with each other. A single shared key would report the second
 * account's honest version 1 as older than the first account's version 4 and
 * raise a false alarm on every account switch.
 */

const DB_NAME = 'siot-vault';
const DB_VERSION = 1;
const STORE = 'meta';

function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      req.result.createObjectStore(STORE);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

/**
 * @param {string} username
 * @returns {Promise<number>} 0 if nothing has been cached yet for this account.
 */
export async function getHighWaterMark(username) {
  const db = await openDb();
  try {
    return await new Promise((resolve, reject) => {
      const req = db.transaction(STORE, 'readonly').objectStore(STORE).get(username);
      req.onsuccess = () => resolve(req.result ?? 0);
      req.onerror = () => reject(req.error);
    });
  } finally {
    db.close();
  }
}

/**
 * @param {string} username
 * @param {number} version
 */
export async function setHighWaterMark(username, version) {
  const db = await openDb();
  try {
    await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, 'readwrite');
      tx.objectStore(STORE).put(version, username);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  } finally {
    db.close();
  }
}
