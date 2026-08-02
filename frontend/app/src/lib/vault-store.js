/**
 * Reading and writing the vault, with the rollback check attached.
 *
 * This exists because more than one screen now touches the vault, and the
 * monotonicity check from design Section 8 is the kind of thing that gets
 * skipped by whichever caller was written second. Making a rollback an exception
 * rather than a return value means a caller cannot forget it: there is no branch
 * to leave unwritten, only a `catch` to leave unhandled, which fails loudly on
 * the screen rather than quietly in the data.
 *
 * The high-water mark is raised only *after* the blob has actually opened at the
 * version the server claimed. A version that arrived with a blob that will not
 * decrypt is not evidence of anything, and recording it would poison the cache
 * against the real vault.
 */

import {
  decryptVault,
  encryptVault,
  emptyVaultDocument,
  fromBase64Url,
  normaliseVaultDocument,
  toBase64Url,
} from '@siot/crypto';
import { fetchVault, saveVault } from './api.js';
import { getVaultKey } from './keyring.js';
import { getHighWaterMark, setHighWaterMark } from './vault-version-store.js';

/**
 * The server served a vault older than one this browser has already seen.
 *
 * The one class of tampering neither the AAD nor the plaintext envelope in
 * `vault.js` can catch on their own: both are satisfied by an old blob that is
 * honestly labelled with its own old version.
 */
export class VaultRollbackError extends Error {
  constructor(serverVersion, cachedVersion) {
    super(`server returned vault version ${serverVersion}; this browser has seen ${cachedVersion}`);
    this.name = 'VaultRollbackError';
    this.serverVersion = serverVersion;
    this.cachedVersion = cachedVersion;
  }
}

/**
 * Fetches, checks and opens the vault.
 *
 * @param {string} username keys the high-water mark, so switching accounts on
 *        one browser is not mistaken for a rollback of the account it replaced.
 * @returns {Promise<{ version: number, document: object, dropped: number }>}
 */
export async function loadVault(username) {
  const vaultKey = getVaultKey();
  if (!vaultKey) throw new Error('the vault is locked');

  const [{ vault_version: version, ciphertext }, cached] = await Promise.all([
    fetchVault(),
    getHighWaterMark(username),
  ]);

  if (version < cached) throw new VaultRollbackError(version, cached);

  // A never-written vault is version 0 with no blob, not a 404, so there is no
  // shape here that skips the check above.
  const contents =
    ciphertext === null ? null : await decryptVault(fromBase64Url(ciphertext), vaultKey, version);

  const { document, dropped } = normaliseVaultDocument(contents);
  await setHighWaterMark(username, version);
  return { version, document, dropped };
}

/**
 * Seals and uploads a document as the next version.
 *
 * A 409 from here means another tab won the race, and the caller's document is
 * built on a vault that no longer exists. There is nothing to retry with: the
 * only correct response is to `loadVault` again and re-apply the change, which
 * is why every edit in `vault-document.js` returns a new document rather than
 * mutating the one it was given.
 *
 * @param {string} username
 * @param {number} currentVersion the version `loadVault` returned.
 * @param {object} document
 * @returns {Promise<number>} the version now stored.
 */
export async function storeVault(username, currentVersion, document) {
  const vaultKey = getVaultKey();
  if (!vaultKey) throw new Error('the vault is locked');

  const nextVersion = currentVersion + 1;
  const blob = await encryptVault(document, vaultKey, nextVersion);

  const { vault_version: stored } = await saveVault({
    vault_version: nextVersion,
    ciphertext: toBase64Url(blob),
  });

  await setHighWaterMark(username, stored);
  return stored;
}

export { emptyVaultDocument };
