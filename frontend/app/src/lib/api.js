/**
 * The server API, as the client sees it.
 *
 * Nothing here sends a password, and nothing here receives anything the server
 * could read that it did not already know. `wrapped_vault_key` is the one
 * response that is genuinely opaque to its sender.
 */

/** A non-2xx response, carrying enough to render a useful message. */
export class ApiError extends Error {
  constructor(status, message, retryAfterSeconds = null) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

/** Matches the /siot prefix backend/src/app.ts mounts every route under. */
const API_BASE = '/siot';

async function request(method, path, body) {
  let response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      method,
      headers: body === undefined ? undefined : { 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
      // The session cookie is HttpOnly; the browser attaches it, we never see it.
      credentials: 'same-origin',
    });
  } catch {
    throw new ApiError(0, 'Could not reach the server.');
  }

  // Every route returns JSON; an empty body only happens on an error we still
  // want to surface with its status rather than a parse failure.
  let payload = null;
  try {
    payload = await response.json();
  } catch {
    payload = null;
  }

  if (!response.ok) {
    const retryAfter = Number(response.headers.get('retry-after'));
    throw new ApiError(
      response.status,
      payload?.message ?? `Request failed (${response.status}).`,
      Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter : null,
    );
  }

  return payload;
}

/**
 * The Argon2id salt for an account. Returns a plausible decoy for names that do
 * not exist, so a 200 here proves nothing about whether the account is real.
 *
 * @param {string} username
 * @returns {Promise<{ salt: string }>} base64url
 */
export function fetchSalt(username) {
  return request('GET', `/salt?username=${encodeURIComponent(username)}`);
}

/**
 * @param {{ username: string, salt: string, login_key: string, wrapped_vault_key: string }} body
 *        every value but `username` base64url
 */
export function signUp(body) {
  return request('POST', '/signup', body);
}

/**
 * @param {string} username
 * @param {string} loginKey base64url of HKDF(master_key, "siot/auth/v1")
 */
export function logIn(username, loginKey) {
  return request('POST', '/login', { username, login_key: loginKey });
}

/** Who the current cookie belongs to, or a 401. */
export function fetchSession() {
  return request('GET', '/session');
}

export function logOut() {
  return request('POST', '/logout');
}

export function logOutEverywhere() {
  return request('POST', '/logout-everywhere');
}

/** The 60-byte blob only this browser's `kek` can open. */
export function fetchWrappedVaultKey() {
  return request('GET', '/vault-key');
}

/**
 * The sealed vault document.
 *
 * @returns {Promise<{ vault_version: number, ciphertext: string|null }>}
 *          `ciphertext` base64url, null for an account that has never written one.
 */
export function fetchVault() {
  return request('GET', '/vault');
}

/**
 * Replaces the whole vault document.
 *
 * `vault_version` must be exactly the current one plus one. The server settles
 * that with a compare-and-swap in a single statement, so two tabs saving at once
 * cannot both pass: the loser gets a 409 naming the version it actually found,
 * and has to re-read and re-apply rather than retry the same body.
 *
 * @param {{ vault_version: number, ciphertext: string }} body `ciphertext` base64url
 * @returns {Promise<{ vault_version: number }>}
 */
export function saveVault(body) {
  return request('PUT', '/vault', body);
}

/**
 * Registers the public half of a device's identity (design 5.3 step 2).
 *
 * Both values are things design 5.2 lists as plaintext-by-design. `DEVICE_SECRET`
 * is not here and must never be: it goes to the vault and to the board, and a
 * server that held it could decrypt every record it stores.
 *
 * @param {{ device_id: string, sign_pub: string }} body both base64url
 */
export function registerDevice(body) {
  return request('POST', '/devices/register', body);
}

/**
 * The metadata the server legitimately holds per device. No names: it has none.
 *
 * @returns {Promise<{ devices: Array<{ device_id: string, last_seq: string, last_seen_at: string|null }> }>}
 */
export function fetchDevices() {
  return request('GET', '/devices');
}

/**
 * One page of a device's records, as the server stored them (roadmap 6.2).
 *
 * Opaque here and opaque to the server: `ciphertext` opens only under the
 * `device_data_key` derived from the `DEVICE_SECRET` in the vault, which is why
 * this returns blobs and `use-device-records.js` is what turns them into
 * readings.
 *
 * `sig` is deliberately not in the response and its absence is not a gap: the
 * signature authenticates a record to the *server*, which cannot decrypt it,
 * while a reader holding `device_data_key` already has the record's own GCM tag
 * over an AAD binding the `DEVICE_ID` and the `seq`, which is strictly stronger.
 *
 * @param {string} deviceId base64url
 * @param {{ beforeSeq?: string, afterSeq?: string, order?: 'asc'|'desc', limit?: number }} [page]
 * @returns {Promise<{ records: Array<{ seq: string, nonce: string, ciphertext: string,
 *                                      created_at: string }> }>}
 */
export function fetchRecords(deviceId, { beforeSeq, afterSeq, order, limit } = {}) {
  const query = new URLSearchParams();
  if (beforeSeq !== undefined) query.set('before_seq', beforeSeq);
  if (afterSeq !== undefined) query.set('after_seq', afterSeq);
  if (order !== undefined) query.set('order', order);
  if (limit !== undefined) query.set('limit', String(limit));

  const suffix = query.size > 0 ? `?${query}` : '';
  return request('GET', `/devices/${encodeURIComponent(deviceId)}/records${suffix}`);
}

/**
 * Removes the server's half of a device: the row, and by cascade every record
 * it uploaded and every grant naming it on either side.
 *
 * This is only half of a delete. The `DEVICE_SECRET` and the name live in the
 * vault and go by a separate `PUT /vault`, and nothing can make the two atomic;
 * roadmap 4.9 chooses the order by which half-finished state is survivable.
 *
 * **A 404 counts as success.** The endpoint answers 404 for "not yours" and
 * "does not exist" alike, and the goal state here is *absence*: a delete that
 * already landed is already in it. That is what makes retrying a two-step delete
 * that failed partway safe, rather than a second attempt reporting a failure
 * that has in fact been achieved.
 *
 * @param {string} deviceId base64url
 */
export async function deleteDevice(deviceId) {
  try {
    await request('DELETE', `/devices/${encodeURIComponent(deviceId)}`);
  } catch (failure) {
    if (failure instanceof ApiError && failure.status === 404) return;
    throw failure;
  }
}

/**
 * Rotates the account password: a fresh salt, a new `login_key`, and the
 * existing `vault_key` re-wrapped under the new `kek`. Vault contents are
 * untouched. The server re-verifies `current_login_key` against the stored
 * hash before accepting any of it; a tab being unlocked is not something the
 * server ever saw happen.
 *
 * @param {{ current_login_key: string, salt: string, login_key: string, wrapped_vault_key: string }} body
 *        every value base64url
 */
export function changePassword(body) {
  return request('POST', '/change-password', body);
}

/**
 * Stores a grant: `device_B_data_key` sealed under `device_A_data_key`, opaque to
 * the server. The caller must own both devices; otherwise the server answers 403
 * (surfaced as an `ApiError` with `status` 403), and 400 for a malformed field.
 * Grants are additive, so repeating a call adds a row rather than replacing one.
 *
 * @param {{ deviceAId: string, deviceBId: string, ciphertext: string }} grant
 *        every value base64url; `ciphertext` is the 60-byte `sealGrant` output.
 */
export function createGrant({ deviceAId, deviceBId, ciphertext }) {
  return request('POST', '/grants', {
    device_a_id: deviceAId,
    device_b_id: deviceBId,
    ciphertext,
  });
}

/**
 * Every grant naming a device as the recipient (design 9.3). The route is public
 * because the recipient's own firmware polls it with no session; the browser
 * uses it to show which devices already hold a given device's key.
 *
 * @param {string} deviceId base64url, the recipient (device A).
 * @returns {Promise<{ grants: Array<{ device_b_id: string, ciphertext: string,
 *                                     created_at: string }> }>}
 */
export function fetchDeviceGrants(deviceId) {
  return request('GET', `/devices/${encodeURIComponent(deviceId)}/grants`);
}

/**
 * Rebinds a device to the `sign_pub` of a rotated `DEVICE_SECRET` (design 9.3).
 * The server re-verifies `current_login_key` (403 if wrong, 404 for a device that
 * is not the caller's) and answers with the boundary: every record accepted under
 * the old key has `seq <= through_seq`. Safe to retry after a lost response.
 *
 * @param {string} deviceId base64url
 * @param {{ signPub: string, currentLoginKey: string }} keys both base64url
 * @returns {Promise<{ through_seq: string }>} decimal string, never a Number.
 */
export function rotateDeviceKey(deviceId, { signPub, currentLoginKey }) {
  return request('POST', `/devices/${encodeURIComponent(deviceId)}/rotate`, {
    sign_pub: signPub,
    current_login_key: currentLoginKey,
  });
}
