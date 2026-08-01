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

async function request(method, path, body) {
  let response;
  try {
    response = await fetch(path, {
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
