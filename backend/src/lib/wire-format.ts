/**
 * Fixed byte lengths shared by every route that puts these values on the wire.
 *
 * These are not preferences, they are a contract with `frontend/lib/crypto/`.
 * Changing one without changing the client rejects every request with a 400
 * before a handler sees it — which is the intended failure, but only if there is
 * one definition to change. Two copies drifting apart is how a size check ends
 * up validating nothing.
 */

/** `SALT_BYTES` in `frontend/lib/crypto/random.js` — 128-bit Argon2id salt. */
export const SALT_BYTES = 16;

/** HKDF-SHA256 output, `info = "siot/auth/v1"`. */
export const LOGIN_KEY_BYTES = 32;

/** iv(12) || ciphertext(32) || tag(16), per `frontend/lib/crypto/vault-key.js`. */
export const WRAPPED_VAULT_KEY_BYTES = 60;
