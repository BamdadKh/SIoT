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

/**
 * The vault document blob, `iv(12) || ciphertext || tag(16)`, per
 * `frontend/lib/crypto/vault.js`. Unlike everything above it this one is
 * variable-length — it holds the whole vault, which grows with the device list —
 * so the check is a range rather than an equality.
 *
 * The floor is the AEAD overhead plus one byte, which is the shortest thing that
 * could be a real blob rather than a malformed one. The ceiling is a guess with
 * a purpose: it is not a security boundary, it is a limit on how much storage
 * one account can consume in a single write. 256 KiB is roughly a thousand
 * device entries, comfortably beyond a real vault and comfortably inside the
 * 1 MiB body limit even after base64's 4/3 expansion.
 */
export const VAULT_BLOB_MIN_BYTES = 12 + 16 + 1;
export const VAULT_BLOB_MAX_BYTES = 256 * 1024;

/** 128-bit random, generated in the browser at provisioning time (design 5.1). */
export const DEVICE_ID_BYTES = 16;

/** Ed25519 public key, `frontend/lib/crypto/` device key derivation (design 5.1). */
export const SIGN_PUB_BYTES = 32;

/** `0x00000000 || seq(8B BE)`, design Section 7.2. */
export const NONCE_BYTES = 12;

/** Ed25519 signature over `AAD || nonce || ciphertext`, design Section 7.3. */
export const SIG_BYTES = 64;

/**
 * `AES-256-GCM(device_data_key, nonce, CBOR{t, r}, AAD)`, design Section 7.3.
 * Floor is the GCM tag plus one byte of CBOR, same reasoning as the vault blob
 * floor. No ceiling from the protocol itself; `RECORD_CIPHERTEXT_MAX_BYTES` is a
 * generous storage cap (one reading upload, not a batch), comfortably inside the
 * body limit after base64 expansion.
 */
export const RECORD_CIPHERTEXT_MIN_BYTES = 16 + 1;
export const RECORD_CIPHERTEXT_MAX_BYTES = 4 * 1024;

/**
 * The AAD's `version` and `record_type` bytes (design Section 7.3) are fixed
 * protocol constants for v1, not wire fields — `POST /records` carries only
 * `{ device_id, seq, nonce, ciphertext, sig }` (design 7.3's own example), so
 * both sides reconstruct the same AAD from these plus the wire `device_id` and
 * `seq`. `record_type` is reserved for Phase 7's per-schema record types; until
 * then every record is type 0.
 */
export const PROTOCOL_VERSION = 1;
export const RECORD_TYPE_V1 = 0;

/** `seq` is a uint64; 20 digits covers up to 2^64-1 with room to spare. */
export const SEQ_MAX_DIGITS = 20;
export const UINT64_MAX = (1n << 64n) - 1n;
