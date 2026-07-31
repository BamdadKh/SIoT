/**
 * Account routes (design Sections 2 and 3).
 *
 * Everything the client sends here is either a public identifier or an opaque
 * blob. There is no password on the wire, and no code path — here or anywhere
 * in `backend/` — that could turn what arrives into `kek` or `vault_key`.
 */

import { Type } from '@sinclair/typebox';
import type { FastifyPluginAsyncTypebox } from '@fastify/type-provider-typebox';
import { Base64UrlBytes, decodeBase64Url } from '../lib/base64url.js';
import { httpError, isUniqueViolation } from '../lib/http-error.js';
import { hashLoginKey } from '../lib/login-key.js';

/** Must match the client's `SALT_BYTES` / key sizes — these are wire format. */
const SALT_BYTES = 16;
const LOGIN_KEY_BYTES = 32;
/** iv(12) || ciphertext(32) || tag(16), per `frontend/lib/crypto/vault-key.js`. */
const WRAPPED_VAULT_KEY_BYTES = 60;

/**
 * ASCII-only, and normalised to lowercase before storage. Restricting the
 * character set is not cosmetic: usernames are the lookup key for `/salt`, and
 * allowing Unicode invites homoglyph pairs that look identical to a human but
 * are distinct rows.
 */
const Username = Type.String({
  pattern: '^[A-Za-z0-9_.-]{3,32}$',
  description: '3-32 chars, letters/digits/underscore/dot/hyphen; case-insensitive',
});

const SignupBody = Type.Object(
  {
    username: Username,
    salt: Base64UrlBytes(SALT_BYTES, 'client Argon2id salt'),
    login_key: Base64UrlBytes(LOGIN_KEY_BYTES, 'HKDF(master_key, "siot/auth/v1")'),
    wrapped_vault_key: Base64UrlBytes(WRAPPED_VAULT_KEY_BYTES, 'vault_key sealed under kek'),
  },
  { additionalProperties: false },
);

const SignupResponse = Type.Object({
  username: Type.String(),
});

export const authRoutes: FastifyPluginAsyncTypebox = async (app) => {
  app.post(
    '/signup',
    { schema: { body: SignupBody, response: { 201: SignupResponse } } },
    async (req, reply) => {
      const username = req.body.username.toLowerCase();
      const salt = decodeBase64Url(req.body.salt, SALT_BYTES);
      const wrappedVaultKey = decodeBase64Url(
        req.body.wrapped_vault_key,
        WRAPPED_VAULT_KEY_BYTES,
      );

      // login_key is password-equivalent. It is hashed immediately, never stored
      // raw, and the buffer is wiped once the hash exists so it does not sit in
      // the heap for the lifetime of the request.
      const loginKey = decodeBase64Url(req.body.login_key, LOGIN_KEY_BYTES);
      let loginKeyHash: string;
      try {
        loginKeyHash = await hashLoginKey(loginKey);
      } finally {
        loginKey.fill(0);
      }

      try {
        await app.pg.query(
          `insert into users (username, salt, login_key_hash, wrapped_vault_key)
           values ($1, $2, $3, $4)`,
          [username, salt, loginKeyHash, wrappedVaultKey],
        );
      } catch (err) {
        // Let the unique index decide rather than a SELECT first: a pre-check is
        // a race, and two simultaneous signups for the same name would both pass
        // it. vault_version defaults to 0 in the schema.
        if (isUniqueViolation(err)) {
          // This does leak that the username exists — unavoidable in any signup
          // form that refuses duplicates. The enumeration defence lives where it
          // can actually work: `GET /salt` returns a decoy for unknown accounts
          // (Section 3), so knowing a name is taken buys nothing further.
          throw httpError(409, 'that username is already taken');
        }
        throw err;
      }

      // No session. Signup proves you can derive the keys; logging in proves it
      // again through the rate-limited path, and keeps one way in instead of two.
      return reply.code(201).send({ username });
    },
  );
};
