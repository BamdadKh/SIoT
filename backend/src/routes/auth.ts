/**
 * Account routes (design Sections 2 and 3).
 *
 * Everything the client sends here is either a public identifier or an opaque
 * blob. There is no password on the wire, and no code path — here or anywhere
 * in `backend/` — that could turn what arrives into `kek` or `vault_key`.
 */

import { Type } from '@sinclair/typebox';
import type { FastifyPluginAsyncTypebox } from '@fastify/type-provider-typebox';
import { Base64UrlBytes, decodeBase64Url, encodeBase64Url } from '../lib/base64url.js';
import { decoySalt } from '../lib/decoy-salt.js';
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

const SaltQuery = Type.Object({ username: Username }, { additionalProperties: false });

const SaltResponse = Type.Object({
  salt: Base64UrlBytes(SALT_BYTES, 'client Argon2id salt'),
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

  /**
   * The client needs the Argon2id salt before it can derive anything, which
   * means handing it out to an unauthenticated caller. The endpoint therefore
   * has exactly one job beyond the lookup: never reveal whether the account is
   * real (design Section 3).
   */
  app.get(
    '/salt',
    { schema: { querystring: SaltQuery, response: { 200: SaltResponse } } },
    async (req, reply) => {
      const username = req.query.username.toLowerCase();

      // Both branches do the same work in the same order — one indexed lookup
      // and one HMAC — so the response time carries no signal either. The decoy
      // is computed even when it is thrown away; it costs microseconds against a
      // database round trip, and code with no existence-dependent branch cannot
      // drift into having one.
      const row = await app.pg.queryOne<{ salt: Buffer }>(
        'select salt from users where username = $1',
        [username],
      );
      const decoy = decoySalt(username, SALT_BYTES);

      // no-store: a cached decoy that later disagrees with a real salt would
      // leak the moment the account gets created.
      return reply
        .header('cache-control', 'no-store')
        .send({ salt: encodeBase64Url(row?.salt ?? decoy) });
    },
  );
};
