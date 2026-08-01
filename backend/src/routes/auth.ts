/**
 * Account routes (design Sections 2 and 3).
 *
 * Everything the client sends here is either a public identifier or an opaque
 * blob. There is no password on the wire, and no code path — here or anywhere
 * in `backend/` — that could turn what arrives into `kek` or `vault_key`.
 */

import { Type } from '@sinclair/typebox';
import type { FastifyPluginAsyncTypebox } from '@fastify/type-provider-typebox';
import { config } from '../config.js';
import { Base64UrlBytes, decodeBase64Url, encodeBase64Url } from '../lib/base64url.js';
import { decoySalt } from '../lib/decoy-salt.js';
import { httpError, isUniqueViolation } from '../lib/http-error.js';
import { hashLoginKey, verifyAgainstDecoy, verifyLoginKey } from '../lib/login-key.js';
import {
  accountThrottle,
  addressThrottle,
  checkThrottles,
  clearThrottle,
  registerFailure,
} from '../lib/rate-limit.js';
import { ABSOLUTE_TTL_SECONDS, SESSION_COOKIE, createSession } from '../lib/session.js';
import { LOGIN_KEY_BYTES, SALT_BYTES, WRAPPED_VAULT_KEY_BYTES } from '../lib/wire-format.js';

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

const LoginBody = Type.Object(
  {
    username: Username,
    login_key: Base64UrlBytes(LOGIN_KEY_BYTES, 'HKDF(master_key, "siot/auth/v1")'),
  },
  { additionalProperties: false },
);

const LoginResponse = Type.Object({
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
   * Login (design Section 3). The password is not here and never was — the
   * client fetched its salt from `/salt`, ran Argon2id locally, and is posting
   * one HKDF branch of the result. The other branch, `kek`, stayed in the
   * browser, so a compromised server watching this endpoint still cannot open a
   * single vault.
   */
  app.post(
    '/login',
    { schema: { body: LoginBody, response: { 200: LoginResponse } } },
    async (req, reply) => {
      const username = req.body.username.toLowerCase();

      // `req.ip` is the socket address: Fastify's `trustProxy` is off, so an
      // X-Forwarded-For header cannot be used to mint a fresh throttle bucket
      // per request. Turning it on requires a proxy we actually trust.
      const throttles = [accountThrottle(username), addressThrottle(req.ip)];

      // Checked before Argon2 runs, so a locked-out attacker cannot keep using
      // login attempts as a CPU-exhaustion lever.
      const throttle = await checkThrottles(app.redis, throttles);
      if (!throttle.allowed) {
        // Headers set on the reply survive the throw — the error handler sends
        // through this same reply object.
        reply.header('retry-after', String(throttle.retryAfterSeconds));
        throw httpError(
          429,
          `too many login attempts, try again in ${throttle.retryAfterSeconds}s`,
        );
      }

      const user = await app.pg.queryOne<{ id: string; login_key_hash: string }>(
        'select id, login_key_hash from users where username = $1',
        [username],
      );

      const loginKey = decodeBase64Url(req.body.login_key, LOGIN_KEY_BYTES);
      let verified: boolean;
      try {
        // Both branches run a full Argon2id verify. The decoy path exists purely
        // so response time cannot distinguish "wrong password" from "no such
        // account" — see `verifyAgainstDecoy`.
        verified = user
          ? await verifyLoginKey(user.login_key_hash, loginKey)
          : await verifyAgainstDecoy(loginKey);
      } finally {
        loginKey.fill(0);
      }

      if (!user || !verified) {
        await registerFailure(app.redis, throttles);
        // One message for both failures. Saying which was wrong would hand back
        // the account-existence answer the whole flow is built to withhold.
        throw httpError(401, 'invalid username or password');
      }

      await clearThrottle(app.redis, throttles[0]);

      const sessionId = await createSession(app.redis, user.id);
      return reply
        .setCookie(SESSION_COOKIE, sessionId, {
          httpOnly: true,
          // Tracks TLS rather than being hardcoded: with TLS_ENABLED=false the
          // browser would drop a Secure cookie and login would fail silently.
          // That mode is already a loud, unsupported debugging hatch where the
          // login_key crosses the wire in the clear — the flag is not what is
          // protecting anything there.
          secure: config.tlsEnabled,
          sameSite: 'strict',
          path: '/',
          // Matches the session's absolute lifetime, so the browser stops
          // presenting a cookie the server has already stopped honouring.
          maxAge: ABSOLUTE_TTL_SECONDS,
        })
        // A session id in a shared cache would be a very bad day.
        .header('cache-control', 'no-store')
        .send({ username });
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
