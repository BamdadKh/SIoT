/**
 * Password change (design Section 2.2, roadmap 3.3).
 *
 * The client does the actual work: derive a new `master_key`/`kek` from the new
 * password, re-wrap the *existing* `vault_key` under it, and post the result
 * alongside a fresh salt and login_key_hash. Vault contents are never touched,
 * never re-uploaded, and never briefly decrypted in bulk: this is 92 bytes of
 * key material moving, not a vault write.
 *
 * The one thing the server *can* check is `current_login_key` against the
 * stored hash, exactly like `/login`. That check earns its place: a client
 * that is unlocked in this tab has already proven the current password to
 * itself, but never to the server, so a bare session-cookie theft (no `kek`,
 * no XSS) would otherwise be enough to overwrite `wrapped_vault_key` with
 * anything at all, permanently orphaning the real one. The server cannot
 * verify that a new wrapped blob decrypts to the *same* `vault_key` (it never
 * sees `vault_key`), but it can and does verify that whoever is asking still
 * knows the current password.
 */

import { Type } from '@sinclair/typebox';
import type { FastifyPluginAsyncTypebox } from '@fastify/type-provider-typebox';
import { Base64UrlBytes, decodeBase64Url } from '../lib/base64url.js';
import { httpError } from '../lib/http-error.js';
import { hashLoginKey, verifyLoginKey } from '../lib/login-key.js';
import {
  addressThrottle,
  changePasswordThrottle,
  checkThrottles,
  clearThrottle,
  registerFailure,
} from '../lib/rate-limit.js';
import { LOGIN_KEY_BYTES, SALT_BYTES, WRAPPED_VAULT_KEY_BYTES } from '../lib/wire-format.js';

const ChangePasswordBody = Type.Object(
  {
    current_login_key: Base64UrlBytes(
      LOGIN_KEY_BYTES,
      'HKDF(current master_key, "siot/auth/v1")',
    ),
    /** Always a fresh salt: a password change is deriving from scratch anyway. */
    salt: Base64UrlBytes(SALT_BYTES, 'new client Argon2id salt'),
    login_key: Base64UrlBytes(LOGIN_KEY_BYTES, 'HKDF(new master_key, "siot/auth/v1")'),
    wrapped_vault_key: Base64UrlBytes(WRAPPED_VAULT_KEY_BYTES, 'vault_key sealed under new kek'),
  },
  { additionalProperties: false },
);

const ChangePasswordResponse = Type.Object({
  username: Type.String(),
});

export const changePasswordRoutes: FastifyPluginAsyncTypebox = async (app) => {
  app.post(
    '/change-password',
    { schema: { body: ChangePasswordBody, response: { 200: ChangePasswordResponse } } },
    async (req) => {
      const userId = req.session!.userId;

      // Checked before Argon2 runs, same reasoning as /login: a locked-out
      // caller should not get to spend CPU on the verify at all.
      const throttles = [changePasswordThrottle(userId), addressThrottle(req.ip)];
      const throttle = await checkThrottles(app.redis, throttles);
      if (!throttle.allowed) {
        throw httpError(429, `too many attempts, try again in ${throttle.retryAfterSeconds}s`);
      }

      const user = await app.pg.queryOne<{ username: string; login_key_hash: string }>(
        'select username, login_key_hash from users where id = $1',
        [userId],
      );
      // Same reasoning as /vault-key and /session: a session naming a user
      // that is gone is an authentication problem, not a 404.
      if (!user) throw httpError(401, 'authentication required');

      const currentLoginKey = decodeBase64Url(req.body.current_login_key, LOGIN_KEY_BYTES);
      let verified: boolean;
      try {
        verified = await verifyLoginKey(user.login_key_hash, currentLoginKey);
      } finally {
        currentLoginKey.fill(0);
      }

      if (!verified) {
        await registerFailure(app.redis, throttles);
        // 403, not 401: the session itself is fine, `requireSession` already let
        // this request through. What failed is proving the current password,
        // a distinct fact this route alone cares about.
        throw httpError(403, 'current password is incorrect');
      }
      await clearThrottle(app.redis, throttles[0]);

      const salt = decodeBase64Url(req.body.salt, SALT_BYTES);
      const wrappedVaultKey = decodeBase64Url(
        req.body.wrapped_vault_key,
        WRAPPED_VAULT_KEY_BYTES,
      );

      const newLoginKey = decodeBase64Url(req.body.login_key, LOGIN_KEY_BYTES);
      let loginKeyHash: string;
      try {
        loginKeyHash = await hashLoginKey(newLoginKey);
      } finally {
        newLoginKey.fill(0);
      }

      // No version guard here: unlike `vault_version`, there is nothing for two
      // concurrent changes to conflict over in a way the server could detect.
      // It cannot see whether either one still carries the right `vault_key`.
      // Last write wins, which just means "the most recent password is the one
      // that works", the same outcome a CAS would produce for the winner anyway.
      await app.pg.query(
        `update users
            set salt = $2, login_key_hash = $3, wrapped_vault_key = $4
          where id = $1`,
        [userId, salt, loginKeyHash, wrappedVaultKey],
      );

      return { username: user.username };
    },
  );
};
