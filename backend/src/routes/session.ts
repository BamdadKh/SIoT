/**
 * Routes that require a live session (design Section 3).
 *
 * Everything here is registered inside the authenticated scope in `app.ts`, so
 * `req.session` is guaranteed non-null by the time a handler runs.
 */

import { Type } from '@sinclair/typebox';
import type { FastifyPluginAsyncTypebox } from '@fastify/type-provider-typebox';
import { httpError } from '../lib/http-error.js';
import { SESSION_COOKIE, revokeAllSessions, revokeSession } from '../lib/session.js';

const SessionResponse = Type.Object({
  username: Type.String(),
});

const LogoutResponse = Type.Object({
  /** How many sessions this ended — 1 for logout, n for logout-everywhere. */
  revoked: Type.Number(),
});

export const sessionRoutes: FastifyPluginAsyncTypebox = async (app) => {
  /**
   * Check current session identity and validity. This is the one call a client
   * needs on page load to decide between the dashboard and the login form.
   * It also makes the session hook observable without waiting for the vault.
   */
  app.get('/session', { schema: { response: { 200: SessionResponse } } }, async (req) => {
    const user = await app.pg.queryOne<{ username: string }>(
      'select username from users where id = $1',
      [req.session!.userId],
    );

    // The session outlived the account it names. This could be a deleted user or
    // a Postgres backup restored against live Redis. A 500 would be misleading
    // here because the request is genuinely unauthenticated.
    if (!user) throw httpError(401, 'authentication required');

    return { username: user.username };
  });

  /**
   * Uses POST instead of GET because a logout reachable by <img src> is a
   * nuisance an attacker can trigger cross-site. SameSite=Strict on the cookie
   * provides the real defense, but the HTTP method should not be the weak link.
   */
  app.post('/logout', { schema: { response: { 200: LogoutResponse } } }, async (req, reply) => {
    await revokeSession(app.redis, req.session!);
    return reply.clearCookie(SESSION_COOKIE, { path: '/' }).send({ revoked: 1 });
  });

  /**
   * The whole reason sessions live in Redis rather than in a signed token: this
   * is a SMEMBERS and a DEL, not a revocation list every future request has to
   * be checked against.
   */
  app.post(
    '/logout-everywhere',
    { schema: { response: { 200: LogoutResponse } } },
    async (req, reply) => {
      const revoked = await revokeAllSessions(app.redis, req.session!.userId);
      return reply.clearCookie(SESSION_COOKIE, { path: '/' }).send({ revoked });
    },
  );
};
