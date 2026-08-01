/**
 * The gate every authenticated route sits behind (design Section 3).
 *
 * This is deliberately *not* a global hook with a list of exempt paths. It is
 * installed on a Fastify encapsulation scope, so a route is protected by where
 * it is registered rather than by remembering to opt in. Forgetting to add a new
 * route to an allowlist fails open; registering it in the wrong scope fails
 * closed, which is the direction a mistake should point.
 */

import fp from 'fastify-plugin';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { httpError } from './http-error.js';
import { SESSION_COOKIE, lookupSession } from './session.js';
import type { ActiveSession } from './session.js';

declare module 'fastify' {
  interface FastifyRequest {
    /** Set by `requireSession`; null on any route that does not use it. */
    session: ActiveSession | null;
  }
}

/** Declares the request property so Fastify can keep one object shape. */
export const sessionPlugin = fp(async (app) => {
  app.decorateRequest('session', null);
});

export async function requireSession(req: FastifyRequest, reply: FastifyReply): Promise<void> {
  // Authenticated responses are per-user by definition. A shared cache holding
  // one is a data leak that has nothing to do with the crypto.
  reply.header('cache-control', 'no-store');

  const cookie = req.cookies[SESSION_COOKIE];
  const session = cookie ? await lookupSession(req.server.redis, cookie) : null;

  if (!session) {
    // A cookie that resolved to nothing is dead for good — expired, revoked, or
    // never real. Clearing it stops the browser replaying it on every request.
    if (cookie) reply.clearCookie(SESSION_COOKIE, { path: '/' });
    // One message for every failure mode. Which one it was is not the client's
    // business, and "session expired" vs "no session" is a free hint to anyone
    // probing with a guessed id.
    throw httpError(401, 'authentication required');
  }

  req.session = session;
}
