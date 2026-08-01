/**
 * Vault routes (design Sections 2.2 and 8).
 *
 * This is the first endpoint whose *response* the server cannot read. Everything
 * before it handed back things the server legitimately knows — a username, a
 * salt. `wrapped_vault_key` is sealed under `kek`, and `kek` is the HKDF branch
 * that never left the browser, so the server is passing along 60 bytes it has no
 * more insight into than an eavesdropper would.
 *
 * Which is exactly why the only check here is "is this the owner". There is no
 * validation of the blob's contents to be written, because there is no way to
 * write one — and if a future change makes it look like there is, that change is
 * wrong.
 */

import { Type } from '@sinclair/typebox';
import type { FastifyPluginAsyncTypebox } from '@fastify/type-provider-typebox';
import { Base64UrlBytes, encodeBase64Url } from '../lib/base64url.js';
import { httpError } from '../lib/http-error.js';
import { WRAPPED_VAULT_KEY_BYTES } from '../lib/wire-format.js';

const VaultKeyResponse = Type.Object({
  wrapped_vault_key: Base64UrlBytes(WRAPPED_VAULT_KEY_BYTES, 'vault_key sealed under kek'),
});

export const vaultRoutes: FastifyPluginAsyncTypebox = async (app) => {
  /**
   * Handed out once per login, after which the client holds the unwrapped
   * `vault_key` in memory. It is a separate call from `/login` on purpose: the
   * login response is about authentication, and a client that has a session but
   * has lost its `kek` (a reload) should be able to tell the difference.
   */
  app.get('/vault-key', { schema: { response: { 200: VaultKeyResponse } } }, async (req) => {
    const row = await app.pg.queryOne<{ wrapped_vault_key: Buffer }>(
      'select wrapped_vault_key from users where id = $1',
      [req.session!.userId],
    );

    // The session names a user that no longer exists. Same reasoning as
    // `GET /session`: the request is genuinely unauthenticated, not broken.
    if (!row) throw httpError(401, 'authentication required');

    return { wrapped_vault_key: encodeBase64Url(row.wrapped_vault_key) };
  });
};
