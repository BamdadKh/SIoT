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
import {
  Base64UrlBytes,
  Base64UrlVariableBytes,
  decodeBase64UrlRange,
  encodeBase64Url,
} from '../lib/base64url.js';
import { httpError } from '../lib/http-error.js';
import {
  VAULT_BLOB_MAX_BYTES,
  VAULT_BLOB_MIN_BYTES,
  WRAPPED_VAULT_KEY_BYTES,
} from '../lib/wire-format.js';

const VaultKeyResponse = Type.Object({
  wrapped_vault_key: Base64UrlBytes(WRAPPED_VAULT_KEY_BYTES, 'vault_key sealed under kek'),
});

const VaultCiphertext = Base64UrlVariableBytes(
  VAULT_BLOB_MIN_BYTES,
  VAULT_BLOB_MAX_BYTES,
  'vault document sealed under vault_key',
);

/**
 * A vault version is a per-user write counter, not a device sequence number, so
 * unlike `seq` it is nowhere near needing 64 bits and travels as a JSON number.
 * The column is `bigint` and `pg` hands it back as a string; `readVersion`
 * below is the only place that conversion happens.
 */
const VaultVersion = Type.Integer({ minimum: 0 });

const VaultWriteBody = Type.Object(
  {
    /** Must be exactly current + 1. Anything else is a conflict, not a correction. */
    vault_version: Type.Integer({ minimum: 1 }),
    ciphertext: VaultCiphertext,
  },
  { additionalProperties: false },
);

const VaultWriteResponse = Type.Object({
  vault_version: VaultVersion,
});

const VaultReadResponse = Type.Object({
  vault_version: VaultVersion,
  /**
   * `null` on an account that has never written a vault, rather than a 404.
   *
   * A 404 would be a second shape the client has to branch on, and the branch
   * that skips the rollback check is exactly the one a hostile server would want
   * to steer it into — "no vault here" and "here is a vault from last week" have
   * to go through the same monotonicity check. Version 0 with no ciphertext is
   * simply the lowest point on that scale.
   */
  ciphertext: Type.Union([VaultCiphertext, Type.Null()]),
});

/** `bigint` arrives from `pg` as a string. */
function readVersion(value: string): number {
  const version = Number(value);
  if (!Number.isSafeInteger(version)) {
    throw new Error(`vault_version ${value} is out of safe integer range`);
  }
  return version;
}

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

  /**
   * The vault document itself (design Section 8), sealed under `vault_key`.
   *
   * `no-store` is not about confidentiality — the blob is opaque to every cache
   * it could pass through. It is about freshness: a cached vault is a rollback
   * the client would have no way to distinguish from a hostile one, and the
   * whole point of the version counter is that stale data is loud.
   */
  app.get('/vault', { schema: { response: { 200: VaultReadResponse } } }, async (req, reply) => {
    const row = await app.pg.queryOne<{ vault_version: string; ciphertext: Buffer | null }>(
      `select u.vault_version, v.ciphertext
         from users u
         left join vault_blobs v on v.user_id = u.id
        where u.id = $1`,
      [req.session!.userId],
    );

    if (!row) throw httpError(401, 'authentication required');

    reply.header('cache-control', 'no-store');
    return {
      vault_version: readVersion(row.vault_version),
      ciphertext: row.ciphertext ? encodeBase64Url(row.ciphertext) : null,
    };
  });

  /**
   * Replaces the whole vault. v1 granularity is one blob per user, so there is
   * nothing to merge server-side — and nothing that *could* be merged, since the
   * server cannot read either side.
   *
   * The version guard is the only correctness check available to a server that
   * cannot see what it is storing. It is a compare-and-swap in one statement
   * rather than a read-then-write, so two tabs saving at once cannot both pass:
   * whichever loses finds `vault_version` already moved and gets a 409.
   *
   * PUT is not idempotent here, which is the intended behaviour rather than a
   * violation of it — a retried write finds the version already consumed and is
   * refused instead of silently applying twice.
   */
  app.put(
    '/vault',
    { schema: { body: VaultWriteBody, response: { 200: VaultWriteResponse } } },
    async (req) => {
      const { vault_version: nextVersion, ciphertext } = req.body;

      // Schema validation has already fixed the alphabet and the string length;
      // this pins the decoded size, which base64 length alone cannot.
      let blob: Buffer;
      try {
        blob = decodeBase64UrlRange(ciphertext, VAULT_BLOB_MIN_BYTES, VAULT_BLOB_MAX_BYTES);
      } catch (err) {
        throw httpError(400, `ciphertext is not a valid vault blob: ${(err as Error).message}`);
      }

      const userId = req.session!.userId;

      return app.pg.transaction(async (tx) => {
        const bumped = await tx.query<{ vault_version: string }>(
          `update users
              set vault_version = vault_version + 1
            where id = $1 and vault_version = $2
        returning vault_version`,
          [userId, nextVersion - 1],
        );

        if (bumped.rowCount === 0) {
          const current = await tx.query<{ vault_version: string }>(
            'select vault_version from users where id = $1',
            [userId],
          );
          // Same reasoning as `/session` and `/vault-key`: a session naming a
          // user that is gone is an authentication problem, not a conflict.
          if (current.rowCount === 0) throw httpError(401, 'authentication required');

          // The current version goes in the message rather than in a structured
          // body because knowing the number does not help on its own — a client
          // that lost the race has to re-read and merge the vault it could not
          // see, so it is fetching `GET /vault` either way.
          throw httpError(
            409,
            `vault is at version ${current.rows[0].vault_version}; ` +
              `this write claimed to follow version ${nextVersion - 1}`,
          );
        }

        await tx.query(
          `insert into vault_blobs (user_id, ciphertext)
                values ($1, $2)
           on conflict (user_id)
             do update set ciphertext = excluded.ciphertext, updated_at = now()`,
          [userId, blob],
        );

        return { vault_version: readVersion(bumped.rows[0].vault_version) };
      });
    },
  );
};
