/**
 * Read-only key grants (design Section 9, roadmap 8.2).
 *
 * The server never sees a key: `ciphertext` is `device_B_data_key` wrapped
 * under `device_A_data_key`, and the AAD binding (`"grant/v1" ||
 * DEVICE_ID_A || DEVICE_ID_B`) is entirely client-side — nothing here
 * constructs or checks it, the same way `PUT /vault` never touches what it
 * stores.
 *
 * Two plugins, because the two routes have different callers and therefore
 * different authentication:
 *
 * - `grantRoutes` (`POST /grants`) is created from the browser by whoever owns
 *   both devices, so it is session-authenticated like the rest of `devices.ts`.
 * - `deviceGrantRoutes` (`GET /devices/:id/grants`) is polled by Device A's own
 *   firmware (design 9.3), which holds no session. It is registered in `app.ts`
 *   alongside `recordRoutes`, not inside `requireSession`'s scope. Design
 *   Section 13.1 already lists "which devices hold grants on which others" as
 *   metadata the server is acknowledged to see, so an unauthenticated read of
 *   opaque blobs by a known `device_id` is not a new leak beyond that.
 *
 * **Open policy question, inherited from the roadmap item as written**
 * ("must own both devices or have rights — decide policy"): this pass
 * requires the caller to own *both* `device_a_id` and `device_b_id`. There is
 * no cross-user device-sharing primitive anywhere else in the design or
 * roadmap, so a grant between two different users' devices has no path to
 * authorization to check in the first place. If that changes, this is the
 * policy to revisit.
 */

import { Type } from '@sinclair/typebox';
import type { FastifyPluginAsyncTypebox } from '@fastify/type-provider-typebox';
import { Base64UrlBytes, decodeBase64Url, encodeBase64Url } from '../lib/base64url.js';
import { httpError } from '../lib/http-error.js';
import { DEVICE_ID_BYTES, GRANT_BLOB_BYTES } from '../lib/wire-format.js';

const DeviceId = Base64UrlBytes(DEVICE_ID_BYTES, '128-bit device identifier');

const CreateGrantBody = Type.Object(
  {
    device_a_id: DeviceId,
    device_b_id: DeviceId,
    ciphertext: Base64UrlBytes(GRANT_BLOB_BYTES, 'device_B_data_key wrapped under device_A_data_key'),
  },
  { additionalProperties: false },
);

const GrantsListResponse = Type.Object({
  grants: Type.Array(
    Type.Object({
      device_b_id: DeviceId,
      ciphertext: Base64UrlBytes(GRANT_BLOB_BYTES, 'device_B_data_key wrapped under device_A_data_key'),
      created_at: Type.String({ format: 'date-time' }),
    }),
  ),
});

export const grantRoutes: FastifyPluginAsyncTypebox = async (app) => {
  /**
   * Records a grant. Ownership of *both* devices is checked in one query
   * rather than two, so there is no window between checking A and checking B
   * for either to change hands.
   */
  app.post(
    '/grants',
    { schema: { body: CreateGrantBody, response: { 201: Type.Object({}) } } },
    async (req, reply) => {
      const deviceAId = decodeBase64Url(req.body.device_a_id, DEVICE_ID_BYTES);
      const deviceBId = decodeBase64Url(req.body.device_b_id, DEVICE_ID_BYTES);
      const ciphertext = decodeBase64Url(req.body.ciphertext, GRANT_BLOB_BYTES);
      const userId = req.session!.userId;

      const owned = await app.pg.query<{ device_id: Buffer }>(
        `select device_id from devices
          where owner_user_id = $1 and device_id in ($2, $3)`,
        [userId, deviceAId, deviceBId],
      );
      if (owned.rowCount !== 2) {
        throw httpError(403, 'both devices must belong to the authenticated account');
      }

      await app.pg.query(
        `insert into grants (device_a_id, device_b_id, ciphertext)
         values ($1, $2, $3)`,
        [deviceAId, deviceBId, ciphertext],
      );

      return reply.code(201).send({});
    },
  );
};

export const deviceGrantRoutes: FastifyPluginAsyncTypebox = async (app) => {
  /**
   * Every grant naming this device as the recipient, newest first: a device
   * that rotates through several key epochs of the same source (design 9.3)
   * needs all of them, not just the latest, since each unwraps a different
   * `device_B_data_key` covering a different slice of history.
   */
  app.get(
    '/devices/:device_id/grants',
    { schema: { params: Type.Object({ device_id: DeviceId }), response: { 200: GrantsListResponse } } },
    async (req, reply) => {
      const deviceAId = decodeBase64Url(req.params.device_id, DEVICE_ID_BYTES);

      const rows = await app.pg.query<{
        device_b_id: Buffer;
        ciphertext: Buffer;
        created_at: Date;
      }>(
        `select device_b_id, ciphertext, created_at
           from grants
          where device_a_id = $1
          order by created_at desc`,
        [deviceAId],
      );

      reply.header('cache-control', 'no-store');
      return {
        grants: rows.rows.map((row) => ({
          device_b_id: encodeBase64Url(row.device_b_id),
          ciphertext: encodeBase64Url(row.ciphertext),
          created_at: row.created_at.toISOString(),
        })),
      };
    },
  );
};
