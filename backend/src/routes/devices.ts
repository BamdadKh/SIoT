/**
 * Device identity routes (design Section 5, roadmap 4.2 and 4.8).
 *
 * Everything here is a value the design document explicitly permits the server
 * to see in plaintext (Section 5.2): `DEVICE_ID`, `device_sign_pub`, and timing
 * metadata. `DEVICE_SECRET` and the device's name never appear on this path —
 * the name lives in the vault (design 5.5) and is joined against this list
 * client-side, not looked up here.
 */

import { Type } from '@sinclair/typebox';
import type { FastifyPluginAsyncTypebox } from '@fastify/type-provider-typebox';
import { Base64UrlBytes, decodeBase64Url, encodeBase64Url } from '../lib/base64url.js';
import { httpError, isUniqueViolation } from '../lib/http-error.js';
import { DEVICE_ID_BYTES, SIGN_PUB_BYTES } from '../lib/wire-format.js';

const DeviceId = Base64UrlBytes(DEVICE_ID_BYTES, '128-bit device identifier');

const RegisterDeviceBody = Type.Object(
  {
    device_id: DeviceId,
    sign_pub: Base64UrlBytes(SIGN_PUB_BYTES, 'Ed25519 device_sign_pub'),
  },
  { additionalProperties: false },
);

const RegisterDeviceResponse = Type.Object({
  device_id: DeviceId,
});

/** `numeric(20,0)` arrives from `pg` as a string; kept as one on the wire too,
 * since `seq` is a uint64 that a JSON number cannot represent losslessly. */
const Seq = Type.String({ pattern: '^[0-9]+$' });

const DeviceListResponse = Type.Object({
  devices: Type.Array(
    Type.Object({
      device_id: DeviceId,
      last_seq: Seq,
      /** `null` until the device's first record lands (Phase 6). */
      last_seen_at: Type.Union([Type.String({ format: 'date-time' }), Type.Null()]),
    }),
  ),
});

export const deviceRoutes: FastifyPluginAsyncTypebox = async (app) => {
  /**
   * Registers the public half of a device's identity, generated in the browser
   * (design 5.1, 5.3 step 2). `DEVICE_SECRET` and everything derived from it
   * never reach this route — the client uploads the encrypted device record to
   * the vault separately (roadmap 4.3), which is the only place the secret and
   * its name are stored.
   */
  app.post(
    '/devices/register',
    { schema: { body: RegisterDeviceBody, response: { 201: RegisterDeviceResponse } } },
    async (req, reply) => {
      const deviceId = decodeBase64Url(req.body.device_id, DEVICE_ID_BYTES);
      const signPub = decodeBase64Url(req.body.sign_pub, SIGN_PUB_BYTES);

      try {
        await app.pg.query(
          `insert into devices (device_id, owner_user_id, sign_pub)
           values ($1, $2, $3)`,
          [deviceId, req.session!.userId, signPub],
        );
      } catch (err) {
        // device_id is the primary key, so the index itself is the uniqueness
        // check — same reasoning as the username check-then-insert race in
        // /signup: a pre-SELECT would let two concurrent registrations of the
        // same freshly-generated id both pass.
        if (isUniqueViolation(err)) {
          throw httpError(409, 'that device_id is already registered');
        }
        throw err;
      }

      return reply.code(201).send({ device_id: req.body.device_id });
    },
  );

  /**
   * The metadata the server legitimately holds per device (design 5.2): the id,
   * how far it has counted, and when its newest record arrived. No names — it
   * has none (design 5.5). The client joins this against the vault's device
   * records by `DEVICE_ID` to get names and to notice the two mismatch cases
   * (roadmap 4.8): a vault entry the server has never heard of, and a device
   * the server reports that the vault has no record for.
   */
  app.get(
    '/devices',
    { schema: { response: { 200: DeviceListResponse } } },
    async (req, reply) => {
      const rows = await app.pg.query<{
        device_id: Buffer;
        last_seq: string;
        last_seen_at: Date | null;
      }>(
        `select device_id, last_seq, last_seen_at
           from devices
          where owner_user_id = $1
          order by created_at asc`,
        [req.session!.userId],
      );

      reply.header('cache-control', 'no-store');
      return {
        devices: rows.rows.map((row) => ({
          device_id: encodeBase64Url(row.device_id),
          last_seq: row.last_seq,
          last_seen_at: row.last_seen_at ? row.last_seen_at.toISOString() : null,
        })),
      };
    },
  );
};
