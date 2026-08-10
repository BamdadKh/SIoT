/**
 * Device commands (design Section 11 — not yet written; roadmap 11.2/11.3/11.4).
 *
 * The dashboard is the writer here, which is the reverse of every other
 * device-authenticated path in this file. `POST` is session-authenticated and
 * owner-scoped exactly like `POST /grants`: the server cannot verify
 * `ciphertext`'s contents either way, so the only thing worth checking at
 * write time is whether this session owns the target device (Section 11.0).
 * `GET` is public and polled by the device itself, which holds no session —
 * the same shape as `GET /devices/:id/grants`. `ack` is device-authenticated
 * by the same Ed25519 key `POST /records` already verifies (design 7.4 check
 * 1), reusing that machinery rather than inventing a second way for the
 * server to trust a device: only the device a command was addressed to can
 * meaningfully say it executed.
 *
 * `device_commands.id` doubles as the delivery cursor named in roadmap
 * 11.2/11.4 — see the migration for why a bare bigserial is enough. It is
 * never bound into the AAD; that stays entirely client/device-side.
 */

import { Type } from '@sinclair/typebox';
import type { FastifyPluginAsyncTypebox } from '@fastify/type-provider-typebox';
import {
  Base64UrlBytes,
  Base64UrlVariableBytes,
  decodeBase64Url,
  decodeBase64UrlRange,
  encodeBase64Url,
} from '../lib/base64url.js';
import { verifyEd25519 } from '../lib/ed25519.js';
import { httpError } from '../lib/http-error.js';
import {
  COMMAND_CIPHERTEXT_MAX_BYTES,
  COMMAND_CIPHERTEXT_MIN_BYTES,
  COMMAND_NONCE_BYTES,
  CURSOR_MAX,
  CURSOR_MAX_DIGITS,
  DEVICE_ID_BYTES,
  SIG_BYTES,
} from '../lib/wire-format.js';

const DeviceId = Base64UrlBytes(DEVICE_ID_BYTES, '128-bit device identifier');
const Cursor = Type.String({ pattern: `^[0-9]{1,${CURSOR_MAX_DIGITS}}$` });

/** Throws if `value` isn't representable as a `device_commands.id`. */
function parseCursor(value: string): bigint {
  const cursor = BigInt(value);
  if (cursor > CURSOR_MAX) {
    throw new Error(`cursor ${value} exceeds the delivery cursor's range`);
  }
  return cursor;
}

/** 8 bytes big-endian — the tail of the ack's signing input, `device_id || up_to`. */
function cursorToBytes(cursor: bigint): Buffer {
  const bytes = Buffer.alloc(8);
  bytes.writeBigUInt64BE(cursor);
  return bytes;
}

const CiphertextField = Base64UrlVariableBytes(
  COMMAND_CIPHERTEXT_MIN_BYTES,
  COMMAND_CIPHERTEXT_MAX_BYTES,
  'AES-256-GCM(device_command_key, nonce, {command_seq, type, args}, AAD)',
);
const NonceField = Base64UrlBytes(COMMAND_NONCE_BYTES, 'random 96-bit nonce (design 11.0)');

const CreateCommandBody = Type.Object(
  { ciphertext: CiphertextField, nonce: NonceField },
  { additionalProperties: false },
);

const CommandsParams = Type.Object({ device_id: DeviceId });

const CommandsListResponse = Type.Object({
  commands: Type.Array(
    Type.Object({
      cursor: Cursor,
      ciphertext: CiphertextField,
      nonce: NonceField,
      created_at: Type.String({ format: 'date-time' }),
    }),
  ),
});

const AckBody = Type.Object(
  {
    up_to: Cursor,
    sig: Base64UrlBytes(SIG_BYTES, 'Ed25519(device_sign_priv, device_id || up_to)'),
  },
  { additionalProperties: false },
);

export const commandRoutes: FastifyPluginAsyncTypebox = async (app) => {
  /**
   * Queues a command for a device the caller owns. Ownership is checked the
   * same way `POST /grants` checks it and `GET /devices/:id/records` checks
   * it: one query, no window between the check and the write for the device
   * to change hands in.
   */
  app.post(
    '/devices/:device_id/commands',
    {
      schema: {
        params: CommandsParams,
        body: CreateCommandBody,
        response: { 201: Type.Object({ cursor: Cursor }) },
      },
    },
    async (req, reply) => {
      const deviceId = decodeBase64Url(req.params.device_id, DEVICE_ID_BYTES);
      const ciphertext = decodeBase64UrlRange(
        req.body.ciphertext,
        COMMAND_CIPHERTEXT_MIN_BYTES,
        COMMAND_CIPHERTEXT_MAX_BYTES,
      );
      const nonce = decodeBase64Url(req.body.nonce, COMMAND_NONCE_BYTES);

      const owned = await app.pg.queryOne(
        'select 1 from devices where device_id = $1 and owner_user_id = $2',
        [deviceId, req.session!.userId],
      );
      // Same anti-enumeration reasoning as every other cross-owner lookup in
      // this codebase: a stranger's device_id must not read differently from
      // a made-up one.
      if (!owned) throw httpError(404, 'unknown device_id');

      const row = await app.pg.queryOne<{ id: string }>(
        `insert into device_commands (device_id, nonce, ciphertext)
         values ($1, $2, $3)
         returning id`,
        [deviceId, nonce, ciphertext],
      );

      return reply.code(201).send({ cursor: row!.id });
    },
  );
};

export const deviceCommandRoutes: FastifyPluginAsyncTypebox = async (app) => {
  /**
   * Every command still queued for this device, oldest first. Expected to
   * stay short — `ack` below prunes it — so this skips the cursor pagination
   * `GET /devices/:id/records` needs for a history that only grows.
   */
  app.get(
    '/devices/:device_id/commands',
    { schema: { params: CommandsParams, response: { 200: CommandsListResponse } } },
    async (req, reply) => {
      const deviceId = decodeBase64Url(req.params.device_id, DEVICE_ID_BYTES);

      const rows = await app.pg.query<{
        id: string;
        nonce: Buffer;
        ciphertext: Buffer;
        created_at: Date;
      }>(
        `select id, nonce, ciphertext, created_at
           from device_commands
          where device_id = $1
          order by id asc`,
        [deviceId],
      );

      reply.header('cache-control', 'no-store');
      return {
        commands: rows.rows.map((row) => ({
          cursor: row.id,
          ciphertext: encodeBase64Url(row.ciphertext),
          nonce: encodeBase64Url(row.nonce),
          created_at: row.created_at.toISOString(),
        })),
      };
    },
  );

  /**
   * Prunes every command at or below `up_to` for this device. Idempotent by
   * construction — deleting rows at or below an already-pruned cursor deletes
   * nothing — so a replayed ack (the ack itself got lost, not the command) is
   * a safe no-op and needs no compare-and-swap the way `last_seq` needs one
   * on the write side (roadmap 11.4).
   */
  app.post(
    '/devices/:device_id/commands/ack',
    {
      schema: {
        params: CommandsParams,
        body: AckBody,
        response: { 200: Type.Object({ pruned: Type.Integer() }) },
      },
    },
    async (req, reply) => {
      const deviceId = decodeBase64Url(req.params.device_id, DEVICE_ID_BYTES);
      const sig = decodeBase64Url(req.body.sig, SIG_BYTES);

      let upTo: bigint;
      try {
        upTo = parseCursor(req.body.up_to);
      } catch (err) {
        throw httpError(400, (err as Error).message);
      }

      const device = await app.pg.queryOne<{ sign_pub: Buffer }>(
        'select sign_pub from devices where device_id = $1',
        [deviceId],
      );
      if (!device) throw httpError(404, 'unknown device_id');

      const message = Buffer.concat([deviceId, cursorToBytes(upTo)]);
      if (!verifyEd25519(device.sign_pub, message, sig)) {
        throw httpError(401, 'signature does not verify against the registered sign_pub');
      }

      const pruned = await app.pg.query(
        'delete from device_commands where device_id = $1 and id <= $2',
        [deviceId, upTo.toString()],
      );

      return reply.code(200).send({ pruned: pruned.rowCount ?? 0 });
    },
  );
};
