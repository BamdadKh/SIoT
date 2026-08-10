/**
 * `device_commands` (design Section 11 — not yet written; roadmap 11.2/11.3/11.4).
 *
 * Opaque to the server like every other blob it stores: `ciphertext` is
 * `{command_seq, type, args}` encrypted under `device_command_key`, with a
 * random per-write nonce rather than one derived from a counter (Section
 * 11.0's deliberate reversal of the record nonce rule — the browser is the
 * encrypting party here, and it has a real CSPRNG, unlike a device at boot).
 *
 * `id` doubles as the delivery cursor the roadmap names: a bigserial is
 * already globally monotonic, which makes it monotonic per device for free,
 * so there is no second per-device counter that could drift out of sync
 * with it. It is never bound into the AAD — that stays entirely
 * client/device-side — it exists purely for the server's own delivery
 * ordering and to know what `ack` may prune.
 */

exports.shorthands = undefined;

exports.up = (pgm) => {
  pgm.createTable('device_commands', {
    id: { type: 'bigserial', primaryKey: true },
    device_id: { type: 'bytea', notNull: true, references: 'devices', onDelete: 'CASCADE' },
    nonce: { type: 'bytea', notNull: true },
    ciphertext: { type: 'bytea', notNull: true },
    created_at: { type: 'timestamptz', notNull: true, default: pgm.func('now()') },
  });
  // GET /devices/:id/commands and the ack prune both filter by device_id.
  pgm.createIndex('device_commands', 'device_id');
};

exports.down = (pgm) => {
  pgm.dropTable('device_commands');
};
