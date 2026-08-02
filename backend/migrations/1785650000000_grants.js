/**
 * Read-only key grants (roadmap 8.2, design Section 9).
 *
 * `ciphertext` is `device_B_data_key` wrapped under `device_A_data_key`
 * (AAD `"grant/v1" || DEVICE_ID_A || DEVICE_ID_B`), opaque to the server the
 * same way `wrapped_vault_key` is.
 *
 * No uniqueness constraint on `(device_a_id, device_b_id)`: design 9.3 says a
 * grant is not revocable, only superseded by re-provisioning B with a new
 * `DEVICE_SECRET`, and "old data stays readable by A forever" depends on A
 * still being able to fetch the grant that wrapped the *old* `device_B_data_key`.
 * Upserting on re-grant would destroy that row. Multiple grants per pair,
 * one per key epoch, is therefore correct rather than a gap to close later.
 */

exports.shorthands = undefined;

exports.up = (pgm) => {
  pgm.createTable('grants', {
    id: { type: 'bigserial', primaryKey: true },
    device_a_id: { type: 'bytea', notNull: true, references: 'devices', onDelete: 'CASCADE' },
    device_b_id: { type: 'bytea', notNull: true, references: 'devices', onDelete: 'CASCADE' },
    // iv(12) || AES-256-GCM(device_B_data_key)(32) || tag(16), same shape as
    // wrapped_vault_key.
    ciphertext: { type: 'bytea', notNull: true },
    created_at: { type: 'timestamptz', notNull: true, default: pgm.func('now()') },
  });
  // The lookup GET /devices/:id/grants runs (roadmap 8.2, "grants targeting it").
  pgm.createIndex('grants', 'device_a_id');
};

exports.down = (pgm) => {
  pgm.dropTable('grants');
};
