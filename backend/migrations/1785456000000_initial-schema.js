/**
 * Initial SIOT schema.
 *
 * Everything the server stores is either an opaque blob or a value the design
 * document explicitly permits it to see in plaintext (Section 5.2):
 * DEVICE_ID, device_sign_pub, usernames, client salts and timing metadata.
 *
 * Sessions are NOT here — they live in Redis (design Section 3).
 */

exports.shorthands = undefined;

exports.up = (pgm) => {
  pgm.createTable('users', {
    id: { type: 'uuid', primaryKey: true, default: pgm.func('gen_random_uuid()') },
    // Stored lowercase; the app normalises before insert/lookup.
    username: { type: 'text', notNull: true, unique: true },
    // 128-bit client-side Argon2id salt. Plaintext is safe: the password never travels.
    salt: { type: 'bytea', notNull: true },
    // Encoded Argon2id hash of login_key, with its own server-generated salt.
    login_key_hash: { type: 'text', notNull: true },
    // vault_key wrapped under kek. Opaque to the server.
    wrapped_vault_key: { type: 'bytea', notNull: true },
    // Authoritative monotonic vault counter for rollback detection (Section 8).
    vault_version: { type: 'bigint', notNull: true, default: 0 },
    created_at: { type: 'timestamptz', notNull: true, default: pgm.func('now()') },
  });

  pgm.createTable('devices', {
    // 128-bit random, generated in the browser at provisioning time.
    device_id: { type: 'bytea', primaryKey: true },
    owner_user_id: {
      type: 'uuid',
      notNull: true,
      references: 'users',
      onDelete: 'CASCADE',
    },
    // Ed25519 public key (32B). Public by design — it is what lets an untrusted
    // server authenticate uploads without holding a secret.
    sign_pub: { type: 'bytea', notNull: true },
    // seq is a uint64 ((boot_epoch << 32) | msg_counter), which overflows a
    // signed bigint. numeric(20,0) holds the full range; read it as a BigInt.
    last_seq: { type: 'numeric(20,0)', notNull: true, default: 0 },
    created_at: { type: 'timestamptz', notNull: true, default: pgm.func('now()') },
  });
  pgm.createIndex('devices', 'owner_user_id');

  pgm.createTable('records', {
    id: { type: 'bigserial', primaryKey: true },
    device_id: { type: 'bytea', notNull: true, references: 'devices', onDelete: 'CASCADE' },
    seq: { type: 'numeric(20,0)', notNull: true },
    // 12B, must equal 0x00000000 || seq — server check 3 (Section 7.4).
    nonce: { type: 'bytea', notNull: true },
    ciphertext: { type: 'bytea', notNull: true },
    // Ed25519 signature (64B) over AAD || nonce || ciphertext.
    sig: { type: 'bytea', notNull: true },
    // Server receive time. The device's own timestamp is inside the ciphertext.
    created_at: { type: 'timestamptz', notNull: true, default: pgm.func('now()') },
  });
  // Belt-and-braces against replay: last_seq is the real check, this makes a
  // duplicate physically unstorable even under a race.
  pgm.addConstraint('records', 'records_device_seq_unique', {
    unique: ['device_id', 'seq'],
  });
  pgm.createIndex('records', [{ name: 'device_id' }, { name: 'seq', sort: 'DESC' }]);

  // v1 vault granularity: one blob per user (design Section 15.6 keeps this open).
  // The version lives on users.vault_version only, so the two cannot drift.
  pgm.createTable('vault_blobs', {
    user_id: { type: 'uuid', primaryKey: true, references: 'users', onDelete: 'CASCADE' },
    ciphertext: { type: 'bytea', notNull: true },
    updated_at: { type: 'timestamptz', notNull: true, default: pgm.func('now()') },
  });
};

exports.down = (pgm) => {
  pgm.dropTable('vault_blobs');
  pgm.dropTable('records');
  pgm.dropTable('devices');
  pgm.dropTable('users');
};
