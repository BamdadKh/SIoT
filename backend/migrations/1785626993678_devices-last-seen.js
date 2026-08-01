/**
 * `last_seen_at` for the device list (roadmap 4.8, design 5.6).
 *
 * Chosen over `max(created_at)` on `records`: liveness is read on every device
 * list load, `records` has no per-device index that makes `max()` cheap once a
 * device has years of history, and `last_seq` already lives on `devices` for the
 * same reason (design check 2, Section 7.4). Keeping both columns updated
 * together in the Phase 6 insert is one extra `set` clause, not a second query.
 *
 * Nullable: a freshly registered device has never uploaded a record.
 */

exports.shorthands = undefined;

exports.up = (pgm) => {
  pgm.addColumn('devices', {
    last_seen_at: { type: 'timestamptz' },
  });
};

exports.down = (pgm) => {
  pgm.dropColumn('devices', 'last_seen_at');
};
