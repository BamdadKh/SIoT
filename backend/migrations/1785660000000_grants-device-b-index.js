/**
 * Index `grants.device_b_id` (roadmap 4.9).
 *
 * Postgres does not index the referencing side of a foreign key automatically,
 * and until now nothing needed it: `grants` was only ever read by
 * `device_a_id` ("grants targeting this device"), which `1785650000000_grants.js`
 * already indexed.
 *
 * `DELETE /devices/:device_id` is what makes the gap matter. Both grant columns
 * cascade, so every device delete has to find the rows naming it on *either*
 * side, and without this index the `device_b_id` half is a sequential scan of
 * the whole table while holding the delete's locks.
 *
 * This is not the batching the roadmap item raises as a possibility — it is the
 * ordinary index a cascading foreign key wants, and it is cheap now and
 * expensive to discover later, when the table is big enough for the scan to be
 * felt.
 */

exports.shorthands = undefined;

exports.up = (pgm) => {
  pgm.createIndex('grants', 'device_b_id');
};

exports.down = (pgm) => {
  pgm.dropIndex('grants', 'device_b_id');
};
