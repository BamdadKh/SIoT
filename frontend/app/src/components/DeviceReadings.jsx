import { arrangeReadings } from '@siot/crypto';
import {
  describeDeviceTime,
  describeStepText,
  formatReading,
  readPayload,
  sequenceSteps,
} from '../lib/records.js';
import { describeSequence } from '../lib/sequence.js';

/**
 * What the device actually said (roadmap 6.3).
 *
 * The first screen in the product where the zero-knowledge claim is visible
 * rather than argued: every value below came off the server as ciphertext and
 * was opened here with a key derived from the `DEVICE_SECRET` in the vault. The
 * server has the same bytes and cannot do this.
 *
 * **This is not the dashboard.** The section above it is where a schema's widget hints
 * become graphs and gauges. What a declared field changes here is only its
 * label, its unit and its place in the row (`arrangeReadings`); a reading no
 * field describes is still a key and a value, since anything more would mean
 * guessing at units. A value of a kind this does not understand is said so
 * plainly.
 *
 * Readings keep the order they arrive in on the wire, which is not necessarily
 * the order a sketch called `addReading` in: nothing verifies a payload's
 * encoding, so a device may sort its keys and the reference encoder in
 * `cbor.js` does (deterministically, for the published vectors). Re-sorting
 * here would take that choice away from the ports that do keep a meaningful
 * order, and would buy nothing from the ones that do not.
 *
 * **Both timestamps, never collapsed into one.** The device's own `t` is inside
 * the authenticated payload but comes from a clock nothing verifies; the arrival
 * time is the server's and is only as trustworthy as the server. `seq` is the
 * sole authoritative order (design 7.1), so it is what the list is sorted by.
 */
export function DeviceReadings({ state, onLoadOlder, schema }) {

  return (
    <section className="device-section">
      <h2 className="h3">Readings</h2>
      <p className="prose section-lede">
        Fetched as ciphertext and opened in this browser with the key derived from this
        device&rsquo;s <span className="mono">DEVICE_SECRET</span>. The server stores every one of
        these and has never been able to read one.
      </p>

      {state.status === 'loading' ? (
        <p className="board-note" role="status">
          Opening records&hellip;
        </p>
      ) : null}

      {state.status === 'error' ? (
        <p className="alarm" role="alert">
          Could not read this device&rsquo;s records: {state.message}
        </p>
      ) : null}

      {state.status === 'ok' ? (
        <Opened state={state} onLoadOlder={onLoadOlder} schema={schema} />
      ) : null}
    </section>
  );
}

/** The records themselves, newest first, with what sits between them. */
function Opened({ state, onLoadOlder, schema }) {
  const { records } = state;

  if (records.length === 0) {
    return (
      <p className="board-note">
        <strong>No records yet.</strong>
        <span>
          {' '}
          Nothing has been uploaded under this device&rsquo;s identifier. A board that has been
          provisioned and flashed reports on whatever interval its sketch sets.
        </span>
      </p>
    );
  }

  const steps = sequenceSteps(records);
  const opened = records.map((record) => ({ record, read: readRecord(record) }));

  // A device with no clock says so once, not on every row: `t = 0` is a property
  // of the firmware's access to time rather than of any one record. It is worth
  // saying at all because it is the difference between "this reading is from
  // 14:32" and "this reading reached the server at 14:32".
  //
  // Judged only on records that actually opened. A page where every record
  // refused says nothing about the device's clock, and claiming it had none
  // would be inventing a fact out of an absence.
  const readable = opened.filter(({ record, read }) => !record.error && read.problem === null);
  const clockless = readable.length > 0 && readable.every(({ read }) => read.deviceTime === null);

  const rows = [];
  for (let index = records.length - 1; index >= 0; index -= 1) {
    rows.push(
      <Record
        key={records[index].seq}
        record={opened[index].record}
        read={opened[index].read}
        showDeviceTime={!clockless}
        schema={schema}
      />,
    );
    const step = steps.get(index);
    if (step) {
      rows.push(
        <li className="record-step" key={`step-${records[index].seq}`}>
          {describeStepText(step)}
        </li>,
      );
    }
  }

  return (
    <div className="stack stack-4">
      {state.unopened > 0 ? (
        <p className="unreadable">
          <strong>
            {state.unopened} of the {records.length} records loaded here would not open.
          </strong>
          <span>
            {' '}
            Each is shown in place rather than dropped, so the history stays the length the device
            actually has. A record refuses for one of four reasons and they are not distinguishable
            from here: a different key, a blob that was altered, a record moved to another
            device&rsquo;s identifier, or a nonce that disagrees with the sequence position it
            claims. Re-provisioning this device with a new{' '}
            <span className="mono">DEVICE_SECRET</span> makes everything before it read exactly like
            this, permanently, and is the ordinary explanation.
          </span>
        </p>
      ) : null}

      {clockless ? (
        <p className="board-note">
          This device reports no clock of its own, so each record is dated by when it reached the
          server. Its own ordering is exact regardless: <span className="mono">seq</span> is what
          the sequence is kept by, not time.
        </p>
      ) : null}

      <ol className="record-list">{rows}</ol>

      {state.moreError ? (
        <p className="alarm" role="alert">
          Could not load older records: {state.moreError}
        </p>
      ) : null}

      <p className="small">
        {state.exhausted ? (
          <span className="ink-faint">
            That is every record the server holds for this device.
          </span>
        ) : (
          <>
            Older records are on the server.{' '}
            <button
              className="button button-link"
              type="button"
              onClick={onLoadOlder}
              disabled={state.loadingMore}
            >
              {state.loadingMore ? 'Opening' : 'Load older'}
            </button>
          </>
        )}
      </p>
    </div>
  );
}

/**
 * One record.
 *
 * The head carries the two things that are true of it whatever is inside: where
 * it sits in the sequence, and when the server received it. The body is whatever
 * the payload said, and the ways a payload can disappoint are stated rather than
 * rendered around.
 */
function Record({ record, read: parsed, showDeviceTime, schema }) {
  if (record.error) {
    return (
      <li className="record record-refused">
        <div className="record-head">
          <span className="record-seq mono">{describeSequence(record.seq) ?? record.seq}</span>
          <span className="record-when" title={record.receivedAt}>
            {formatArrival(record.receivedAt)}
          </span>
        </div>
        <p className="record-problem">Would not open. {record.error}</p>
      </li>
    );
  }

  return (
    <li className="record">
      <div className="record-head">
        <span className="record-seq mono">{describeSequence(record.seq) ?? record.seq}</span>
        <span className="record-when" title={record.receivedAt}>
          {formatArrival(record.receivedAt)}
        </span>
      </div>

      {parsed.problem ? (
        <p className="record-problem">{parsed.problem}</p>
      ) : (
        <dl className="record-readings">
          {arrangeReadings(schema, parsed.readings).map(({ key, value, field, mismatch }) => (
            <div className="record-reading" key={key}>
              {/* A label replaces the key on screen and the key stays on hover:
                  it is still what the device sent and what the export holds. */}
              <dt title={field?.label ? key : undefined}>{field?.label ?? key}</dt>
              <dd className="mono">
                {formatReading(value)}
                {field?.unit && !mismatch ? <span className="record-unit"> {field.unit}</span> : null}
              </dd>
              {mismatch ? (
                <dd className="record-mismatch">Declared as {TYPE_NAMES[field.type]}</dd>
              ) : null}
            </div>
          ))}
        </dl>
      )}

      {parsed.unsupported.length > 0 ? (
        <p className="record-problem">
          {parsed.unsupported.length === 1
            ? `One reading (${parsed.unsupported[0]}) holds a value this version does not render.`
            : `${parsed.unsupported.length} readings (${parsed.unsupported.join(', ')}) hold values this version does not render.`}
        </p>
      ) : null}

      {showDeviceTime ? (
        <p className="record-clock small">
          Device clock: {describeDeviceTime(parsed.deviceTime)}
        </p>
      ) : null}
    </li>
  );
}

/** How a declared type reads in a sentence. */
const TYPE_NAMES = { number: 'a number', boolean: 'on or off', text: 'text' };

/** @param {{ payload: unknown, error: string|null }} record */
export function readRecord(record) {
  if (record.error) return { deviceTime: null, readings: [], unsupported: [], problem: null };
  return readPayload(record.payload);
}

/**
 * The arrival time, exact rather than relative. The device list uses relative
 * phrasing because it answers "is this thing still alive"; a run of records
 * dense enough to have gaps in it answers "when exactly", and forty rows of
 * "3 minutes ago" would say nothing.
 */
function formatArrival(receivedAt) {
  const when = new Date(receivedAt);
  if (!Number.isFinite(when.getTime())) return 'At an unreadable time';
  return when.toLocaleString();
}
