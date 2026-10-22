import { useRef, useState } from 'react';
import {
  buildSchema,
  setDeviceSchema,
  SCHEMA_KEY_MAX_LENGTH,
  SCHEMA_LABEL_MAX_LENGTH,
  SCHEMA_MAX_FIELDS,
  SCHEMA_UNIT_MAX_LENGTH,
  SCHEMA_WIDGETS,
} from '@siot/crypto';
import { ApiError } from '../lib/api.js';
import { loadVault, storeVault, VaultRollbackError } from '../lib/vault-store.js';
import { Field } from './Field.jsx';
import { Choice } from './Choice.jsx';

/** What each type is called on screen. The stored names are the allowlist's. */
const TYPE_LABELS = { number: 'Number', boolean: 'On or off', text: 'Text' };
const WIDGET_LABELS = { value: 'Value', graph: 'Graph', gauge: 'Gauge', toggle: 'Switch' };

/**
 * What this device's readings mean (roadmap 7.1).
 *
 * **Declared here, on the device's own page, rather than during Add device.**
 * The roadmap says "at pairing time", and that is the one moment a schema
 * cannot be checked against anything: the sketch has not run, so every key would
 * be typed from memory, and a key off by one character is a field that silently
 * never fills. Here the form starts from the keys the device has actually sent
 * (`observed`), and a key it has not sent yet can still be added by name.
 *
 * Saving is an ordinary vault write, built the way the rename beside it is: the
 * vault is re-read immediately before writing, and the stored fields are shown
 * back rather than the draft. `setDeviceSchema` validates strictly at the last
 * point before sealing, which is the 7.2 allowlist; the form's own checks are
 * for the person, not for safety.
 *
 * @param {{ username: string, entry: { id: string, schema?: object },
 *           observed: Array<{ key: string, type: string }>, reload: () => Promise<void> }} props
 */
export function DeviceFields({ username, entry, observed, reload }) {
  // Stored fields get ids from their position, new ones from a counter, so the
  // inputs keep their identity across renders before and after the first edit.
  const nextRowId = useRef(0);
  const makeRow = (field) => {
    nextRowId.current += 1;
    return { rowId: `new-${nextRowId.current}`, ...field };
  };

  const stored = entry.schema?.fields ?? [];
  const [draft, setDraft] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [saved, setSaved] = useState(false);

  // Drafts are made lazily from what is stored, so a reload after someone
  // else's save shows the new fields until this tab starts editing.
  const rows = draft ?? stored.map((field, index) => ({ rowId: `stored-${index}`, ...toRow(field, false) }));
  const changed =
    draft !== null &&
    JSON.stringify(draft.map(toField)) !==
      JSON.stringify(stored.map((field) => toField(toRow(field, false))));

  const declared = new Set(rows.map((row) => row.key));
  const undescribed = observed.filter(({ key }) => !declared.has(key));
  const full = rows.length >= SCHEMA_MAX_FIELDS;

  function edit(next) {
    setDraft(next);
    setSaved(false);
    setError(null);
  }

  function updateRow(rowId, patch) {
    edit(
      rows.map((row) => {
        if (row.rowId !== rowId) return row;
        const merged = { ...row, ...patch };
        // A widget the new type cannot be shown as goes back to the plain value
        // rather than leaving a combination the validator would refuse.
        if (!SCHEMA_WIDGETS[merged.type].includes(merged.widget)) merged.widget = 'value';
        return merged;
      }),
    );
  }

  /**
   * The order fields are listed in is the order Readings and the dashboard use,
   * so this is the whole of the layout (roadmap 7.4): it travels in the sealed
   * schema like everything else here, and there is no second document to keep in
   * step with it.
   */
  function moveRow(rowId, by) {
    const from = rows.findIndex((row) => row.rowId === rowId);
    const to = from + by;
    if (from < 0 || to < 0 || to >= rows.length) return;
    const next = [...rows];
    [next[from], next[to]] = [next[to], next[from]];
    edit(next);
  }

  function describeObserved() {
    const room = SCHEMA_MAX_FIELDS - rows.length;
    edit([
      ...rows,
      ...undescribed.slice(0, room).map(({ key, type }) =>
        makeRow(toRow({ key, type, widget: type === 'number' ? 'graph' : 'value' }, false)),
      ),
    ]);
  }

  function addByName() {
    edit([...rows, makeRow(toRow({ key: '', type: 'number', widget: 'value' }, true))]);
  }

  async function handleSubmit(event) {
    event.preventDefault();
    if (busy || !changed) return;

    let fields;
    try {
      // Checked before the network, so a field the allowlist refuses names
      // itself without a vault read in between.
      fields = rows.map(toField);
      buildSchema(fields);
    } catch (failure) {
      setError(failure.message);
      return;
    }

    setBusy(true);
    setError(null);
    try {
      const { version, document } = await loadVault(username);
      await storeVault(username, version, setDeviceSchema(document, entry.id, fields));
      setDraft(null);
      setSaved(true);
      await reload();
    } catch (failure) {
      setError(describe(failure));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="device-section">
      <h2 className="h3">Fields</h2>
      <p className="prose section-lede">
        What each reading is: what to call it, its unit, and how to show it. Stored in your vault
        beside this device&rsquo;s secret, so the server cannot tell a thermometer from a door
        sensor. Once the device sends a declared field, the dashboard above draws it, in the order listed here.
      </p>

      <form className="stack stack-4" onSubmit={handleSubmit}>
        {rows.length === 0 ? (
          <p className="board-note">
            <strong>No fields declared.</strong> Readings show under the names the device sends.
          </p>
        ) : (
          <ol className="record-list">
            {rows.map((row, index) => (
              <FieldRow
                key={row.rowId}
                row={row}
                disabled={busy}
                onMoveUp={index > 0 ? () => moveRow(row.rowId, -1) : null}
                onMoveDown={index < rows.length - 1 ? () => moveRow(row.rowId, 1) : null}
                onChange={(patch) => updateRow(row.rowId, patch)}
                onRemove={() => edit(rows.filter((other) => other.rowId !== row.rowId))}
              />
            ))}
          </ol>
        )}

        {undescribed.length > 0 && !full ? (
          <p className="small">
            {undescribed.length === 1 ? 'One reading' : `${undescribed.length} readings`} this device
            has sent {undescribed.length === 1 ? 'has' : 'have'} no field:{' '}
            {undescribed.map(({ key }, index) => (
              <span key={key}>
                {index > 0 ? ', ' : null}
                <span className="mono">{key}</span>
              </span>
            ))}
            .{' '}
            <button className="button button-link" type="button" onClick={describeObserved} disabled={busy}>
              Describe {undescribed.length === 1 ? 'it' : 'them'}
            </button>
          </p>
        ) : null}

        {!full ? (
          <p className="small">
            Expecting a reading it has not sent yet?{' '}
            <button className="button button-link" type="button" onClick={addByName} disabled={busy}>
              Add a field by name
            </button>
          </p>
        ) : null}

        {error ? (
          <p className="alarm" role="alert">
            {error}
          </p>
        ) : null}

        {saved && !changed ? (
          <p className="success" role="status">
            Saved. The fields are in your vault.
          </p>
        ) : null}

        <div>
          <button className="button button-inline" type="submit" disabled={busy || !changed}>
            {busy ? 'Saving' : 'Save fields'}
          </button>
        </div>
      </form>
    </section>
  );
}

/**
 * One declared field. The key is the device's and is shown as such, in mono, at
 * the head of the row; changing it is removing the field and adding another,
 * because a field is *about* that key. Only a field added by name has an input
 * for it, since there is nothing yet for it to be about.
 */
function FieldRow({ row, disabled, onMoveUp, onMoveDown, onChange, onRemove }) {
  return (
    <li className="record">
      <div className="record-head">
        {row.typedKey ? (
          <span className="record-seq">New field</span>
        ) : (
          <span className="mono schema-key">{row.key}</span>
        )}
        {/* Moves are offered only where there is somewhere to move to, rather
            than as a faint control that does nothing at the ends. */}
        <span className="row row-links">
          {onMoveUp ? (
            <button className="button button-link" type="button" onClick={onMoveUp} disabled={disabled} aria-label={`Move ${row.key || 'this field'} up`}>
              Up
            </button>
          ) : null}
          {onMoveDown ? (
            <button className="button button-link" type="button" onClick={onMoveDown} disabled={disabled} aria-label={`Move ${row.key || 'this field'} down`}>
              Down
            </button>
          ) : null}
          <button className="button button-link" type="button" onClick={onRemove} disabled={disabled}>
            Remove
          </button>
        </span>
      </div>

      <div className="schema-grid">
        {row.typedKey ? (
          <Field
            label="Reading name"
            value={row.key}
            onChange={(key) => onChange({ key })}
            disabled={disabled}
            maxLength={SCHEMA_KEY_MAX_LENGTH}
            spellCheck={false}
            autoComplete="off"
          />
        ) : null}

        <Field
          label="Label"
          value={row.label}
          onChange={(label) => onChange({ label })}
          disabled={disabled}
          maxLength={SCHEMA_LABEL_MAX_LENGTH}
          placeholder={row.key || undefined}
        />

        <Choice
          label="Type"
          value={row.type}
          options={Object.keys(SCHEMA_WIDGETS).map((type) => [type, TYPE_LABELS[type]])}
          onChange={(type) => onChange({ type })}
          disabled={disabled}
        />

        <Choice
          label="Show as"
          value={row.widget}
          options={SCHEMA_WIDGETS[row.type].map((widget) => [widget, WIDGET_LABELS[widget]])}
          onChange={(widget) => onChange({ widget })}
          disabled={disabled}
        />

        {row.type === 'number' ? (
          <Field
            label="Unit"
            value={row.unit}
            onChange={(unit) => onChange({ unit })}
            disabled={disabled}
            maxLength={SCHEMA_UNIT_MAX_LENGTH}
          />
        ) : null}

        {row.widget === 'gauge' ? (
          <>
            <Field
              label="Gauge from"
              type="number"
              step="any"
              value={row.min}
              onChange={(min) => onChange({ min })}
              disabled={disabled}
            />
            <Field
              label="Gauge to"
              type="number"
              step="any"
              value={row.max}
              onChange={(max) => onChange({ max })}
              disabled={disabled}
            />
          </>
        ) : null}
      </div>
    </li>
  );
}

/** A stored field as the strings the inputs hold. */
function toRow(field, typedKey) {
  return {
    typedKey,
    key: field.key,
    label: field.label ?? '',
    type: field.type,
    widget: field.widget,
    unit: field.unit ?? '',
    min: field.min === undefined ? '' : String(field.min),
    max: field.max === undefined ? '' : String(field.max),
  };
}

/**
 * The inputs back into the shape the validator reads. Gauge bounds that do not
 * parse go through as `NaN` so the validator names them, rather than being
 * quietly read as absent.
 */
function toField(row) {
  const field = { key: row.key, type: row.type, widget: row.widget };
  if (row.label.trim()) field.label = row.label;
  if (row.type === 'number' && row.unit.trim()) field.unit = row.unit;
  if (row.widget === 'gauge') {
    field.min = row.min.trim() === '' ? NaN : Number(row.min);
    field.max = row.max.trim() === '' ? NaN : Number(row.max);
  }
  return field;
}

function describe(failure) {
  if (failure instanceof VaultRollbackError) {
    return (
      `The server returned vault version ${failure.serverVersion} when this browser has already ` +
      `seen ${failure.cachedVersion}. The fields were not changed. Open Devices to see the ` +
      `warning in full.`
    );
  }
  if (failure instanceof ApiError) {
    if (failure.status === 401) return 'Your session ended. Sign in again; the fields were not changed.';
    if (failure.status === 409) {
      return 'Your vault changed in another tab, so this write was refused. Reload and try again.';
    }
    if (failure.status === 0) return 'Could not reach the server. The fields were not changed.';
    return `${failure.message}. The fields were not changed.`;
  }
  return failure?.message ?? 'Could not save the fields.';
}
