import { useMemo } from 'react';
import { valueMatchesField } from '@siot/crypto';
import { buildDashboard, gaugePosition } from '../lib/dashboard.js';
import { formatReading } from '../lib/records.js';
import { describeSequence } from '../lib/sequence.js';

/**
 * The device's declared fields, drawn the way each one asks (roadmap 7.3).
 *
 * Rendered entirely from the schema and the records this page has opened, with
 * nothing specific to any device: a panel exists because a field was declared,
 * and which widget draws it is looked up in `WIDGETS` by the hint the 7.2
 * allowlist already vetted. A name not in that table is drawn as a plain value
 * rather than reaching for a component by name.
 *
 * The section is a `.record-list` like Readings and Fields beside it, one row per
 * field, rather than a grid of cards: the page already has one way of showing a
 * register of things, and a second would make it two designs.
 *
 * **Nothing here says "now".** Every value is the newest one among the records
 * loaded on this page and is dated by when that record reached the server, which
 * is as much as the client knows. What `dashboard.js` decides about gaps,
 * restarts and mismatched values is stated on the panel rather than drawn over.
 *
 * @param {{ state: object, schema: object|null }} props `state` is the
 *        `useDeviceRecords` state Readings is drawn from.
 */
export function DeviceDashboard({ state, schema }) {
  const panels = useMemo(
    () => (state.status === 'ok' ? buildDashboard(schema, state.records, valueMatchesField) : []),
    [state, schema],
  );

  // No schema, no dashboard: Readings already shows every value, and a panel
  // guessed from an undeclared key would be inventing a unit. Fields, below,
  // says where a dashboard comes from. Before any record there is nothing a
  // panel could show but a row of absences, and Readings already says so.
  if (panels.length === 0 || state.records.length === 0) return null;

  return (
    <section className="device-section">
      <h2 className="h3">Dashboard</h2>
      <p className="prose section-lede">
        The newest value of each declared field among the {state.records.length}{' '}
        {state.records.length === 1 ? 'record' : 'records'} loaded below, dated by when it reached
        the server. A server can hold back newer records, so this is the latest this browser has
        seen, not necessarily the latest the device sent.
      </p>

      <ol className="record-list">
        {panels.map((panel) => (
          <Panel key={panel.field.key} panel={panel} />
        ))}
      </ol>
    </section>
  );
}

/** Which component draws each widget hint. Lookup only, never a name from data. */
const WIDGETS = {
  value: ValueWidget,
  graph: GraphWidget,
  gauge: GaugeWidget,
  toggle: ToggleWidget,
};

/** How a declared type reads in a sentence, matching Readings. */
const TYPE_NAMES = { number: 'a number', boolean: 'on or off', text: 'text' };

function Panel({ panel }) {
  const { field, latest } = panel;
  const Widget = Object.hasOwn(WIDGETS, field.widget) ? WIDGETS[field.widget] : ValueWidget;

  let body;
  if (!latest) {
    body = <p className="dash-absent">Not in the records loaded here.</p>;
  } else if (latest.mismatch && field.widget !== 'graph') {
    // Drawn as what it is, the way Readings draws it: a needle or a switch for a
    // value of the wrong type would be the widget inventing a reading. A graph
    // still draws, since its history is more than the newest value.
    body = <Mismatch field={field} value={latest.value} />;
  } else {
    body = <Widget panel={panel} />;
  }

  return (
    <li className="record">
      <div className="record-head">
        {/* The label replaces the key and the key stays on hover, as in Readings. */}
        <span className="dash-label" title={field.label ? field.key : undefined}>
          {field.label ?? field.key}
        </span>
        {latest ? (
          <span className="record-when" title={describeSequence(latest.seq) ?? latest.seq}>
            {formatArrival(latest.receivedAt)}
          </span>
        ) : null}
      </div>
      <div className="dash-body">{body}</div>
    </li>
  );
}

/** The value with its unit, the number in the machine's face and the unit in the owner's. */
function Reading({ field, value }) {
  return (
    <p className="dash-value mono">
      {formatReading(value)}
      {field.unit ? <span className="record-unit"> {field.unit}</span> : null}
    </p>
  );
}

/** A value that is not its declared type, shown as what it is. */
function Mismatch({ field, value }) {
  return (
    <div>
      <p className="dash-value mono">{formatReading(value)}</p>
      <p className="record-mismatch">Declared as {TYPE_NAMES[field.type]}</p>
    </div>
  );
}

function ValueWidget({ panel }) {
  return <Reading field={panel.field} value={panel.latest.value} />;
}

/* --- graph ---------------------------------------------------------------- */

/** The drawing's own coordinate space; the SVG stretches it to the column. */
const GRAPH_WIDTH = 1000;
const GRAPH_HEIGHT = 160;
/** Keeps a point at the range's edge from having half its stroke clipped. */
const GRAPH_INSET = 6;

/**
 * A time series that is not spaced by time. Each step along the axis is one
 * record, because `seq` is the only order the client trusts; the two ends are
 * dated by arrival so the span is still legible. Where the sequence breaks, the
 * line stops.
 */
function GraphWidget({ panel }) {
  const { field, latest, series } = panel;
  const { segments, span, low, high, points, breaks, mismatched } = series;

  const x = (index) => (span <= 1 ? GRAPH_WIDTH / 2 : (index / (span - 1)) * GRAPH_WIDTH);
  const y = (value) =>
    GRAPH_HEIGHT - GRAPH_INSET - ((value - low) / (high - low)) * (GRAPH_HEIGHT - 2 * GRAPH_INSET);

  // A segment of one point is a dot: a zero-length line with a round cap, which
  // survives the non-uniform stretch where a <circle> would turn into an ellipse.
  const paths = segments.map((segment) =>
    segment.length === 1
      ? `M${x(segment[0].x)} ${y(segment[0].y)}l0 0`
      : segment
          .map((point, index) => `${index === 0 ? 'M' : 'L'}${x(point.x)} ${y(point.y)}`)
          .join(''),
  );

  // Each break is marked where it falls, halfway between the two points either
  // side of it, so a break one record wide is not lost in the stroke.
  const breakAt = segments
    .slice(1)
    .map((segment, index) => (x(segments[index].at(-1).x) + x(segment[0].x)) / 2);

  const notes = [];
  if (breaks > 0) {
    notes.push(
      `The line breaks ${breaks === 1 ? 'once' : `${breaks} times`}, at each dashed mark: ` +
        'records missing from the sequence, a restart, or a record that would not open.',
    );
  }
  if (mismatched > 0) {
    notes.push(
      `${mismatched === 1 ? 'One value was' : `${mismatched} values were`} not a number and ` +
        `${mismatched === 1 ? 'is' : 'are'} left off.`,
    );
  }

  return (
    <div className="stack stack-3">
      {latest.mismatch ? (
        <Mismatch field={field} value={latest.value} />
      ) : (
        <Reading field={field} value={latest.value} />
      )}

      <figure className="dash-graph">
        <div className="dash-graph-plot">
          <div className="dash-graph-scale mono" aria-hidden="true">
            <span>{formatScale(high)}</span>
            <span>{formatScale(low)}</span>
          </div>
          <svg
            className="dash-graph-svg"
            viewBox={`0 0 ${GRAPH_WIDTH} ${GRAPH_HEIGHT}`}
            preserveAspectRatio="none"
            role="img"
            aria-label={`${points} ${points === 1 ? 'value' : 'values'} of ${field.label ?? field.key}, oldest to newest`}
          >
            <line className="dash-graph-rule" x1="0" x2={GRAPH_WIDTH} y1="0.5" y2="0.5" />
            <line
              className="dash-graph-rule"
              x1="0"
              x2={GRAPH_WIDTH}
              y1={GRAPH_HEIGHT - 0.5}
              y2={GRAPH_HEIGHT - 0.5}
            />
            {breakAt.map((at, index) => (
              <line
                key={`break-${index}`}
                className="dash-graph-break"
                x1={at}
                x2={at}
                y1="0"
                y2={GRAPH_HEIGHT}
              />
            ))}
            {paths.map((d, index) => (
              <path key={index} className="dash-graph-line" d={d} />
            ))}
          </svg>
        </div>
        <figcaption className="dash-graph-axis small">
          <span>{span === 1 ? 'One record' : `${span} records, oldest first`}</span>
          <span>Spaced by record, not by time</span>
        </figcaption>
      </figure>

      {notes.length > 0 ? <p className="small">{notes.join(' ')}</p> : null}
    </div>
  );
}

/**
 * The ends of a graph's range. Four significant digits: the scale says roughly
 * where the line sits, and the exact value is the headline above it.
 */
function formatScale(value) {
  return String(Number(value.toPrecision(4)));
}

/* --- gauge ---------------------------------------------------------------- */

const GAUGE_RADIUS = 42;
const GAUGE_CENTRE = { x: 50, y: 50 };

/** A point on the dial, `fraction` of the way from the minimum at the left. */
function dialPoint(fraction) {
  const angle = Math.PI * (1 - fraction);
  return {
    x: GAUGE_CENTRE.x + GAUGE_RADIUS * Math.cos(angle),
    y: GAUGE_CENTRE.y - GAUGE_RADIUS * Math.sin(angle),
  };
}

/**
 * A half dial between the declared minimum and maximum. The needle cannot leave
 * the dial, so a value outside the range is pinned to the end it passed and
 * the panel says so in words; otherwise the gauge would be showing the limit as
 * the reading.
 */
function GaugeWidget({ panel }) {
  const { field, latest } = panel;
  const { fraction, outside } = gaugePosition(field, latest.value);
  const start = dialPoint(0);
  const end = dialPoint(1);
  const at = dialPoint(fraction);
  const arc = (to) =>
    `M${start.x} ${start.y}A${GAUGE_RADIUS} ${GAUGE_RADIUS} 0 0 1 ${to.x} ${to.y}`;

  return (
    <div className="dash-gauge">
      <figure className="dash-gauge-dial">
        <svg
          viewBox="0 0 100 56"
          role="img"
          aria-label={`${formatReading(latest.value)} on a dial from ${formatReading(field.min)} to ${formatReading(field.max)}`}
        >
          <path className="dash-gauge-track" d={arc(end)} />
          {fraction > 0 ? <path className="dash-gauge-fill" d={arc(at)} /> : null}
        </svg>
        <figcaption className="dash-gauge-range mono" aria-hidden="true">
          <span>{formatReading(field.min)}</span>
          <span>{formatReading(field.max)}</span>
        </figcaption>
      </figure>

      <div className="stack stack-3">
        <Reading field={field} value={latest.value} />
        {outside ? (
          <p className="small">
            {outside === 'above'
              ? `Above the dial, which ends at ${formatReading(field.max)}.`
              : `Below the dial, which starts at ${formatReading(field.min)}.`}
          </p>
        ) : null}
      </div>
    </div>
  );
}

/* --- toggle --------------------------------------------------------------- */

/**
 * State as the device last reported it, and only that. Drawn as a switch
 * because that is what the field declared, in ink rather than olive and with no
 * pointer, since it cannot be pressed: sending to a device is Phase 11's command
 * channel (roadmap 11.5), and a control that looked live and did nothing would
 * be worse than one that says it is not built.
 */
function ToggleWidget({ panel }) {
  const on = panel.latest.value === true;
  return (
    <div className="stack stack-3">
      <p className="dash-switch-row">
        <span className={on ? 'dash-switch dash-switch-on' : 'dash-switch'} aria-hidden="true">
          <span className="dash-switch-knob" />
        </span>
        <span className="dash-value">{on ? 'On' : 'Off'}</span>
      </p>
      <p className="small ink-faint">As reported. Switching it from here is not built yet.</p>
    </div>
  );
}

/** Exact rather than relative, for the reason `DeviceReadings` gives. */
function formatArrival(receivedAt) {
  const when = new Date(receivedAt);
  if (!Number.isFinite(when.getTime())) return 'At an unreadable time';
  return when.toLocaleString();
}
