import { useEffect, useRef, useState } from 'react';
import { exportDeviceRecords } from '../lib/export-device.js';

/** The anchor the delete confirmation points at, so the offer there has somewhere to go. */
export const EXPORT_SECTION_ID = 'download';

/**
 * Downloading a device's readings (roadmap 6.4).
 *
 * Assembled here, out of records this browser fetched and opened; there is no
 * endpoint that could build it, because the server cannot read what it would
 * have to write. Nothing goes back over the network.
 *
 * **The cost is stated beside the control, not apologised for.** A file on disk
 * is outside every guarantee in the design document, the same way a revealed
 * `DEVICE_SECRET` is, but keeping your own readings is an ordinary thing to want.
 * So it is a neutral `.board-note` rather than the `.alarm` the escape hatches
 * wear, and it sits above the buttons, since a cost read after the click is a
 * cost read too late.
 *
 * **Nothing is held afterwards.** The file text lives in one local variable for
 * as long as it takes to become a `Blob`, and the object URL is revoked once the
 * download has been handed to the browser. The same "do not stay revealed" rule
 * `RevealCredentials` follows.
 */
export function ExportRecords({ entry }) {
  const [work, setWork] = useState(null);
  const [done, setDone] = useState(null);
  const [error, setError] = useState(null);
  const controller = useRef(null);

  // Leaving the page stops a walk that may be thousands of requests long.
  useEffect(() => () => controller.current?.abort(), []);

  async function handleExport(format) {
    if (work) return;
    const abort = new AbortController();
    controller.current = abort;
    setDone(null);
    setError(null);
    setWork({ format, fetched: 0, unopened: 0 });

    try {
      const file = await exportDeviceRecords(entry, {
        format,
        signal: abort.signal,
        onProgress: (progress) => {
          if (!abort.signal.aborted) setWork({ format, ...progress });
        },
      });
      if (abort.signal.aborted) return;
      saveFile(file.text, file.mime, fileName(entry, file.extension));
      setDone({ format, recordCount: file.recordCount, unopened: file.unopened });
    } catch (failure) {
      if (abort.signal.aborted) return;
      setError(failure.message);
    } finally {
      if (controller.current === abort) {
        controller.current = null;
        setWork(null);
      }
    }
  }

  function handleStop() {
    controller.current?.abort();
    controller.current = null;
    setWork(null);
  }

  return (
    <section className="device-section" id={EXPORT_SECTION_ID}>
      <h2 className="h3">Download</h2>
      <p className="prose section-lede">
        Every reading this device has uploaded, fetched and opened in this browser and written to a
        file on your machine. The server is never asked to build it and could not: it has never
        been able to read one.
      </p>

      <div className="stack stack-4">
        <p className="board-note">
          The file is plaintext. Once it is on disk it is outside your vault, copied wherever that
          machine backs up to, and nothing here can follow it or take it back.
        </p>

        {error ? (
          <p className="alarm" role="alert">
            The download stopped: {error}
          </p>
        ) : null}

        {done ? (
          <p className="success" role="status">
            Downloaded {countOf(done.recordCount)} as {done.format.toUpperCase()}.
            {done.unopened > 0 ? (
              <>
                {' '}
                {countOf(done.unopened)} would not open with this device&rsquo;s key; they are in the
                file, marked as unopened, rather than left out.
              </>
            ) : null}
          </p>
        ) : null}

        <div className="row row-links">
          <button
            className="button button-inline"
            type="button"
            onClick={() => handleExport('csv')}
            disabled={Boolean(work)}
          >
            {work?.format === 'csv' ? 'Preparing CSV' : 'Download CSV'}
          </button>
          <button
            className="button button-inline"
            type="button"
            onClick={() => handleExport('json')}
            disabled={Boolean(work)}
          >
            {work?.format === 'json' ? 'Preparing JSON' : 'Download JSON'}
          </button>
        </div>

        {work ? (
          <div className="stack stack-3">
            {/* Indeterminate on purpose: the walk does not know how many pages
                there are until it reaches the end, and a percentage would be a
                guess. The count is the honest part. */}
            <div className="work-bar" role="progressbar" aria-label="Fetching records">
              <div className="work-bar-mark" />
            </div>
            <p className="small" role="status">
              {countOf(work.fetched)} fetched and opened so far. Taking too long?{' '}
              <button className="button button-link" type="button" onClick={handleStop}>
                Stop
              </button>
            </p>
          </div>
        ) : (
          <p className="small">
            CSV opens in a spreadsheet. JSON keeps every digit and is the one to keep.
          </p>
        )}
      </div>
    </section>
  );
}

function countOf(n) {
  return `${n.toLocaleString()} ${n === 1 ? 'record' : 'records'}`;
}

/**
 * The name is the person's own, from the vault, but it is still going into a
 * filename: anything outside a plain slug is dropped rather than trusted to the
 * browser's own sanitising, and the `DEVICE_ID` stands in when nothing is left.
 */
function fileName(entry, extension) {
  const slug = (entry.name ?? '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 48);
  const date = new Date().toISOString().slice(0, 10);
  return `siot-${slug || entry.id}-${date}.${extension}`;
}

function saveFile(text, mime, name) {
  const url = URL.createObjectURL(new Blob([text], { type: `${mime};charset=utf-8` }));
  try {
    const link = document.createElement('a');
    link.href = url;
    link.download = name;
    link.click();
  } finally {
    // After the current task, so the navigation the click queued has already
    // taken the URL; revoking synchronously races it in some browsers.
    setTimeout(() => URL.revokeObjectURL(url), 0);
  }
}
