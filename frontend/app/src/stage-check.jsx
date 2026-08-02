// THROWAWAY SCAFFOLDING (CLAUDE.md rule 4). Delete with serial-check.html.
//
// AddDevice's stages, side by side with fixed props, so the layout can be
// judged without a session, an unlocked vault and a board plugged in. Reaching
// them through the real screen means getting past three gates first, and the
// states worth looking at hardest (an occupied board, a half-finished add) are
// the ones that are most awkward to reach on purpose.
import { createRoot } from 'react-dom/client';

import '@fontsource-variable/archivo/standard.css';
import '@fontsource/martian-mono/400.css';
import './styles/tokens.css';
import './styles/base.css';

import { Plate } from './components/Plate.jsx';
import { Field } from './components/Field.jsx';
import { SubmitButton } from './components/SubmitButton.jsx';

// base.css pins html/body/#root to 100% so `.plate-center` can centre against the
// viewport. This page stacks more than a viewport of plates, so it opts out.
for (const node of [document.documentElement, document.body, document.getElementById('root')]) {
  node.style.height = 'auto';
}

function Frame({ label, children }) {
  return (
    <div>
      <p className="mono" style={{ marginBottom: 'var(--sp-3)' }}>
        {label}
      </p>
      <Plate>
        <div className="wordmark" style={{ marginBottom: 'var(--sp-5)' }}>
          SIoT
        </div>
        <h1 className="h1">Add a device</h1>
        <p className="prose" style={{ marginTop: 'var(--sp-3)' }}>
          The name is stored in your vault, encrypted, and never reaches the server. Neither
          does the device&rsquo;s secret: it goes from this page straight to the board over USB.
        </p>
        <div style={{ marginTop: 'var(--sp-5)' }}>
          <Field label="Device name" value="Greenhouse humidity" onChange={() => {}} />
        </div>
        {children}
        <hr className="rule" style={{ margin: 'var(--sp-6) 0 18px' }} />
        <div className="row spread">
          <span className="small">
            Signed in as <span className="mono">bamdad</span>
          </span>
          <div className="row" style={{ gap: 'var(--sp-4)' }}>
            <a className="button button-link" href="#">
              Devices
            </a>
            <button className="button button-link" type="button">
              Sign out
            </button>
          </div>
        </div>
      </Plate>
    </div>
  );
}

createRoot(document.getElementById('root')).render(
  <div
    style={{
      display: 'flex',
      gap: '32px',
      alignItems: 'flex-start',
      padding: '32px',
      flexWrap: 'wrap',
    }}
  >
    <Frame label="1 · naming">
      <div style={{ marginTop: 'var(--sp-5)' }}>
        <SubmitButton>Connect board</SubmitButton>
      </div>
      <p className="small" style={{ margin: 'var(--sp-4) 0 0' }}>
        Not an ESP32, or no board to hand?{' '}
        <button className="button button-link" type="button">
          Add it without one
        </button>
      </p>
    </Frame>

    <Frame label="2 · board blank">
      <p className="board-note" style={{ marginTop: 'var(--sp-4)' }}>
        This board has no credentials on it. Ready to provision.
      </p>
      <div style={{ marginTop: 'var(--sp-5)' }}>
        <SubmitButton>Write to board</SubmitButton>
      </div>
      <p className="small" style={{ margin: 'var(--sp-4) 0 0' }}>
        Wrong board?{' '}
        <button className="button button-link" type="button">
          Disconnect
        </button>
      </p>
    </Frame>

    <Frame label="2 · board occupied">
      <div className="alarm" style={{ marginTop: 'var(--sp-4)' }} role="alert">
        <strong>This board already belongs to another device.</strong>
        <p style={{ margin: 'var(--sp-2) 0 0' }}>
          It is holding <strong>Greenhouse humidity</strong> (
          <span className="mono">AAECAw&hellip;DA0ODw</span>). Writing over it would leave that
          device reporting under credentials nothing can decrypt, permanently. Nothing has been
          changed. Use a different board, or re-provision that device from its own entry in
          Devices.
        </p>
      </div>
      <p className="small" style={{ margin: 'var(--sp-4) 0 0' }}>
        Finished with this board?{' '}
        <button className="button button-link" type="button">
          Disconnect
        </button>
      </p>
    </Frame>

    <Frame label="3 · written">
      <div className="success" style={{ marginTop: 'var(--sp-5)' }} role="status">
        <strong>Greenhouse humidity</strong> is in your vault, registered, and written to the
        board. It will start reporting once it is running firmware that uses those credentials.
      </div>
    </Frame>

    <Frame label="3 · added, no board">
      <div className="board-note" style={{ marginTop: 'var(--sp-5)' }} role="status">
        <strong>Greenhouse humidity</strong> is in your vault and registered. Its credentials
        have not reached any hardware yet, so it will show in Devices as never having reported.
        Provision an ESP32 from this page when you have one to hand, or, for other hardware,
        read the credentials out once revealing them is built.
      </div>
    </Frame>

    <Frame label="1 · no Web Serial">
      <p className="board-note" style={{ marginTop: 'var(--sp-4)' }}>
        This browser cannot talk to a board. Writing credentials over USB needs Web Serial,
        which today means a Chromium browser: Chrome, Edge or Opera on desktop.
      </p>
      <div style={{ marginTop: 'var(--sp-5)' }}>
        <SubmitButton>Add device</SubmitButton>
      </div>
    </Frame>
  </div>,
);
