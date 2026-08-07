import { useEffect, useState } from 'react';

/**
 * The wire protocol, published so that a revealed secret is half of an answer
 * rather than a dead end (roadmap 4.7). Opened only on a click, never fetched:
 * nothing on any screen in this app may reach a third party on load, and a
 * documentation link that did would be telling GitHub who is provisioning a
 * device and when.
 */
export const PROTOCOL_DOC_URL = 'https://github.com/BamdadKh/SIoT/blob/main/docs/protocol.md';

/** How long "Copied" stays up before the control goes back to offering the copy. */
const COPIED_MS = 2500;

/**
 * Reveal credentials: the deliberate escape hatch (design 5.3.1, roadmap 4.6).
 *
 * It exists because the protocol in `docs/protocol.md` is an invitation with no
 * key attached without it. Someone writing their own client for hardware that is
 * not an ESP32 has to be able to get `DEVICE_ID` and `DEVICE_SECRET` out, and
 * the alternative to a control that does it honestly is people pulling the blob
 * out of the vault by hand, which is the same exposure with none of the warnings.
 *
 * **It is an escape hatch and must not be shaped like a path.** Design 5.3.1
 * fixes the shape and this follows it exactly:
 *
 * - Reached by an intentional action on a device that already exists. Nothing in
 *   setup routes through here, and `AddDevice` links to a device's page rather
 *   than offering this inline.
 * - It reveals on demand and does not stay revealed. The state is local to this
 *   component, so leaving the page hides it; switching away from the tab hides
 *   it; and it never persists anywhere, because past this button there is
 *   nowhere it could persist to that would still be inside the guarantees.
 * - It states its costs at the moment of revealing, not in documentation nobody
 *   opens. That is the `.alarm` panel below, and it is the same shape the delete
 *   confirmation and the occupied-board override use, because all three are one
 *   thing: a warning attached to a deliberate act, at the moment of the act.
 *
 * What it deliberately does not do is dress the values as a step in a flow.
 * There is no "next", no primary button, and no completion state: past this
 * point the guarantees in the design document genuinely stop, and a screen that
 * made that look routine would be misrepresenting where the boundary is.
 */
export function RevealCredentials({ device, entry }) {
  const [revealed, setRevealed] = useState(false);

  /*
   * "Does not stay revealed", taken literally. Two triggers, and neither is a
   * timer: a countdown that yanks the value away mid-transcription is a UI
   * people work around by screenshotting it, which is a strictly worse place
   * for a secret to end up than the screen it was on.
   *
   * The device changing underneath is the same reasoning that disarms the delete
   * confirmation: what was revealed was a decision about *this* device.
   */
  useEffect(() => setRevealed(false), [device.id]);

  useEffect(() => {
    if (!revealed) return undefined;
    const hide = () => {
      if (document.hidden) setRevealed(false);
    };
    document.addEventListener('visibilitychange', hide);
    return () => document.removeEventListener('visibilitychange', hide);
  }, [revealed]);

  return (
    <section className="device-section">
      <h2 className="h3">Credentials</h2>
      <p className="prose section-lede">
        Everything this device needs to produce records the server will accept. The guided flow
        writes them over USB and no copy is made; reading them here is for hardware that flow
        cannot reach, and it is the point at which the guarantees below stop being ours to make.
      </p>

      {revealed ? (
        <Revealed entry={entry} onHide={() => setRevealed(false)} />
      ) : (
        <p className="small">
          Writing your own client for other hardware?{' '}
          <button className="button button-link" type="button" onClick={() => setRevealed(true)}>
            Reveal credentials
          </button>
        </p>
      )}
    </section>
  );
}

/**
 * The values, under the three costs design 5.3.1 names.
 *
 * The costs are above the values rather than below them: they are the reason the
 * control is shaped this way, and a warning under the thing it warns about is a
 * warning read after the decision it was for.
 */
function Revealed({ entry, onHide }) {
  return (
    <div className="stack stack-4">
      <div className="alarm" role="alert">
        <strong>These two values are the whole device.</strong>
        <p>
          Anything holding them can read every reading this device has ever uploaded and sign new
          ones the server will accept as genuine. Copying puts them on the clipboard and then
          wherever they go next: a synced editor, a backup, a stray commit. Nothing in this
          product reaches any of those places.
        </p>
        <p>
          There is no overwrite protection out here either. The board check that refuses to
          provision over another device only exists inside the USB flow; written by hand, these
          can land on hardware that already carries a working device and orphan it. Where they
          come to rest, and whether they survive a firmware update, is now yours to arrange.
        </p>
      </div>

      <div className="stack stack-4">
        <Credential label="DEVICE_ID" value={entry.id} />
        <Credential label="DEVICE_SECRET" value={entry.secret} />
      </div>

      <p className="small">
        Both are base64url. What to do with them is{' '}
        <a href={PROTOCOL_DOC_URL} target="_blank" rel="noreferrer">
          the wire protocol
        </a>
        : the HKDF labels that split the secret, the AEAD parameters, how the nonce is built, and
        the three checks the server runs. A port that follows it is accepted on exactly the same
        terms as the ESP32 library, because the server has no notion of a blessed client.
      </p>

      <p className="small">
        Finished with them?{' '}
        <button className="button button-link" type="button" onClick={onHide}>
          Hide them
        </button>{' '}
        &mdash; they also hide when you leave this page or switch away from this tab.
      </p>
    </div>
  );
}

/** One value, its label, and the copy control design 5.3.1 asks for. */
function Credential({ label, value }) {
  const [copied, setCopied] = useState(false);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    if (!copied) return undefined;
    const timer = setTimeout(() => setCopied(false), COPIED_MS);
    return () => clearTimeout(timer);
  }, [copied]);

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(value);
      setFailed(false);
      setCopied(true);
    } catch {
      // Clipboard access can be refused outright, and a control that silently
      // did nothing would leave someone pasting whatever was there before.
      setFailed(true);
      setCopied(false);
    }
  }

  return (
    <div className="field">
      <span className="field-label">{label}</span>
      <div className="credential-value">
        <span className="credential-text">{value}</span>
        <button
          className="button button-link credential-copy"
          type="button"
          onClick={handleCopy}
          aria-label={`Copy ${label}`}
        >
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
      {failed ? (
        <span className="small device-note-error" role="alert">
          This browser refused the clipboard. Select the value and copy it by hand.
        </span>
      ) : null}
    </div>
  );
}
