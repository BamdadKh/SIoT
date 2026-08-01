import { useEffect, useState } from 'react';
import { decryptVault, fromBase64Url } from '@siot/crypto';
import { fetchVault } from '../lib/api.js';
import { getVaultKey } from '../lib/keyring.js';
import { getHighWaterMark, setHighWaterMark } from '../lib/vault-version-store.js';
import { TopBar } from '../components/TopBar.jsx';

/**
 * The signed-in, unlocked home.
 *
 * There is no "Add device" control yet on purpose: pairing is Phase 4 and a
 * button that leads nowhere is worse than none. The empty state says what the
 * next step will be, and the control lands beside the heading when it works.
 *
 * The copy names the one supported flow (design 5.3): plug an ESP32 in and the
 * browser writes its credentials over Web Serial. It deliberately does not
 * mention revealing credentials for other hardware; that is an escape hatch
 * reached from a device that already exists (5.3.1), and an empty state is
 * exactly where it would get mistaken for a second way to start.
 *
 * Once 4.8 lands this stops being the only thing on the screen: devices appear
 * here with the name their owner gave them (which lives in the vault, never on
 * the server) and when each was last heard from.
 *
 * On mount it does the roadmap 3.2 rollback check: fetch the vault, compare its
 * version against the IndexedDB high-water mark, and refuse to go further if
 * the server just handed back something older than what this browser has
 * already seen. That is the one class of tampering neither the AAD nor the
 * plaintext envelope in `vault.js` can catch on their own: both are satisfied
 * by an old blob that is *honestly* labelled with its own old version.
 */
export function Devices({ username, onSignOut, signingOut }) {
  const [vault, setVault] = useState({ status: 'checking' });

  useEffect(() => {
    let live = true;

    (async () => {
      try {
        const vaultKey = getVaultKey();
        const [{ vault_version: serverVersion, ciphertext }, cached] = await Promise.all([
          fetchVault(),
          getHighWaterMark(username),
        ]);

        if (serverVersion < cached) {
          if (live) setVault({ status: 'rollback', serverVersion, cached });
          return;
        }

        // Confirms the blob actually opens under this version before trusting
        // it enough to raise the high-water mark. A never-written vault has no
        // blob to check and version 0, which cannot regress anything.
        if (ciphertext !== null) {
          await decryptVault(fromBase64Url(ciphertext), vaultKey, serverVersion);
        }

        await setHighWaterMark(username, serverVersion);
        if (live) setVault({ status: 'ok' });
      } catch (err) {
        if (live) setVault({ status: 'error', message: err.message });
      }
    })();

    return () => {
      live = false;
    };
  }, [username]);

  return (
    <>
      <TopBar username={username} onSignOut={onSignOut} signingOut={signingOut} />
      <main className="page">
        <div className="page-head">
          <h1 className="h2">Devices</h1>
        </div>

        {vault.status === 'rollback' ? (
          <section className="rollback-warning">
            <span className="tick tick-tl" />
            <span className="tick tick-tr" />
            <span className="tick tick-bl" />
            <span className="tick tick-br" />
            <h2 className="h3">This vault went backwards</h2>
            <p className="prose" style={{ marginTop: 'var(--sp-3)' }}>
              The server just returned vault version{' '}
              <span className="mono">{vault.serverVersion}</span>, but this browser has already
              seen version <span className="mono">{vault.cached}</span>. That can only happen if
              the server served an old copy of your vault, either by mistake or on purpose.
              Nothing has been decrypted or trusted.
            </p>
            <p className="prose" style={{ marginTop: 'var(--sp-3)' }}>
              Do not make changes to devices or credentials from this browser until this is
              resolved.
            </p>
          </section>
        ) : null}

        {vault.status === 'error' ? (
          <p className="alarm" role="alert">
            Could not check the vault: {vault.message}
          </p>
        ) : null}

        {vault.status === 'ok' ? (
          <section className="slot">
            <span className="tick tick-tl" />
            <span className="tick tick-tr" />
            <span className="tick tick-bl" />
            <span className="tick tick-br" />
            <h2 className="h3">No devices yet</h2>
            <p className="prose">Plug an ESP32 in over USB to set one up.</p>
          </section>
        ) : null}
      </main>
    </>
  );
}
