import { useState } from 'react';
import { deriveAccountKeys, fromBase64Url, unwrapVaultKey } from '@siot/crypto';
import { ApiError, fetchSalt, fetchWrappedVaultKey } from '../lib/api.js';
import { unlock } from '../lib/keyring.js';
import { Plate } from '../components/Plate.jsx';
import { Field } from '../components/Field.jsx';
import { SubmitButton } from '../components/SubmitButton.jsx';

/**
 * A live session with a sealed vault, which is the state a reload always lands
 * in. The cookie survived; `kek` did not, because it only ever existed in the
 * page that has just been thrown away.
 *
 * Note what this screen does *not* do: it never calls `/login`. The password is
 * checked by whether the derived `kek` opens the 60-byte blob, entirely on this
 * machine. A wrong password produces a GCM authentication failure here and the
 * server is never told one was attempted.
 */
export function Unlock({ username, onUnlocked, onSignOut, signingOut }) {
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(null);
  const [error, setError] = useState(null);

  async function handleSubmit(event) {
    event.preventDefault();
    setError(null);

    let loginKey = null;
    let kek = null;
    let vaultKey = null;

    try {
      setBusy('Working out your key');
      const { salt } = await fetchSalt(username);
      ({ loginKey, kek } = await deriveAccountKeys(password, fromBase64Url(salt)));

      // Only `kek` is wanted here. `login_key` is the other branch of the same
      // derivation and there is nothing to prove to the server, so it is wiped
      // immediately rather than carried around.
      loginKey.fill(0);
      loginKey = null;

      const { wrapped_vault_key: wrapped } = await fetchWrappedVaultKey();
      vaultKey = await unwrapVaultKey(fromBase64Url(wrapped), kek);

      unlock(kek, vaultKey);
      kek = null;
      vaultKey = null;

      setPassword('');
      onUnlocked();
    } catch (failure) {
      setError(describe(failure));
      setBusy(null);
    } finally {
      loginKey?.fill(0);
      kek?.fill(0);
      vaultKey?.fill(0);
    }
  }

  return (
    <Plate>
      <div className="wordmark" style={{ marginBottom: 'var(--sp-5)' }}>
        SIoT
      </div>
      <h1 className="h1">Vault locked</h1>
      <p className="prose" style={{ marginTop: 'var(--sp-3)' }}>
        Reloading cleared the key that opens your data. Enter your password to unlock it.
      </p>

      <form onSubmit={handleSubmit}>
        <div style={{ marginTop: 'var(--sp-5)' }}>
          <Field
            label="Password"
            type="password"
            value={password}
            onChange={setPassword}
            disabled={Boolean(busy)}
            autoComplete="current-password"
            autoFocus
          />
        </div>

        {error ? (
          <p className="alarm" style={{ marginTop: 'var(--sp-4)' }} role="alert">
            {error}
          </p>
        ) : null}

        <div style={{ marginTop: 'var(--sp-5)' }}>
          <SubmitButton busy={Boolean(busy)} busyLabel={busy} disabled={password.length === 0}>
            Unlock
          </SubmitButton>
        </div>
      </form>

      <hr className="rule" style={{ margin: 'var(--sp-6) 0 18px' }} />
      <div className="row spread">
        <span className="small">
          Signed in as <span className="mono">{username}</span>
        </span>
        <button className="button button-link" type="button" onClick={onSignOut} disabled={signingOut}>
          {signingOut ? 'Signing out' : 'Sign out'}
        </button>
      </div>
    </Plate>
  );
}

function describe(failure) {
  if (failure instanceof ApiError) {
    if (failure.status === 401) return 'Your session ended. Sign in again.';
    if (failure.status === 0) return 'Could not reach the server.';
    return failure.message;
  }
  // Everything else reaching here is the unwrap refusing, which means the key
  // this password produced is not the one the vault was sealed with.
  return 'That password does not open this vault.';
}
